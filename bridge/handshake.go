package bridge

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/p2p"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/lib/version"
)

type bridgeAuthKind int

const (
	bridgeAuthKindControl bridgeAuthKind = iota
	bridgeAuthKindPublic
	bridgeAuthKindVisitor
	bridgeAuthKindAccess
)

func (kind bridgeAuthKind) String() string {
	switch kind {
	case bridgeAuthKindAccess:
		return "access_only"
	case bridgeAuthKindPublic:
		return "public_config"
	case bridgeAuthKindVisitor:
		return "visitor_access"
	default:
		return "control_client"
	}
}

func bridgeAuthKindForClient(client *file.Client) bridgeAuthKind {
	if client == nil {
		return bridgeAuthKindControl
	}
	return bridgeAuthKindForRuntimeClient(client, currentBridgeConfig())
}

func bridgeAuthKindForRuntimeClient(client *file.Client, cfg *servercfg.Snapshot) bridgeAuthKind {
	if client == nil {
		return bridgeAuthKindControl
	}
	if cfg == nil {
		cfg = currentBridgeConfig()
	}
	if !client.NoStore || !client.NoDisplay {
		return bridgeAuthKindControl
	}
	vkey := strings.TrimSpace(client.VerifyKey)
	if vkey == "" {
		return bridgeAuthKindControl
	}
	matchPublic := strings.TrimSpace(cfg.Runtime.PublicVKey) != "" && vkey == strings.TrimSpace(cfg.Runtime.PublicVKey)
	matchVisitor := strings.TrimSpace(cfg.Runtime.VisitorVKey) != "" && vkey == strings.TrimSpace(cfg.Runtime.VisitorVKey)
	switch {
	case matchPublic && matchVisitor:
		return bridgeAuthKindAccess
	case matchVisitor:
		return bridgeAuthKindVisitor
	case matchPublic:
		return bridgeAuthKindPublic
	default:
		return bridgeAuthKindControl
	}
}

func (kind bridgeAuthKind) allowsFlag(flag string) bool {
	switch kind {
	case bridgeAuthKindAccess:
		switch flag {
		case common.WORK_CONFIG, common.WORK_REGISTER, common.WORK_VISITOR, common.WORK_SECRET, common.WORK_P2P, common.WORK_P2P_RESOLVE:
			return true
		}
	case bridgeAuthKindPublic:
		switch flag {
		case common.WORK_CONFIG, common.WORK_REGISTER:
			return true
		}
	case bridgeAuthKindVisitor:
		switch flag {
		case common.WORK_REGISTER, common.WORK_VISITOR, common.WORK_SECRET, common.WORK_P2P, common.WORK_P2P_RESOLVE:
			return true
		}
	default:
		switch flag {
		case common.WORK_MAIN, common.WORK_CHAN, common.WORK_CONFIG, common.WORK_REGISTER, common.WORK_FILE, common.WORK_P2P_SESSION, common.WORK_VISITOR, common.WORK_SECRET, common.WORK_P2P, common.WORK_P2P_RESOLVE:
			return true
		}
	}
	return false
}

func (s *Bridge) verifyError(c *conn.Conn) {
	if !ServerSecureMode {
		_, _ = c.Write([]byte(common.VERIFY_EER))
	}
	_ = c.Close()
}

func (s *Bridge) verifySuccess(c *conn.Conn) {
	_, _ = c.Write([]byte(common.VERIFY_SUCCESS))
}

type bridgeHandshakeVersion struct {
	ver          int
	minVerRaw    []byte
	clientVer    string
	clientVerRaw []byte
}

type bridgeHandshakeAuthResult struct {
	id     int
	client *file.Client
}

type bridgeRuntimeAuthEnvelope struct {
	ts      int64
	tsBuf   []byte
	keyBuf  []byte
	infoBuf []byte
	randBuf []byte
	hmacBuf []byte
}

type bridgeRuntimeAuthContext struct {
	id     int
	client *file.Client
	env    bridgeRuntimeAuthEnvelope
}

func readBridgeHandshakeVersion(c *conn.Conn) (bridgeHandshakeVersion, bool) {
	var zero bridgeHandshakeVersion
	minVerBytes, ver, ok := readBridgeHandshakeMinVersion(c)
	if !ok {
		return zero, false
	}
	clientVer, clientVerRaw, ok := readBridgeHandshakeClientVersion(c)
	if !ok {
		return zero, false
	}
	return bridgeHandshakeVersion{
		ver:          ver,
		minVerRaw:    minVerBytes,
		clientVer:    clientVer,
		clientVerRaw: clientVerRaw,
	}, true
}

func readBridgeHandshakeMinVersion(c *conn.Conn) ([]byte, int, bool) {
	if _, err := c.GetShortContent(3); err != nil {
		logs.Trace("The client %v connect error: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return nil, 0, false
	}
	minVerBytes, err := c.GetShortLenContent()
	if err != nil {
		logs.Trace("Failed to read version length from client %v: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return nil, 0, false
	}
	ver := version.GetIndex(string(minVerBytes))
	if (ServerSecureMode && ver < version.MinVer) || ver == -1 {
		logs.Warn("Client %v basic version mismatch: expected %s, got %s", c.Conn.RemoteAddr(), version.GetLatest(), string(minVerBytes))
		_ = c.Close()
		return nil, 0, false
	}
	return minVerBytes, ver, true
}

func readBridgeHandshakeClientVersion(c *conn.Conn) (string, []byte, bool) {
	vs, err := c.GetShortLenContent()
	if err != nil {
		logs.Error("Failed to read client version from %v: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return "", nil, false
	}
	return string(bytes.TrimRight(vs, "\x00")), vs, true
}

func (s *Bridge) authenticateBridgeClient(c *conn.Conn, tunnelType string, hs bridgeHandshakeVersion) (bridgeHandshakeAuthResult, bool) {
	if hs.ver == 0 {
		return s.authenticateLegacyBridgeClient(c, hs)
	}
	return s.authenticateRuntimeBridgeClient(c, tunnelType, hs)
}

func (s *Bridge) authenticateLegacyBridgeClient(c *conn.Conn, hs bridgeHandshakeVersion) (bridgeHandshakeAuthResult, bool) {
	var zero bridgeHandshakeAuthResult
	client, id, ok := s.resolveLegacyBridgeClient(c, hs)
	if !ok {
		return zero, false
	}
	s.verifySuccess(c)
	return bridgeHandshakeAuthResult{id: id, client: client}, true
}

func (s *Bridge) resolveLegacyBridgeClient(c *conn.Conn, hs bridgeHandshakeVersion) (*file.Client, int, bool) {
	if _, err := c.Write([]byte(crypt.Md5(version.GetVersion(hs.ver)))); err != nil {
		logs.Error("Failed to write server version to client %v: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return nil, 0, false
	}
	keyBuf, ok := readLegacyBridgeClientKey(c)
	if !ok {
		return nil, 0, false
	}
	id, client, ok := s.lookupLegacyBridgeClient(c, hs.ver, keyBuf)
	if !ok {
		return nil, 0, false
	}
	return client, id, true
}

func readLegacyBridgeClientKey(c *conn.Conn) ([]byte, bool) {
	keyBuf, err := c.GetShortContent(32)
	if err != nil {
		logs.Trace("Failed to read vKey from client %v: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return nil, false
	}
	return keyBuf, true
}

func (s *Bridge) lookupLegacyBridgeClient(c *conn.Conn, ver int, keyBuf []byte) (int, *file.Client, bool) {
	id, err := currentBridgeDB().GetIdByVerifyKey(string(keyBuf), c.RemoteAddr().String(), "", crypt.Md5)
	if err != nil {
		logs.Error("Validation error for client %v (proto-ver %d, vKey %x): %v", c.Conn.RemoteAddr(), ver, keyBuf, err)
		s.verifyError(c)
		return 0, nil, false
	}
	client, err := currentBridgeDB().GetClient(id)
	if err != nil {
		logs.Error("Failed to load client record for ID %d: %v", id, err)
		_ = c.Close()
		return 0, nil, false
	}
	return id, client, true
}

func decodeBridgeRuntimeClientInfo(tunnelType string, ver int, payload []byte) (string, string, error) {
	if ver < 3 {
		ip := common.DecodeIP(payload)
		if ip == nil {
			return "", "", fmt.Errorf("failed to decode legacy ip payload")
		}
		return ip.String(), tunnelType, nil
	}
	if len(payload) < 18 {
		return "", "", fmt.Errorf("invalid payload length: %d", len(payload))
	}
	ipPart := payload[:17]
	l := int(payload[17])
	if len(payload) < 18+l {
		return "", "", fmt.Errorf("declared tp length %d exceeds payload", l)
	}
	ip := common.DecodeIP(ipPart)
	if ip == nil {
		return "", "", fmt.Errorf("failed to decode IP")
	}
	return ip.String(), fmt.Sprintf("%s,%s", tunnelType, string(payload[18:18+l])), nil
}

func readBridgeRuntimeAuthEnvelope(c *conn.Conn) (bridgeRuntimeAuthEnvelope, error) {
	var zero bridgeRuntimeAuthEnvelope
	if c == nil {
		return zero, errors.New("nil conn")
	}
	tsBuf, err := c.GetShortContent(8)
	if err != nil {
		return zero, err
	}
	keyBuf, err := c.GetShortContent(64)
	if err != nil {
		return zero, err
	}
	infoBuf, err := c.GetShortLenContent()
	if err != nil {
		return zero, err
	}
	randBuf, err := c.GetShortLenContent()
	if err != nil {
		return zero, err
	}
	hmacBuf, err := c.GetShortContent(32)
	if err != nil {
		return zero, err
	}
	return bridgeRuntimeAuthEnvelope{
		ts:      common.BytesToTimestamp(tsBuf),
		tsBuf:   tsBuf,
		keyBuf:  keyBuf,
		infoBuf: infoBuf,
		randBuf: randBuf,
		hmacBuf: hmacBuf,
	}, nil
}

func validateBridgeRuntimeTimestamp(ts int64) error {
	if !ServerSecureMode {
		return nil
	}
	now := common.TimeNow().Unix()
	if ts > now+rep.ttl || ts < now-rep.ttl {
		return fmt.Errorf("timestamp validation failed: ts=%d, now=%d", ts, now)
	}
	return nil
}

func resolveBridgeRuntimeClient(c *conn.Conn, ver int, keyBuf []byte) (int, *file.Client, error) {
	id, err := currentBridgeDB().GetClientIdByBlake2bVkey(string(keyBuf))
	if err != nil {
		return 0, nil, fmt.Errorf("validation error for client %v (proto-ver %d, vKey %x): %w", c.Conn.RemoteAddr(), ver, keyBuf, err)
	}
	client, err := currentBridgeDB().GetClient(id)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to load client record for ID %d: %w", id, err)
	}
	if !client.Status {
		return 0, nil, fmt.Errorf("client %v (ID %d) is disabled", c.Conn.RemoteAddr(), id)
	}
	client.Addr = common.GetIpByAddr(c.RemoteAddr().String())
	return id, client, nil
}

func applyBridgeRuntimeClientInfo(client *file.Client, tunnelType string, ver int, infoBuf []byte) error {
	infoDec, err := crypt.DecryptBytes(infoBuf, client.VerifyKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt Info: %w", err)
	}
	localAddr, mode, err := decodeBridgeRuntimeClientInfo(tunnelType, ver, infoDec)
	if err != nil {
		return fmt.Errorf("failed to decode runtime info: %w", err)
	}
	client.LocalAddr = localAddr
	client.Mode = mode
	return nil
}

func verifyBridgeRuntimeAuthEnvelope(client *file.Client, hs bridgeHandshakeVersion, env bridgeRuntimeAuthEnvelope) error {
	if !ServerSecureMode {
		return nil
	}
	expected := crypt.ComputeHMAC(client.VerifyKey, env.ts, hs.minVerRaw, hs.clientVerRaw, env.infoBuf, env.randBuf)
	if !bytes.Equal(env.hmacBuf, expected) {
		return errors.New("hmac verification failed")
	}
	if IsReplay(string(env.hmacBuf)) {
		return errors.New("replay detected")
	}
	return nil
}

func writeBridgeRuntimeAuthResponse(c *conn.Conn, client *file.Client, hs bridgeHandshakeVersion, env bridgeRuntimeAuthEnvelope) error {
	if _, err := c.BufferWrite(crypt.ComputeHMAC(client.VerifyKey, env.ts, env.hmacBuf, []byte(version.GetVersion(hs.ver)))); err != nil {
		return fmt.Errorf("failed to write HMAC response: %w", err)
	}
	if hs.ver <= 1 {
		return c.FlushBuf()
	}
	fpBuf, err := crypt.EncryptBytes(crypt.GetCertFingerprint(crypt.GetCert()), client.VerifyKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt cert fingerprint: %w", err)
	}
	if err := c.WriteLenContent(fpBuf); err != nil {
		return fmt.Errorf("failed to write cert fingerprint: %w", err)
	}
	if hs.ver > 3 {
		if hs.ver > 5 {
			if err := c.WriteLenContent([]byte(crypt.GetUUID().String())); err != nil {
				return fmt.Errorf("failed to write UUID: %w", err)
			}
		}
		randByte, err := common.RandomBytes(1000)
		if err != nil {
			return fmt.Errorf("failed to generate rand byte: %w", err)
		}
		if err := c.WriteLenContent(randByte); err != nil {
			return fmt.Errorf("failed to write rand byte: %w", err)
		}
	}
	if err := c.FlushBuf(); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
}

func (s *Bridge) authenticateRuntimeBridgeClient(c *conn.Conn, tunnelType string, hs bridgeHandshakeVersion) (bridgeHandshakeAuthResult, bool) {
	var zero bridgeHandshakeAuthResult
	authCtx, ok := s.resolveRuntimeBridgeAuthContext(c, tunnelType, hs)
	if !ok {
		return zero, false
	}
	if err := verifyBridgeRuntimeAuthEnvelope(authCtx.client, hs, authCtx.env); err != nil {
		logs.Error("%v for %v", err, c.Conn.RemoteAddr())
		_ = c.Close()
		return zero, false
	}
	if err := writeBridgeRuntimeAuthResponse(c, authCtx.client, hs, authCtx.env); err != nil {
		logs.Error("%v for %v", err, c.Conn.RemoteAddr())
		_ = c.Close()
		return zero, false
	}
	return bridgeHandshakeAuthResult{id: authCtx.id, client: authCtx.client}, true
}

func (s *Bridge) resolveRuntimeBridgeAuthContext(c *conn.Conn, tunnelType string, hs bridgeHandshakeVersion) (bridgeRuntimeAuthContext, bool) {
	var zero bridgeRuntimeAuthContext
	env, err := readBridgeRuntimeAuthEnvelope(c)
	if err != nil {
		logs.Error("Failed to read runtime auth envelope from %v: %v", c.Conn.RemoteAddr(), err)
		_ = c.Close()
		return zero, false
	}
	if err := validateBridgeRuntimeTimestamp(env.ts); err != nil {
		logs.Error("%v for %v", err, c.Conn.RemoteAddr())
		_ = c.Close()
		return zero, false
	}
	id, client, err := resolveBridgeRuntimeClient(c, hs.ver, env.keyBuf)
	if err != nil {
		logs.Error("%v", err)
		s.verifyError(c)
		return zero, false
	}
	if err := applyBridgeRuntimeClientInfo(client, tunnelType, hs.ver, env.infoBuf); err != nil {
		logs.Error("%v for %v", err, c.Conn.RemoteAddr())
		_ = c.Close()
		return zero, false
	}
	return bridgeRuntimeAuthContext{id: id, client: client, env: env}, true
}

type bridgeRuntimeWorkEnvelope struct {
	flag string
	uuid string
}

type bridgeRuntimeDispatch struct {
	addr  net.Addr
	work  bridgeRuntimeWorkEnvelope
	isPub bool
}

func resolveBridgeRuntimeUUID(addr net.Addr, ver int, runtimeUUID string) string {
	runtimeUUID = strings.TrimSpace(runtimeUUID)
	if runtimeUUID != "" {
		return runtimeUUID
	}
	if addr == nil {
		return crypt.GenerateUUID("").String()
	}
	runtimeUUID = addr.String()
	if ver < 5 {
		runtimeUUID = common.GetIpByAddr(runtimeUUID)
	}
	return crypt.GenerateUUID(runtimeUUID).String()
}

func readBridgeRuntimeWorkEnvelope(c *conn.Conn, ver int) (bridgeRuntimeWorkEnvelope, bool) {
	var zero bridgeRuntimeWorkEnvelope
	addr := c.RemoteAddr()
	flag, err := c.ReadFlag()
	if err != nil {
		logs.Warn("Failed to read operation flag from %v: %v", addr, err)
		_ = c.Close()
		return zero, false
	}
	var runtimeUUID string
	if ver > 3 {
		if ver > 5 {
			uuidBuf, err := c.GetShortLenContent()
			if err != nil {
				logs.Error("Failed to read uuid buffer from %v: %v", addr, err)
				_ = c.Close()
				return zero, false
			}
			runtimeUUID = string(uuidBuf)
		}
		if _, err := c.GetShortLenContent(); err != nil {
			logs.Error("Failed to read random buffer from %v: %v", addr, err)
			_ = c.Close()
			return zero, false
		}
	}
	return bridgeRuntimeWorkEnvelope{
		flag: flag,
		uuid: resolveBridgeRuntimeUUID(addr, ver, runtimeUUID),
	}, true
}

func (s *Bridge) typeDeal(c *conn.Conn, id, ver int, vs, tunnelType string, authKind bridgeAuthKind, first bool) {
	dispatch, ok := s.resolveBridgeRuntimeDispatch(c, id, ver, authKind)
	if !ok {
		return
	}
	switch dispatch.work.flag {
	case common.WORK_MAIN:
		s.handleMainWork(c, id, ver, vs, dispatch.work.uuid, dispatch.addr, dispatch.isPub)
		return
	case common.WORK_CHAN:
		s.handleTunnelWork(c, id, ver, vs, tunnelType, authKind, dispatch.work.uuid, dispatch.addr, first)
		return
	case common.WORK_CONFIG:
		s.handleConfigWork(c, id, ver, vs, dispatch.work.uuid, dispatch.isPub)
		return
	case common.WORK_REGISTER:
		s.handleRegisterWork(c)
		return
	case common.WORK_VISITOR:
		s.handleVisitorWork(c, id, ver, vs, tunnelType, authKind, dispatch.addr, first)
		return
	case common.WORK_SECRET:
		s.handleSecretWork(c)
		return
	case common.WORK_FILE:
		s.handleFileWork(c, id)
		return
	case common.WORK_P2P_RESOLVE:
		s.handleP2PResolveWork(c, id, dispatch.work.uuid, ver)
		return
	case common.WORK_P2P:
		s.handleP2PConnectWork(c, id, dispatch.work.uuid, ver)
		return
	case common.WORK_P2P_SESSION:
		s.handleP2PSessionWork(c, id)
		return
	}

	c.SetAlive()
}

func (s *Bridge) resolveBridgeRuntimeDispatch(c *conn.Conn, id, ver int, authKind bridgeAuthKind) (bridgeRuntimeDispatch, bool) {
	var zero bridgeRuntimeDispatch
	addr := c.RemoteAddr()
	work, ok := readBridgeRuntimeWorkEnvelope(c, ver)
	if !ok {
		return zero, false
	}
	c.SetAlive()
	if !authKind.allowsFlag(work.flag) {
		logs.Warn("Rejected work flag %s for auth kind %s from %v", work.flag, authKind, addr)
		_ = c.Close()
		return zero, false
	}
	return bridgeRuntimeDispatch{
		addr:  addr,
		work:  work,
		isPub: currentBridgeDB().IsPubClient(id),
	}, true
}

var bridgeSecretDispatchTimeout = 250 * time.Millisecond

func (s *Bridge) register(c *conn.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hour int32
	if err := binary.Read(c, binary.LittleEndian, &hour); err == nil {
		ip := common.GetIpByAddr(c.RemoteAddr().String())
		s.Register.Store(ip, time.Now().Add(time.Hour*time.Duration(hour)))
		logs.Info("Registered IP: %s for %d hours", ip, hour)
	} else {
		logs.Warn("Failed to register IP: %v", err)
	}
	_ = c.Close()
}

func (s *Bridge) handleRegisterWork(c *conn.Conn) {
	s.sessionGo(func() { s.register(c) })
}

func (s *Bridge) handleSecretWork(c *conn.Conn) {
	b, err := c.GetShortContent(32)
	if err != nil {
		logs.Error("secret error, failed to match the key successfully")
		_ = c.Close()
		return
	}
	if !s.enqueueSecret(conn.NewSecret(string(b), c)) {
		logs.Warn("secret dispatch queue unavailable or full")
		_ = c.Close()
	}
}

func (s *Bridge) enqueueSecret(secret *conn.Secret) bool {
	if s == nil || s.SecretChan == nil || secret == nil {
		return false
	}
	select {
	case s.SecretChan <- secret:
		return true
	default:
	}
	timer := time.NewTimer(bridgeSecretDispatchTimeout)
	defer timer.Stop()
	select {
	case s.SecretChan <- secret:
		return true
	case <-timer.C:
		return false
	}
}

func (s *Bridge) handleFileWork(c *conn.Conn, id int) {
	logs.Warn("clientId %d not support file", id)
	_ = c.Close()
}

func (s *Bridge) handleP2PResolveWork(c *conn.Conn, id int, uuid string, ver int) {
	req, err := decodeJSONPayload[p2p.P2PResolveRequest](c)
	if err != nil {
		logs.Error("p2p resolve error, %v", err)
		_ = c.Close()
		return
	}
	target, err := s.resolveBridgeP2PRoute(id, uuid, ver, req.PasswordMD5, "", req.RouteHint)
	if err != nil {
		logs.Error("p2p resolve failed: %v", err)
		_ = c.Close()
		return
	}
	logMessage, err := s.dispatchBridgeP2PResolveResult(c, target)
	if err != nil {
		logs.Warn("%s: %v", logMessage, err)
		_ = c.Close()
		return
	}
}

func (s *Bridge) handleP2PConnectWork(c *conn.Conn, id int, uuid string, ver int) {
	req, err := decodeJSONPayload[p2p.P2PConnectRequest](c)
	if err != nil {
		logs.Error("p2p connect error, %v", err)
		_ = c.Close()
		return
	}
	target, err := s.resolveBridgeP2PRoute(id, uuid, ver, req.PasswordMD5, req.ProviderUUID, req.RouteHint)
	if err != nil {
		logs.Error("p2p connect resolve failed: %v", err)
		_ = c.Close()
		return
	}
	if err := validateBridgeP2PConnectAssociation(req, target.association); err != nil {
		logs.Warn("%v", err)
		_ = c.Close()
		return
	}
	session, err := s.createBridgeP2PConnectSession(c, id, target)
	if err != nil {
		logs.Warn("create p2p session failed: %v", err)
		_ = c.Close()
		return
	}
	logMessage, abortReason, err := s.dispatchBridgeP2PConnectStart(c, target, session)
	if err != nil {
		logs.Warn("%s: %v", logMessage, err)
		session.abort(abortReason)
		_ = c.Close()
		return
	}
	s.sessionGo(func() { session.serve(common.WORK_P2P_VISITOR, c) })
}

func (s *Bridge) handleP2PSessionWork(c *conn.Conn, id int) {
	join, err := decodeBridgeP2PSessionJoin(c)
	if err != nil {
		_ = c.Close()
		return
	}
	session, err := s.resolveBridgeP2PSessionJoin(join, id)
	if err != nil {
		_ = c.Close()
		return
	}
	if !session.attachProvider(c) {
		_ = c.Close()
		return
	}
	s.sessionGo(func() { session.serve(common.WORK_P2P_PROVIDER, c) })
}

func buildBridgeP2PResolveResult(target bridgeP2PResolvedRoute) p2p.P2PResolveResult {
	return p2p.P2PResolveResult{
		Association:       target.association,
		AssociationPolicy: target.accessGrant,
		Route:             target.route,
		Phase:             target.phase,
		NeedPunch:         target.needPunch,
	}
}

func (s *Bridge) dispatchBridgeP2PResolveResult(c *conn.Conn, target bridgeP2PResolvedRoute) (string, error) {
	if err := s.sendP2PAssociationBind(target.node, target.signal, buildP2PAssociationBind(target.association, target.accessGrant, target.route, target.phase)); err != nil {
		return "send provider p2p bind failed", err
	}
	result := buildBridgeP2PResolveResult(target)
	if err := encodeJSONPayload(c, &result); err != nil {
		return "send visitor p2p resolve failed", err
	}
	return "", nil
}

func validateBridgeP2PConnectAssociation(req p2p.P2PConnectRequest, association p2p.P2PAssociation) error {
	if req.AssociationID == "" || req.AssociationID == association.AssociationID {
		return nil
	}
	return fmt.Errorf("p2p association mismatch visitor=%s bridge=%s", req.AssociationID, association.AssociationID)
}

func (s *Bridge) createBridgeP2PConnectSession(c *conn.Conn, id int, target bridgeP2PResolvedRoute) (*p2pBridgeSession, error) {
	visitorProbe := buildProbeConfig(c)
	providerProbe := buildProbeConfig(target.signal)
	return s.p2pSessions.create(id, target.task.Client.Id, target.task, c, visitorProbe, providerProbe, target.association, target.accessGrant, target.route)
}

func (s *Bridge) dispatchBridgeP2PConnectStart(c *conn.Conn, target bridgeP2PResolvedRoute, session *p2pBridgeSession) (string, string, error) {
	if err := p2p.WriteBridgeMessage(c, common.P2P_PUNCH_START, session.visitorStart); err != nil {
		return "send visitor p2p start failed", "send visitor start failed", err
	}
	if err := sendBridgeMessageToNodeSignal(target.node, target.signal, common.P2P_PUNCH_START, session.providerStart); err != nil {
		return "send provider p2p start failed", "send provider start failed", err
	}
	return "", "", nil
}

func decodeBridgeP2PSessionJoin(c *conn.Conn) (p2p.P2PSessionJoin, error) {
	return decodeJSONPayload[p2p.P2PSessionJoin](c)
}

func (s *Bridge) resolveBridgeP2PSessionJoin(join p2p.P2PSessionJoin, id int) (*p2pBridgeSession, error) {
	session, ok := s.p2pSessions.get(join.SessionID)
	if !ok || session == nil {
		return nil, fmt.Errorf("p2p session unavailable")
	}
	if session.token != join.Token {
		return nil, fmt.Errorf("p2p session token mismatch")
	}
	if session.providerID != id {
		return nil, fmt.Errorf("p2p session provider mismatch")
	}
	return session, nil
}

func (s *Bridge) handleMainWork(c *conn.Conn, id, ver int, vs, uuid string, addr net.Addr, isPub bool) {
	if isPub {
		_ = c.Close()
		return
	}
	if tcpConn, ok := c.Conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(5 * time.Second)
	}

	node := NewNode(uuid, vs, ver)
	node.AddSignal(c)
	client := NewClient(id, node)
	client.SetCloseNodeHook(s.notifyCloseNode)
	if existing, loaded := s.loadOrStoreRuntimeClient(id, client); loaded {
		client = existing
		client.SetCloseNodeHook(s.notifyCloseNode)
		client.MarkConnectedNow()
		client.RemoveOfflineNodesExcept(uuid, true)
		if existingNode, ok := client.GetNodeByUUID(uuid); ok {
			node = existingNode
			node.AddSignal(c)
		} else {
			client.AddNode(node)
		}
	}
	client.MarkConnectedNow()
	s.sessionGo(func() { s.GetHealthFromClient(id, c, client, node) })
	logs.Info("ClientId %d connection succeeded, address:%v ", id, addr)
}

func (s *Bridge) handleConfigWork(c *conn.Conn, id, ver int, vs, uuid string, isPub bool) {
	client, err := currentBridgeDB().GetClient(id)
	if err != nil || (!isPub && !client.ConfigConnAllow) {
		_ = c.Close()
		return
	}
	_ = binary.Write(c, binary.LittleEndian, isPub)
	s.sessionGo(func() { s.getConfig(c, isPub, client, ver, vs, uuid) })
}

func (s *Bridge) CliProcess(c *conn.Conn, tunnelType string) {
	auth, hs, ok := s.resolveBridgeClientProcess(c, tunnelType)
	if !ok {
		return
	}
	s.typeDeal(c, auth.id, hs.ver, hs.clientVer, tunnelType, bridgeAuthKindForClient(auth.client), true)
}

func (s *Bridge) resolveBridgeClientProcess(c *conn.Conn, tunnelType string) (bridgeHandshakeAuthResult, bridgeHandshakeVersion, bool) {
	var zeroAuth bridgeHandshakeAuthResult
	var zeroVersion bridgeHandshakeVersion
	if c.Conn == nil || c.Conn.RemoteAddr() == nil {
		logs.Warn("Invalid connection")
		_ = c.Close()
		return zeroAuth, zeroVersion, false
	}
	c.SetReadDeadlineBySecond(bridgeHandshakeReadTimeout)
	hs, ok := readBridgeHandshakeVersion(c)
	if !ok {
		return zeroAuth, zeroVersion, false
	}
	auth, ok := s.authenticateBridgeClient(c, tunnelType, hs)
	if !ok {
		return zeroAuth, zeroVersion, false
	}
	return auth, hs, true
}

type replay struct {
	mu    sync.Mutex
	items map[string]int64
	ttl   int64
}

var rep = replay{
	items: make(map[string]int64, 100),
	ttl:   300,
}

func IsReplay(key string) bool {
	now := time.Now().Unix()
	rep.mu.Lock()
	defer rep.mu.Unlock()
	expireBefore := now - rep.ttl
	for k, ts := range rep.items {
		if ts < expireBefore {
			delete(rep.items, k)
		}
	}
	if _, ok := rep.items[key]; ok {
		return true
	}
	rep.items[key] = now
	return false
}
