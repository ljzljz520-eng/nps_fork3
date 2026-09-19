package bridge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/server/connection"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

var (
	ServerTcpEnable  = false
	ServerKcpEnable  = false
	ServerQuicEnable = false
	ServerTlsEnable  = false
	ServerWsEnable   = false
	ServerWssEnable  = false
	ServerSecureMode = false
)

var bridgeHandshakeReadTimeout time.Duration = 10
var currentBridgeListenerRuntimeRoot = connection.CurrentBridgeRuntime
var currentBridgeQUICRuntimeRoot = connection.CurrentQUICRuntime
var currentBridgeDBRoot = file.GetDb

func currentBridgeListenerRuntime() connection.BridgeRuntimeConfig {
	if currentBridgeListenerRuntimeRoot != nil {
		return currentBridgeListenerRuntimeRoot()
	}
	return connection.CurrentBridgeRuntime()
}

func currentBridgeQUICRuntime() connection.QUICRuntimeConfig {
	if currentBridgeQUICRuntimeRoot != nil {
		return currentBridgeQUICRuntimeRoot()
	}
	return connection.CurrentQUICRuntime()
}

func currentBridgeDB() *file.DbUtils {
	if currentBridgeDBRoot != nil {
		if db := currentBridgeDBRoot(); db != nil {
			return db
		}
	}
	return file.GetDb()
}

type Bridge struct {
	Client             *sync.Map
	Register           *sync.Map
	VirtualTcpListener *conn.VirtualListener
	VirtualTlsListener *conn.VirtualListener
	VirtualWsListener  *conn.VirtualListener
	VirtualWssListener *conn.VirtualListener
	OpenHost           chan *file.Host
	OpenTask           chan *file.Tunnel
	SecretChan         chan *conn.Secret
	ipVerify           atomic.Bool
	runList            *sync.Map //map[int]interface{}
	disconnectTime     atomic.Int64
	p2pSessions        *p2pSessionManager
	p2pAssociations    *p2pAssociationManager
	closeClientHook    atomic.Value
	closeNodeHook      atomic.Value

	// lifecycle management
	lifeMu         sync.Mutex // serializes StartTunnel vs Shutdown; guards the fields below
	started        bool
	startBlocked   bool
	intakeRejected bool          // listeners have been closed exactly once (guarded by lifeMu)
	shutdownCh     chan struct{} // closed when shutdown begins (new connections are rejected)
	doneCh         chan struct{} // closed when Shutdown has fully completed
	shutdownOnce   sync.Once
	doneOnce       sync.Once
	shutdownMu     sync.Mutex // serializes shutdown orchestration
	shutdownErr    error      // result of the first shutdown orchestration
	listeners      bridgeHeldListeners

	rawConns sync.Map // map[string]net.Conn tracked during connection intake

	loopWG    sync.WaitGroup // accept/ping/supervisor loops
	sessionWG sync.WaitGroup // connection/session goroutines
}

// bridgeHeldListeners holds the underlying listeners created at startup so
// they can be explicitly closed during shutdown.
type bridgeHeldListeners struct {
	tcp         net.Listener
	tls         net.Listener
	ws          net.Listener
	wss         net.Listener
	reservedTLS net.Listener
	// wsGateway/wssGateway are the websocket upgrade wrappers between the
	// virtual listeners and the bridge handlers; they have their own
	// close channel and must be closed to unblock their Accept loops.
	wsGateway   net.Listener
	wssGateway  net.Listener
	kcp         *kcp.Listener
	quicRuntime *conn.QUICListenerRuntime
}

func NewTunnel(ipVerify bool, runList *sync.Map, disconnectTime int) *Bridge {
	bridge := &Bridge{
		Client:          &sync.Map{},
		Register:        &sync.Map{},
		OpenHost:        make(chan *file.Host, 100),
		OpenTask:        make(chan *file.Tunnel, 100),
		SecretChan:      make(chan *conn.Secret, 100),
		runList:         runList,
		p2pAssociations: newP2PAssociationManager(),
		shutdownCh:      make(chan struct{}),
		doneCh:          make(chan struct{}),
	}
	bridge.p2pSessions = newP2PSessionManager(bridge.p2pAssociations)
	bridge.ipVerify.Store(ipVerify)
	bridge.disconnectTime.Store(int64(disconnectTime))
	return bridge
}

func (s *Bridge) IPVerifyEnabled() bool {
	if s == nil {
		return false
	}
	return s.ipVerify.Load()
}

func (s *Bridge) SetIPVerify(enabled bool) {
	if s == nil {
		return
	}
	s.ipVerify.Store(enabled)
}

func (s *Bridge) DisconnectTimeout() int {
	if s == nil {
		return 0
	}
	return int(s.disconnectTime.Load())
}

func (s *Bridge) SetDisconnectTimeout(seconds int) {
	if s == nil {
		return
	}
	s.disconnectTime.Store(int64(seconds))
}

type closeClientHookEntry struct {
	run func(int)
}

type closeNodeHookEntry struct {
	run func(int, string)
}

type bridgeRuntimeClientLookupState uint8

const (
	bridgeRuntimeClientMissing bridgeRuntimeClientLookupState = iota
	bridgeRuntimeClientReady
	bridgeRuntimeClientInvalid
)

type bridgeRuntimeClientLookupResult struct {
	client  *Client
	state   bridgeRuntimeClientLookupState
	cleaned bool
}

func (s *Bridge) SetCloseClientHook(hook func(int)) {
	if s == nil {
		return
	}
	s.closeClientHook.Store(closeClientHookEntry{run: hook})
}

func (s *Bridge) SetCloseNodeHook(hook func(int, string)) {
	if s == nil {
		return
	}
	s.closeNodeHook.Store(closeNodeHookEntry{run: hook})
}

func (s *Bridge) notifyCloseClient(id int) {
	if s == nil || id == 0 {
		return
	}
	value := s.closeClientHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(closeClientHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id)
}

func (s *Bridge) notifyCloseNode(id int, uuid string) {
	if s == nil || id == 0 || strings.TrimSpace(uuid) == "" {
		return
	}
	value := s.closeNodeHook.Load()
	if value == nil {
		return
	}
	entry, ok := value.(closeNodeHookEntry)
	if !ok || entry.run == nil {
		return
	}
	entry.run(id, uuid)
}

func (s *Bridge) DelClient(id int) {
	result := s.lookupRuntimeClient(id)
	if result.state != bridgeRuntimeClientReady || result.client == nil {
		return
	}
	_ = result.client.Close()
	if !s.removeCurrentClient(id, result.client) {
		return
	}
	if currentBridgeDB().IsPubClient(id) {
		return
	}
	s.notifyCloseClient(id)
}

func (s *Bridge) loadRuntimeClient(id int) (*Client, bool) {
	result := s.lookupRuntimeClient(id)
	return result.client, result.state == bridgeRuntimeClientReady
}

func (s *Bridge) loadOrStoreRuntimeClient(id int, candidate *Client) (*Client, bool) {
	if s == nil || s.Client == nil || candidate == nil || id == 0 {
		return nil, false
	}
	for {
		value, loaded := s.Client.LoadOrStore(id, candidate)
		if !loaded {
			return candidate, false
		}
		result := s.runtimeClientFromValue(id, value, true)
		if result.state == bridgeRuntimeClientReady && result.client != nil {
			return result.client, true
		}
	}
}

func (s *Bridge) lookupRuntimeClient(id int) bridgeRuntimeClientLookupResult {
	if s == nil || s.Client == nil || id == 0 {
		return bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientMissing}
	}
	value, ok := s.Client.Load(id)
	if !ok {
		return bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientMissing}
	}
	return s.runtimeClientFromValue(id, value, true)
}

func (s *Bridge) runtimeClientFromValue(id int, value interface{}, cleanupInvalid bool) bridgeRuntimeClientLookupResult {
	client, ok := value.(*Client)
	if ok && client != nil {
		return bridgeRuntimeClientLookupResult{client: client, state: bridgeRuntimeClientReady}
	}
	result := bridgeRuntimeClientLookupResult{state: bridgeRuntimeClientInvalid}
	if cleanupInvalid && s != nil && s.Client != nil {
		result.cleaned = s.Client.CompareAndDelete(id, value)
	}
	return result
}

func (s *Bridge) removeCurrentClient(id int, client *Client) bool {
	if s == nil || s.Client == nil || client == nil {
		return false
	}
	return s.Client.CompareAndDelete(id, client)
}

func (s *Bridge) removeEmptyRuntimeClient(id int, client *Client) bool {
	if s == nil || client == nil || id <= 0 {
		return false
	}
	if client.NodeCount() != 0 {
		return false
	}
	if !s.removeCurrentClient(id, client) {
		return false
	}
	if !currentBridgeDB().IsPubClient(id) {
		s.notifyCloseClient(id)
	}
	return true
}

func (s *Bridge) removeClientEntryIfCurrent(key, value interface{}) bool {
	if s == nil || s.Client == nil || key == nil || value == nil {
		return false
	}
	return s.Client.CompareAndDelete(key, value)
}

func (s *Bridge) removeRegistrationIfCurrent(ip string, expiresAt time.Time) bool {
	if s == nil || s.Register == nil || ip == "" {
		return false
	}
	return s.Register.CompareAndDelete(ip, expiresAt)
}

func (s *Bridge) removeRegistrationValueIfCurrent(ip string, value interface{}) bool {
	if s == nil || s.Register == nil || ip == "" {
		return false
	}
	return s.Register.CompareAndDelete(ip, value)
}

func (s *Bridge) removeRegistrationEntryIfCurrent(key, value interface{}) bool {
	if s == nil || s.Register == nil || key == nil || value == nil {
		return false
	}
	return s.Register.CompareAndDelete(key, value)
}

func (s *Bridge) CleanupExpiredRegistrations(now time.Time) int {
	if s == nil || s.Register == nil {
		return 0
	}
	removed := 0
	s.Register.Range(func(key, value interface{}) bool {
		ip, ok := key.(string)
		if !ok {
			if s.removeRegistrationEntryIfCurrent(key, value) {
				removed++
			}
			return true
		}
		expireAt, ok := value.(time.Time)
		if !ok {
			if s.removeRegistrationValueIfCurrent(ip, value) {
				removed++
			}
			return true
		}
		if !expireAt.After(now) && s.removeRegistrationIfCurrent(ip, expireAt) {
			removed++
		}
		return true
	})
	return removed
}

func (s *Bridge) IsServer() bool {
	return true
}

const bridgeHealthReadRetryMax = 3

type bridgeClientHealthUpdate struct {
	clientID  int
	routeUUID string
	info      string
	healthy   bool
}

func buildBridgeClientHealthUpdate(clientID int, routeUUID, info string, healthy bool) bridgeClientHealthUpdate {
	return bridgeClientHealthUpdate{
		clientID:  clientID,
		routeUUID: strings.TrimSpace(routeUUID),
		info:      strings.TrimSpace(info),
		healthy:   healthy,
	}
}

func readBridgeClientHealthUpdate(clientID int, c *conn.Conn, routeUUID string, retry *int) (bridgeClientHealthUpdate, bool) {
	if c == nil || retry == nil {
		return bridgeClientHealthUpdate{}, false
	}
	for {
		info, healthy, err := c.GetHealthInfo()
		if err == nil {
			*retry = 0
			return buildBridgeClientHealthUpdate(clientID, routeUUID, info, healthy), true
		}
		if conn.IsTimeout(err) && *retry < bridgeHealthReadRetryMax {
			*retry++
			continue
		}
		logs.Trace("GetHealthInfo error, id=%d, retry=%d, detail=%s", clientID, *retry, conn.DescribeNetError(err, c.Conn))
		return bridgeClientHealthUpdate{}, false
	}
}

func (s *Bridge) consumeBridgeClientHealth(clientID int, c *conn.Conn, routeUUID string) {
	if s == nil || clientID <= 0 || c == nil {
		return
	}
	retry := 0
	for {
		update, ok := readBridgeClientHealthUpdate(clientID, c, routeUUID, &retry)
		if !ok {
			return
		}
		s.applyBridgeClientTargetHealth(update)
	}
}

func bridgeClientRouteUUID(node *Node) string {
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.UUID)
}

func (s *Bridge) cleanupBridgeClientHealthSignal(client *Client, node *Node, signal *conn.Conn) {
	if s == nil || client == nil || node == nil || signal == nil {
		return
	}
	if !node.CloseIfSignalCurrent(signal) {
		return
	}
	if client.closeAndRemoveNodeIfCurrent(bridgeClientRouteUUID(node), node) {
		s.removeEmptyRuntimeClient(client.Id, client)
	}
}

func (s *Bridge) GetHealthFromClient(id int, c *conn.Conn, client *Client, node *Node) {
	if id <= 0 || c == nil {
		return
	}
	s.consumeBridgeClientHealth(id, c, bridgeClientRouteUUID(node))
	s.cleanupBridgeClientHealthSignal(client, node, c)
}

func (s *Bridge) applyBridgeTaskTargetHealth(update bridgeClientHealthUpdate) {
	currentBridgeDB().RangeTasks(func(v *file.Tunnel) bool {
		if v.Client != nil && v.Client.Id == update.clientID && v.Mode == "tcp" {
			v.UpdateRuntimeTargetHealth(update.routeUUID, update.info, update.healthy)
		}
		return true
	})
}

func (s *Bridge) applyBridgeHostTargetHealth(update bridgeClientHealthUpdate) {
	currentBridgeDB().RangeHosts(func(v *file.Host) bool {
		if v.Client != nil && v.Client.Id == update.clientID {
			v.UpdateRuntimeTargetHealth(update.routeUUID, update.info, update.healthy)
		}
		return true
	})
}

func (s *Bridge) applyBridgeClientTargetHealth(update bridgeClientHealthUpdate) {
	if s == nil || update.clientID <= 0 {
		return
	}
	s.applyBridgeTaskTargetHealth(update)
	s.applyBridgeHostTargetHealth(update)
}

func (s *Bridge) ping() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdownCh:
			return
		case <-ticker.C:
			closedClients := s.collectPingClosedClients()
			for _, clientId := range closedClients {
				logs.Info("the client %d closed", clientId)
				s.DelClient(clientId)
			}
		}
	}
}

func (s *Bridge) collectPingClosedClients() []int {
	if s == nil || s.Client == nil {
		return nil
	}
	closedClients := make([]int, 0)
	s.Client.Range(func(key, value interface{}) bool {
		clientID, ok := key.(int)
		if !ok {
			s.removeClientEntryIfCurrent(key, value)
			return true
		}
		if clientID <= 0 {
			return true
		}
		result := s.runtimeClientFromValue(clientID, value, false)
		if result.state != bridgeRuntimeClientReady || result.client == nil {
			logs.Trace("Client %d is nil", clientID)
			closedClients = append(closedClients, clientID)
			return true
		}
		client := result.client
		health := client.collectPingHealth()
		if health.state == clientPingHealthEmpty {
			if s.removeEmptyRuntimeClient(clientID, client) {
				return true
			}
		}
		if health.state != clientPingHealthHealthy {
			if _, shouldClose := client.notePingUnavailable(); shouldClose {
				logs.Trace("Stop client %d", clientID)
				closedClients = append(closedClients, clientID)
			}
			return true
		}
		client.resetPingRetry()
		return true
	})
	return closedClients
}

// Shutdown errors returned to callers / recorded as explicit failure.
var (
	ErrBridgeShuttingDown   = errors.New("bridge is shutting down")
	ErrBridgeAlreadyStarted = errors.New("bridge already started")
	ErrSessionsNotDrained   = errors.New("sessions were not drained before the deadline")
	ErrLoopsNotStopped      = errors.New("background loops did not stop before the deadline")
)

// IsShuttingDown reports whether graceful shutdown has begun.
func (s *Bridge) IsShuttingDown() bool {
	if s == nil {
		return true
	}
	select {
	case <-s.shutdownCh:
		return true
	default:
		return false
	}
}

// ShutdownChan is closed once graceful shutdown begins.
func (s *Bridge) ShutdownChan() <-chan struct{} { return s.shutdownCh }

// Done is closed when a Shutdown call has fully completed.
func (s *Bridge) Done() <-chan struct{} { return s.doneCh }

// sessionGo runs fn on a tracked session goroutine. Any panic is recovered so
// a faulty sub-runtime cannot crash the process or wedge the WaitGroup.
func (s *Bridge) sessionGo(fn func()) {
	s.sessionWG.Add(1)
	go func() {
		defer s.sessionWG.Done()
		defer recoverSessionPanic()
		fn()
	}()
}

// loopGo runs fn on a tracked loop goroutine.
func (s *Bridge) loopGo(fn func()) {
	s.loopWG.Add(1)
	go func() {
		defer s.loopWG.Done()
		defer recoverSessionPanic()
		fn()
	}()
}

func recoverSessionPanic() {
	if r := recover(); r != nil {
		logs.Error("bridge sub-runtime panic recovered: %v", r)
	}
}

// trackConn registers a raw connection during intake so it can be forcibly
// closed if shutdown begins while it is still being processed.
func (s *Bridge) trackConn(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	s.rawConns.Store(rawConnKey(c), c)
	return c
}

func (s *Bridge) untrackConn(c net.Conn) {
	if c == nil {
		return
	}
	s.rawConns.Delete(rawConnKey(c))
}

func rawConnKey(c net.Conn) string {
	return fmt.Sprintf("%p", c)
}

// closeTrackedConns force-closes every connection currently being taken in.
func (s *Bridge) closeTrackedConns() {
	s.rawConns.Range(func(_, value any) bool {
		if c, ok := value.(net.Conn); ok {
			_ = c.Close()
		}
		return true
	})
}

// waitForWG blocks until wg is drained or ctx is done. It reports whether the
// group drained. A helper goroutine is used to bridge WaitGroup (no context)
// into a select; it exits as soon as the group drains.
func waitForWG(ctx context.Context, wg *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// BeginShutdown immediately rejects new intake on every protocol without
// waiting for existing sessions to drain. It lets a host process stop new
// connections, flush writers and only afterwards call Shutdown to drain and
// force-close. Idempotent and safe for concurrent invocation.
func (s *Bridge) BeginShutdown() {
	s.shutdownOnce.Do(func() { close(s.shutdownCh) })
	// Serialize against StartTunnel so all startup resources are registered
	// before the listeners are closed.
	s.lifeMu.Lock()
	s.startBlocked = true
	// Every concurrent caller invokes BeginShutdown; only the first one may
	// close the listeners (a second Close has no benefit and surfaces as a
	// duplicate close to instrumented listeners).
	if !s.intakeRejected {
		s.rejectNewConnectionsLocked()
		s.intakeRejected = true
	}
	s.lifeMu.Unlock()
}

// Shutdown performs a bounded graceful shutdown:
//  1. New connections on every protocol are rejected immediately.
//  2. Existing sessions may complete within the grace period.
//  3. Any session remaining after grace is forcibly closed.
//  4. All goroutines are reclaimed, bounded by ctx.
//
// It is idempotent and safe for concurrent invocation; concurrent callers
// block until the first call completes and share its result.
func (s *Bridge) Shutdown(ctx context.Context, grace time.Duration) error {
	s.BeginShutdown()

	// Only one caller orchestrates the shutdown; concurrent callers wait for
	// it to finish and return the same result (no double force-close).
	s.shutdownMu.Lock()
	defer s.shutdownMu.Unlock()
	select {
	case <-s.doneCh:
		return s.shutdownErr
	default:
	}

	err := s.runShutdown(ctx, grace)
	s.shutdownErr = err
	s.doneOnce.Do(func() { close(s.doneCh) })
	return err
}

func (s *Bridge) runShutdown(ctx context.Context, grace time.Duration) error {
	var failures []error

	// Grace period: wait for in-flight sessions to finish naturally.
	if grace > 0 {
		graceCtx, cancel := context.WithTimeout(ctx, grace)
		waitForWG(graceCtx, &s.sessionWG)
		cancel()
	}

	// Force-close everything that remains.
	s.forceCloseSessions()

	if ctx.Err() == nil {
		if !waitForWG(ctx, &s.sessionWG) {
			failures = append(failures, ErrSessionsNotDrained)
		}
		if !waitForWG(ctx, &s.loopWG) {
			failures = append(failures, ErrLoopsNotStopped)
		}
	} else {
		failures = append(failures, ctx.Err())
	}

	return errors.Join(failures...)
}

// rejectNewConnectionsLocked stops intake on every protocol. It must be called
// with lifeMu held.
func (s *Bridge) rejectNewConnectionsLocked() {
	for _, l := range []net.Listener{
		s.listeners.tcp,
		s.listeners.tls,
		s.listeners.ws,
		s.listeners.wss,
		s.listeners.reservedTLS,
	} {
		if l != nil {
			_ = l.Close()
		}
	}
	// QUIC Close rejects new connections/cancels handshakes without affecting
	// already established connections. The UDP socket is released later in
	// force-close after established sessions have gone.
	if s.listeners.quicRuntime != nil && s.listeners.quicRuntime.Listener != nil {
		_ = s.listeners.quicRuntime.Listener.Close()
	}
	// KCP sessions share the listener socket, so it is intentionally left open
	// until force-close; the intake handler rejects brand-new sessions instead.
}

// forceCloseSessions forcibly terminates all established sessions and
// releases every listening socket.
func (s *Bridge) forceCloseSessions() {
	// Abort bridge-mediated P2P negotiations; closes their control connections.
	if s.p2pSessions != nil {
		s.p2pSessions.abortAll("server shutdown")
	}
	// Close any connection still inside intake (handshake / first work read).
	s.closeTrackedConns()
	// Close all established clients: closes nodes, tunnels and signals
	// (including QUIC connections).
	s.Client.Range(func(_, value any) bool {
		if client, ok := value.(*Client); ok && client != nil {
			_ = client.Close()
		}
		return true
	})
	// Release the KCP listening socket now that its sessions are gone.
	if s.listeners.kcp != nil {
		_ = s.listeners.kcp.Close()
	}
	// Release the QUIC transport and its UDP socket: rejects late handshakes
	// and makes the port immediately rebindable.
	if s.listeners.quicRuntime != nil {
		_ = s.listeners.quicRuntime.Release()
	}
	// Close virtual listeners: unblocks the virtual-side accept loops and
	// drains queued, not-yet-processed connections.
	for _, vl := range []*conn.VirtualListener{
		s.VirtualTcpListener,
		s.VirtualTlsListener,
		s.VirtualWsListener,
		s.VirtualWssListener,
	} {
		if vl != nil {
			_ = vl.Close()
		}
	}
	// Close the websocket upgrade gateways: unblocks their Accept loops and
	// stops the embedded HTTP servers, releasing the virtual listeners.
	for _, gl := range []net.Listener{s.listeners.wsGateway, s.listeners.wssGateway} {
		if gl != nil {
			_ = gl.Close()
		}
	}
	// Drain any secret connection waiting in the dispatch channel.
	s.drainSecretChan()
}

// drainSecretChan closes secret connections queued for processing.
func (s *Bridge) drainSecretChan() {
	if s.SecretChan == nil {
		return
	}
	for {
		select {
		case secret := <-s.SecretChan:
			if secret != nil && secret.Conn != nil {
				_ = secret.Conn.Close()
			}
		default:
			return
		}
	}
}

var (
	bridgeGetReservedTLSListener = connection.GetBridgeReservedTLSListener
	bridgeGetTCPListener         = connection.GetBridgeTcpListener
	bridgeGetTLSListener         = connection.GetBridgeTlsListener
	bridgeGetWSListener          = connection.GetBridgeWsListener
	bridgeGetWSSListener         = connection.GetBridgeWssListener
)

type bridgeListenerBootstrap struct {
	reservedTLSListener   net.Listener
	tcpListener           net.Listener
	tlsListener           net.Listener
	wsListener            net.Listener
	wssListener           net.Listener
	useReservedTLSGateway bool
}

func (b *bridgeListenerBootstrap) close() {
	if b == nil {
		return
	}
	for _, listener := range []net.Listener{
		b.reservedTLSListener,
		b.tcpListener,
		b.tlsListener,
		b.wsListener,
		b.wssListener,
	} {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

func (b *bridgeListenerBootstrap) openReservedTLSListener() error {
	if !ServerTlsEnable || !ServerWssEnable {
		return nil
	}
	listener, err := bridgeGetReservedTLSListener()
	if err != nil {
		return err
	}
	b.reservedTLSListener = listener
	b.useReservedTLSGateway = listener != nil
	return nil
}

func (b *bridgeListenerBootstrap) openTCPListener() error {
	if !ServerTcpEnable {
		return nil
	}
	listener, err := bridgeGetTCPListener()
	if err != nil {
		return err
	}
	b.tcpListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openTLSListener() error {
	if !ServerTlsEnable || b.useReservedTLSGateway {
		return nil
	}
	listener, err := bridgeGetTLSListener()
	if err != nil {
		return err
	}
	b.tlsListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openWSListener() error {
	if !ServerWsEnable {
		return nil
	}
	listener, err := bridgeGetWSListener()
	if err != nil {
		return err
	}
	b.wsListener = listener
	return nil
}

func (b *bridgeListenerBootstrap) openWSSListener() error {
	if !ServerWssEnable || b.useReservedTLSGateway {
		return nil
	}
	listener, err := bridgeGetWSSListener()
	if err != nil {
		return err
	}
	b.wssListener = listener
	return nil
}

func bootstrapBridgeListeners() (_ *bridgeListenerBootstrap, err error) {
	bootstrap := &bridgeListenerBootstrap{}
	defer func() {
		if err != nil {
			bootstrap.close()
		}
	}()

	if err = bootstrap.openReservedTLSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openTCPListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openTLSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openWSListener(); err != nil {
		return nil, err
	}
	if err = bootstrap.openWSSListener(); err != nil {
		return nil, err
	}
	return bootstrap, nil
}

// sessionSpawn returns a conn.HandlerSpawn that schedules handlers on tracked
// session goroutines (Add happens synchronously, before the goroutine starts).
func (s *Bridge) sessionSpawn() conn.HandlerSpawn {
	return func(fn func()) { s.sessionGo(fn) }
}

// intake tracks raw during connection intake (handshake and the first work
// dispatch) and invokes process. If shutdown begins, raw is closed and
// process does not run.
func (s *Bridge) intake(raw net.Conn, process func(net.Conn)) {
	s.trackConn(raw)
	defer s.untrackConn(raw)
	if s.IsShuttingDown() {
		_ = raw.Close()
		return
	}
	process(raw)
}

// clientConnHandler is the top-level handler for a newly accepted connection.
func (s *Bridge) clientConnHandler(tunnelType string) func(net.Conn) {
	return func(raw net.Conn) {
		s.intake(raw, func(c net.Conn) {
			s.CliProcess(conn.NewConn(c), tunnelType)
		})
	}
}

func (s *Bridge) startBridgeTCPListener(listeners *bridgeListenerBootstrap) {
	s.VirtualTcpListener = conn.NewVirtualListener(nil)
	s.loopGo(func() {
		conn.AcceptTracked(s.VirtualTcpListener, s.sessionSpawn(), s.clientConnHandler(common.CONN_TCP))
	})
	if listeners != nil && listeners.tcpListener != nil {
		s.VirtualTcpListener.SetAddr(listeners.tcpListener.Addr())
		l := listeners.tcpListener
		vl := s.VirtualTcpListener
		s.loopGo(func() { conn.Accept(l, vl.ServeVirtual) })
	}
}

func (s *Bridge) startBridgeTLSListener(listeners *bridgeListenerBootstrap) {
	s.VirtualTlsListener = conn.NewVirtualListener(nil)
	tlsHandler := func(c net.Conn) {
		s.intake(c, func(plain net.Conn) {
			tlsConn := tls.Server(plain, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})
			s.CliProcess(conn.NewConn(tlsConn), common.CONN_TLS)
		})
	}
	if listeners != nil && listeners.useReservedTLSGateway {
		tlsHandler = s.clientConnHandler(common.CONN_TLS)
	}
	s.loopGo(func() {
		conn.AcceptTracked(s.VirtualTlsListener, s.sessionSpawn(), tlsHandler)
	})
	if listeners != nil && listeners.tlsListener != nil {
		s.VirtualTlsListener.SetAddr(listeners.tlsListener.Addr())
		l := listeners.tlsListener
		vl := s.VirtualTlsListener
		s.loopGo(func() { conn.Accept(l, vl.ServeVirtual) })
	}
}

func (s *Bridge) startBridgeWSListener(listeners *bridgeListenerBootstrap, bridgeCfg connection.BridgeRuntimeConfig) {
	s.VirtualWsListener = conn.NewVirtualListener(nil)
	wsLn := conn.NewWSListener(s.VirtualWsListener, bridgeCfg.Path, bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	s.listeners.wsGateway = wsLn
	s.loopGo(func() {
		conn.AcceptTracked(wsLn, s.sessionSpawn(), s.clientConnHandler(common.CONN_WS))
	})
	if listeners != nil && listeners.wsListener != nil {
		s.VirtualWsListener.SetAddr(listeners.wsListener.Addr())
		l := listeners.wsListener
		vl := s.VirtualWsListener
		s.loopGo(func() { conn.Accept(l, vl.ServeVirtual) })
	}
}

func (s *Bridge) startBridgeWSSListener(listeners *bridgeListenerBootstrap, bridgeCfg connection.BridgeRuntimeConfig) {
	s.VirtualWssListener = conn.NewVirtualListener(nil)
	var wssLn net.Listener = conn.NewWSSListener(s.VirtualWssListener, bridgeCfg.Path, crypt.GetCert(), bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	if listeners != nil && listeners.useReservedTLSGateway {
		wssLn = conn.NewWSListener(s.VirtualWssListener, bridgeCfg.Path, bridgeCfg.TrustedIPs, bridgeCfg.RealIPHeader)
	}
	s.listeners.wssGateway = wssLn
	s.loopGo(func() {
		conn.AcceptTracked(wssLn, s.sessionSpawn(), s.clientConnHandler(common.CONN_WSS))
	})
	if listeners != nil && listeners.wssListener != nil {
		s.VirtualWssListener.SetAddr(listeners.wssListener.Addr())
		l := listeners.wssListener
		vl := s.VirtualWssListener
		s.loopGo(func() { conn.Accept(l, vl.ServeVirtual) })
	}
}

func (s *Bridge) startBridgeReservedTLSGateway(listeners *bridgeListenerBootstrap) {
	if listeners == nil || !listeners.useReservedTLSGateway || listeners.reservedTLSListener == nil {
		return
	}
	s.VirtualTlsListener.SetAddr(listeners.reservedTLSListener.Addr())
	s.VirtualWssListener.SetAddr(listeners.reservedTLSListener.Addr())
	l := listeners.reservedTLSListener
	s.loopGo(func() {
		conn.AcceptTracked(l, s.sessionSpawn(), s.handleReservedTLSConn)
	})
}

func (s *Bridge) startBridgeKCPListener(bridgeCfg connection.BridgeRuntimeConfig) {
	if !ServerKcpEnable {
		return
	}
	addr := common.BuildAddress(bridgeCfg.KCPIP, strconv.Itoa(bridgeCfg.KCPPort))
	kcpLn, err := conn.NewKcpListener(addr)
	if err != nil {
		logs.Error("KCP listener error: %v", err)
		return
	}
	s.listeners.kcp = kcpLn
	s.loopGo(func() {
		_ = conn.ServeKCP(kcpLn, s.sessionSpawn(), s.IsShuttingDown, s.clientConnHandler("kcp"))
	})
}

func buildBridgeQUICConfig(quicCfg connection.QUICRuntimeConfig) *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:    time.Duration(quicCfg.KeepAliveSec) * time.Second,
		MaxIdleTimeout:     time.Duration(quicCfg.IdleTimeoutSec) * time.Second,
		MaxIncomingStreams: quicCfg.MaxStreams,
	}
}

func buildBridgeQUICTLSConfig(quicCfg connection.QUICRuntimeConfig) *tls.Config {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}}
	tlsCfg.NextProtos = quicCfg.ALPN
	return tlsCfg
}

func (s *Bridge) startBridgeQUICListener(bridgeCfg connection.BridgeRuntimeConfig, quicCfg connection.QUICRuntimeConfig) {
	if !ServerQuicEnable {
		return
	}
	addr := common.BuildAddress(bridgeCfg.QUICIP, strconv.Itoa(bridgeCfg.QUICPort))
	quicRuntime, err := conn.NewQuicListener(addr, buildBridgeQUICTLSConfig(quicCfg), buildBridgeQUICConfig(quicCfg))
	if err != nil {
		logs.Error("QUIC listener error: %v", err)
		return
	}
	s.listeners.quicRuntime = quicRuntime
	s.loopGo(func() {
		_ = conn.ServeQUIC(quicRuntime.Listener, s.sessionSpawn(), s.clientConnHandler("quic"))
	})
}

func (s *Bridge) adoptBootstrapListeners(b *bridgeListenerBootstrap) {
	if b == nil {
		return
	}
	s.listeners.tcp = b.tcpListener
	s.listeners.tls = b.tlsListener
	s.listeners.ws = b.wsListener
	s.listeners.wss = b.wssListener
	s.listeners.reservedTLS = b.reservedTLSListener
}

func (s *Bridge) StartTunnel() error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.startBlocked {
		return ErrBridgeShuttingDown
	}
	if s.started {
		return ErrBridgeAlreadyStarted
	}

	bridgeCfg := currentBridgeListenerRuntime()
	quicCfg := currentBridgeQUICRuntime()
	bootstrap, err := bootstrapBridgeListeners()
	if err != nil {
		return err
	}
	s.started = true
	s.adoptBootstrapListeners(bootstrap)
	s.loopGo(s.ping)
	s.startBridgeTCPListener(bootstrap)
	s.startBridgeTLSListener(bootstrap)
	s.startBridgeWSListener(bootstrap, bridgeCfg)
	s.startBridgeWSSListener(bootstrap, bridgeCfg)
	s.startBridgeReservedTLSGateway(bootstrap)
	s.startBridgeKCPListener(bridgeCfg)
	s.startBridgeQUICListener(bridgeCfg, quicCfg)
	return nil
}

const (
	httpGet     = 716984
	httpPost    = 807983
	httpHead    = 726965
	httpPut     = 808585
	httpDelete  = 686976
	httpConnect = 677978
	httpOptions = 798084
	httpTrace   = 848265
	clientHello = 848384
)

func isBridgeGatewayHTTPPrefix(prefix []byte) bool {
	switch common.BytesToNum(prefix) {
	case httpConnect, httpDelete, httpGet, httpHead, httpOptions, httpPost, httpPut, httpTrace:
		return true
	default:
		return false
	}
}

func isBridgeGatewayWebsocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	path := r.URL.Path
	if path == "" {
		path = r.URL.EscapedPath()
	}
	if path == "" {
		path = r.RequestURI
	}
	return path == currentBridgeListenerRuntime().Path
}

type bridgeReservedTLSGateway struct {
	tlsConn *tls.Conn
	prefix  []byte
}

type bridgeReservedTLSRequest struct {
	conn *conn.Conn
	rb   []byte
	req  *http.Request
}

func acceptReservedTLSGateway(raw net.Conn) (bridgeReservedTLSGateway, error) {
	if raw == nil {
		return bridgeReservedTLSGateway{}, io.EOF
	}
	tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{crypt.GetCert()}})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return bridgeReservedTLSGateway{}, err
	}
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(tlsConn, prefix); err != nil {
		_ = tlsConn.Close()
		return bridgeReservedTLSGateway{}, err
	}
	return bridgeReservedTLSGateway{
		tlsConn: tlsConn,
		prefix:  prefix,
	}, nil
}

func (s *Bridge) routeReservedTLSProtocol(gateway bridgeReservedTLSGateway) bool {
	switch common.BytesToNum(gateway.prefix) {
	case clientHello:
		s.VirtualTlsListener.ServeVirtual(conn.NewConn(gateway.tlsConn).SetRb(gateway.prefix))
		return true
	default:
		if !isBridgeGatewayHTTPPrefix(gateway.prefix) {
			_ = gateway.tlsConn.Close()
			return true
		}
		return false
	}
}

func readReservedTLSGatewayRequest(gateway bridgeReservedTLSGateway) (bridgeReservedTLSRequest, error) {
	c := conn.NewConn(gateway.tlsConn).SetRb(gateway.prefix)
	_, _, rb, req, err := c.GetHost()
	if err != nil {
		_ = c.Close()
		return bridgeReservedTLSRequest{}, err
	}
	return bridgeReservedTLSRequest{
		conn: c,
		rb:   rb,
		req:  req,
	}, nil
}

func (s *Bridge) serveReservedTLSWebsocket(request bridgeReservedTLSRequest) {
	if request.conn == nil || !isBridgeGatewayWebsocketRequest(request.req) {
		if request.conn != nil {
			_ = request.conn.Close()
		}
		return
	}
	s.VirtualWssListener.ServeVirtual(request.conn.SetRb(request.rb))
}

func (s *Bridge) handleReservedTLSConn(raw net.Conn) {
	gateway, err := acceptReservedTLSGateway(raw)
	if err != nil {
		return
	}
	if s.routeReservedTLSProtocol(gateway) {
		return
	}
	request, err := readReservedTLSGatewayRequest(gateway)
	if err != nil {
		return
	}
	s.serveReservedTLSWebsocket(request)
}

func (s *Bridge) loadClientNode(clientID int, uuid string) *Node {
	if clientID == 0 {
		return nil
	}
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil
	}
	client, ok := s.loadRuntimeClient(clientID)
	if !ok {
		return nil
	}
	node, ok := client.GetNodeByUUID(uuid)
	if !ok || node == nil {
		return nil
	}
	return node
}

func (s *Bridge) LoadClientNodeRuntime(clientID int, uuid string) any {
	return s.loadClientNode(clientID, uuid)
}

func (s *Bridge) ClientOnlineNodeCount(clientID int) int {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return 0
	}
	return client.OnlineNodeCount()
}

func (s *Bridge) ClientHasMultipleOnlineNodes(clientID int) bool {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return false
	}
	return client.HasMultipleOnlineNodes()
}

func (s *Bridge) SelectClientRouteUUID(clientID int) string {
	client, ok := s.loadRuntimeClient(clientID)
	if !ok || client == nil {
		return ""
	}
	if ClientSelectMode == Primary {
		if node := client.currentNodeIfOnline(); node != nil {
			return strings.TrimSpace(node.UUID)
		}
	}
	node := client.GetNode()
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.UUID)
}

func (s *Bridge) ClientSelectionCanRotate() bool {
	return ClientSelectMode != Primary
}

func (s *Bridge) AddClientNodeConn(clientID int, uuid string) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.AddConn()
	}
}

func (s *Bridge) CutClientNodeConn(clientID int, uuid string) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.CutConn()
	}
}

func (s *Bridge) ObserveClientNodeBridgeTraffic(clientID int, uuid string, in, out int64) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.ObserveBridgeTraffic(in, out)
	}
}

func (s *Bridge) ObserveClientNodeServiceTraffic(clientID int, uuid string, in, out int64) {
	if node := s.loadClientNode(clientID, uuid); node != nil {
		node.ObserveServiceTraffic(in, out)
	}
}
