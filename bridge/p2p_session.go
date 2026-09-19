package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/p2p"
	"github.com/djylb/nps/server/p2pstate"
)

type p2pSessionManager struct {
	sessions     sync.Map
	associations *p2pAssociationManager
}

type p2pBridgeSession struct {
	mgr             *p2pSessionManager
	id              string
	token           string
	visitorID       int
	providerID      int
	task            *file.Tunnel
	timeouts        p2p.P2PTimeouts
	visitorControl  *conn.Conn
	providerControl *conn.Conn
	visitorReport   *p2p.P2PProbeReport
	providerReport  *p2p.P2PProbeReport
	visitorStart    p2p.P2PPunchStart
	providerStart   p2p.P2PPunchStart
	associationID   string
	timer           *time.Timer
	mu              sync.Mutex
	closed          bool
	summarySent     bool
	visitorReady    bool
	providerReady   bool
	goSent          bool
	telemetry       p2pSessionTelemetry
}

type p2pSessionCompletion struct {
	visitorControl     *conn.Conn
	providerControl    *conn.Conn
	associationID      string
	markEstablished    bool
	markFailed         bool
	abortVisitorRole   string
	abortProviderRole  string
	abortReason        string
	telemetrySnapshot  p2pSessionTelemetrySnapshot
	emitTelemetry      bool
	unregisterP2PState bool
}

func newP2PSessionManager(associations *p2pAssociationManager) *p2pSessionManager {
	return &p2pSessionManager{associations: associations}
}

func (m *p2pSessionManager) create(visitorID, providerID int, task *file.Tunnel, visitorControl *conn.Conn, visitorProbe, providerProbe p2p.P2PProbeConfig, association p2p.P2PAssociation, accessGrant p2p.P2PAccessPolicy, route p2p.P2PRouteContext) (*p2pBridgeSession, error) {
	if m == nil {
		return nil, errors.New("nil p2p session manager")
	}
	if task == nil {
		return nil, errors.New("p2p task missing")
	}
	if visitorControl == nil {
		return nil, errors.New("visitor control missing")
	}
	if !p2p.HasUsableProbeEndpoint(visitorProbe) || !p2p.HasUsableProbeEndpoint(providerProbe) {
		return nil, fmt.Errorf("p2p probe endpoint is not configured")
	}
	sessionID := crypt.GenerateUUID(strconv.Itoa(visitorID), strconv.Itoa(providerID), task.Password, time.Now().String()).String()
	token, err := generateP2PSessionToken()
	if err != nil {
		return nil, err
	}
	wire, err := p2p.NewP2PWireSpec()
	if err != nil {
		return nil, err
	}
	timeouts := loadP2PTimeouts()
	ttl := sessionTTL(timeouts)
	session := newBridgeSession(visitorID, providerID, task, visitorControl, sessionID, token, timeouts, visitorProbe, providerProbe, wire, time.Now(), association, accessGrant, route)
	session.mgr = m
	session.associationID = association.AssociationID
	session.timer = time.AfterFunc(ttl, func() {
		session.abort("session timeout")
	})
	if m.associations != nil {
		m.associations.markPunching(association.AssociationID)
	}
	m.sessions.Store(sessionID, session)
	p2pstate.Register(sessionID, wire, token, ttl)
	return session, nil
}

func (m *p2pSessionManager) get(sessionID string) (*p2pBridgeSession, bool) {
	value, ok := m.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	session, ok := value.(*p2pBridgeSession)
	if !ok || session == nil {
		m.deleteSessionIfCurrent(sessionID, value)
		return nil, false
	}
	if session.isClosed() {
		m.deleteSessionIfCurrent(sessionID, session)
		return nil, false
	}
	return session, true
}

func (m *p2pSessionManager) deleteSessionIfCurrent(sessionID string, value interface{}) bool {
	if m == nil || sessionID == "" || value == nil {
		return false
	}
	return m.sessions.CompareAndDelete(sessionID, value)
}

// abortAll aborts every active in-memory session with the given reason. It is
// safe to call during shutdown: individual session aborts are idempotent.
func (m *p2pSessionManager) abortAll(reason string) {
	if m == nil {
		return
	}
	m.sessions.Range(func(key, value any) bool {
		session, ok := value.(*p2pBridgeSession)
		if ok && session != nil {
			session.abort(reason)
		}
		m.sessions.CompareAndDelete(key, value)
		return true
	})
}

func (s *p2pBridgeSession) attachProvider(control *conn.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attachProviderLocked(control)
}

func (s *p2pBridgeSession) serve(role string, control *conn.Conn) {
	for {
		msg, err := readSessionControlMessage(control)
		if err != nil {
			s.abortPending(role, sessionControlReadFailureReason(role, msg.flag))
			return
		}
		if !s.handleControlMessage(role, msg) {
			return
		}
	}
}

func newBridgeStart(role, peerRole, sessionID, token string, probe p2p.P2PProbeConfig, timeouts p2p.P2PTimeouts, wire p2p.P2PWireSpec, associationID string, accessGrant p2p.P2PAccessPolicy, self, peer p2p.P2PPeerRuntime, route p2p.P2PRouteContext) p2p.P2PPunchStart {
	return p2p.P2PPunchStart{
		SessionID:         sessionID,
		Token:             token,
		Wire:              wire,
		Role:              role,
		PeerRole:          peerRole,
		Probe:             probe,
		Timeouts:          timeouts,
		AssociationID:     associationID,
		AssociationPolicy: accessGrant,
		Self:              self,
		Peer:              peer,
		Route:             route,
	}
}

func newBridgeSession(visitorID, providerID int, task *file.Tunnel, visitorControl *conn.Conn, sessionID, token string, timeouts p2p.P2PTimeouts, visitorProbe, providerProbe p2p.P2PProbeConfig, wire p2p.P2PWireSpec, createdAt time.Time, association p2p.P2PAssociation, accessGrant p2p.P2PAccessPolicy, route p2p.P2PRouteContext) *p2pBridgeSession {
	return &p2pBridgeSession{
		id:             sessionID,
		token:          token,
		visitorID:      visitorID,
		providerID:     providerID,
		task:           task,
		timeouts:       timeouts,
		visitorControl: visitorControl,
		visitorStart:   newBridgeStart(common.WORK_P2P_VISITOR, common.WORK_P2P_PROVIDER, sessionID, token, visitorProbe, timeouts, wire, association.AssociationID, accessGrant, association.Visitor, association.Provider, route),
		providerStart:  newBridgeStart(common.WORK_P2P_PROVIDER, common.WORK_P2P_VISITOR, sessionID, token, providerProbe, timeouts, wire, association.AssociationID, accessGrant, association.Provider, association.Visitor, route),
		associationID:  association.AssociationID,
		telemetry:      newP2PSessionTelemetry(createdAt),
	}
}

func (s *p2pBridgeSession) handleProgress(role string, progress *p2p.P2PPunchProgress) {
	if progress == nil {
		return
	}
	completion, shouldComplete := s.recordProgress(role, progress)
	logP2PSessionProgress(progress)
	if shouldComplete {
		s.applySessionCompletion(completion)
	}
}

func (s *p2pBridgeSession) recordProgress(role string, progress *p2p.P2PPunchProgress) (p2pSessionCompletion, bool) {
	var zero p2pSessionCompletion
	s.mu.Lock()
	if s.closed || progress.SessionID != s.id || progress.Role != role {
		s.mu.Unlock()
		return zero, false
	}
	now := time.Now()
	s.ensureTelemetryLocked(now)
	s.telemetry.recordProgress(*progress)
	if s.summarySent && s.goSent {
		snapshot, finalized := s.telemetry.maybeFinalizeSuccess(now)
		if finalized {
			completion := s.prepareLockedTransportEstablishedCompletion(snapshot)
			s.mu.Unlock()
			return completion, true
		}
	}
	s.mu.Unlock()
	return zero, false
}

func logP2PSessionProgress(progress *p2p.P2PPunchProgress) {
	if progress == nil {
		return
	}
	logs.Info("[P2P] session=%s role=%s stage=%s status=%s local=%s remote=%s detail=%s meta=%v counters=%v",
		progress.SessionID, progress.Role, progress.Stage, progress.Status, progress.LocalAddr, progress.RemoteAddr, progress.Detail, progress.Meta, progress.Counters)
}

func (s *p2pBridgeSession) isClosed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *p2pBridgeSession) attachProviderLocked(control *conn.Conn) bool {
	if s.closed || control == nil {
		return false
	}
	if s.providerControl != nil && s.providerControl != control {
		return false
	}
	s.providerControl = control
	return true
}

func (s *p2pBridgeSession) ensureTelemetryLocked(now time.Time) {
	if s.telemetry.createdAt.IsZero() {
		s.telemetry = newP2PSessionTelemetry(now)
	}
}

func (s *p2pBridgeSession) snapshotTelemetryLocked() p2pSessionTelemetrySnapshot {
	if s.telemetry.createdAt.IsZero() {
		return p2pSessionTelemetrySnapshot{}
	}
	return s.telemetry.snapshot()
}

func (s *p2pBridgeSession) tryFinalizeTransportEstablished() {
	completion, ok := s.prepareTransportEstablishedCompletion()
	if !ok {
		return
	}
	s.applySessionCompletion(completion)
}

func (s *p2pBridgeSession) finishTransportEstablished() {
	s.tryFinalizeTransportEstablished()
}

func (s *p2pBridgeSession) prepareTransportEstablishedCompletion() (p2pSessionCompletion, bool) {
	var zero p2pSessionCompletion
	if s == nil {
		return zero, false
	}
	s.mu.Lock()
	if s.closed || !s.summarySent || !s.goSent {
		s.mu.Unlock()
		return zero, false
	}
	snapshot, finalized := s.telemetry.maybeFinalizeSuccess(time.Now())
	if !finalized {
		s.mu.Unlock()
		return zero, false
	}
	completion := s.prepareLockedTransportEstablishedCompletion(snapshot)
	s.mu.Unlock()
	return completion, true
}

func (s *p2pBridgeSession) prepareLockedTransportEstablishedCompletion(snapshot p2pSessionTelemetrySnapshot) p2pSessionCompletion {
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	completion := p2pSessionCompletion{
		visitorControl:    s.visitorControl,
		providerControl:   s.providerControl,
		associationID:     s.associationID,
		markEstablished:   true,
		telemetrySnapshot: snapshot,
		emitTelemetry:     true,
	}
	s.visitorControl = nil
	s.providerControl = nil
	return completion
}

func (s *p2pBridgeSession) telemetrySnapshot() p2pSessionTelemetrySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotTelemetryLocked()
}

const p2pAbortWriteTimeout = 100 * time.Millisecond

type p2pSessionControlMessage struct {
	flag    string
	payload []byte
}

type p2pSessionSummaryDispatch struct {
	visitorControl  *conn.Conn
	providerControl *conn.Conn
	visitorSummary  p2p.P2PProbeSummary
	providerSummary p2p.P2PProbeSummary
	timeout         time.Duration
}

type p2pSessionGoDispatch struct {
	visitorControl  *conn.Conn
	providerControl *conn.Conn
	goMsg           p2p.P2PPunchGo
}

func buildSessionSummaries(sessionID, token string, timeouts p2p.P2PTimeouts, visitorReport, providerReport *p2p.P2PProbeReport) (p2p.P2PProbeSummary, p2p.P2PProbeSummary) {
	visitorSelf := mergeProbeObservation(sessionID, visitorReport.Self)
	providerSelf := mergeProbeObservation(sessionID, providerReport.Self)
	visitorSummary := p2p.P2PProbeSummary{
		SessionID:    sessionID,
		Token:        token,
		Role:         common.WORK_P2P_VISITOR,
		PeerRole:     common.WORK_P2P_PROVIDER,
		Self:         visitorSelf,
		Peer:         providerSelf,
		Timeouts:     timeouts,
		SummaryHints: buildSummaryHintsModel(visitorSelf, providerSelf),
	}
	providerSummary := p2p.P2PProbeSummary{
		SessionID:    sessionID,
		Token:        token,
		Role:         common.WORK_P2P_PROVIDER,
		PeerRole:     common.WORK_P2P_VISITOR,
		Self:         providerSelf,
		Peer:         visitorSelf,
		Timeouts:     timeouts,
		SummaryHints: visitorSummary.SummaryHints,
	}
	return visitorSummary, providerSummary
}

func readSessionControlMessage(control *conn.Conn) (p2pSessionControlMessage, error) {
	var zero p2pSessionControlMessage
	if control == nil {
		return zero, fmt.Errorf("nil control conn")
	}
	flag, err := control.ReadFlag()
	if err != nil {
		return zero, err
	}
	payload, err := control.GetShortLenContent()
	if err != nil {
		return p2pSessionControlMessage{flag: flag}, err
	}
	return p2pSessionControlMessage{flag: flag, payload: payload}, nil
}

func sessionControlReadFailureReason(role, flag string) string {
	switch flag {
	case common.P2P_PROBE_REPORT:
		return fmt.Sprintf("%s report read failed", role)
	case common.P2P_PUNCH_PROGRESS:
		return fmt.Sprintf("%s progress read failed", role)
	case common.P2P_PUNCH_READY:
		return fmt.Sprintf("%s ready read failed", role)
	case common.P2P_PUNCH_ABORT:
		return fmt.Sprintf("%s abort read failed", role)
	case "":
		return fmt.Sprintf("%s control closed", role)
	default:
		return fmt.Sprintf("%s control payload read failed", role)
	}
}

func decodeSessionPayload[T any](msg p2pSessionControlMessage) (T, error) {
	var zero T
	if err := json.Unmarshal(msg.payload, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}

func (s *p2pBridgeSession) handleControlMessage(role string, msg p2pSessionControlMessage) bool {
	switch msg.flag {
	case common.P2P_PROBE_REPORT:
		report, err := decodeSessionPayload[p2p.P2PProbeReport](msg)
		if err != nil {
			s.abortPending(role, sessionControlReadFailureReason(role, msg.flag))
			return false
		}
		s.handleReport(role, &report)
	case common.P2P_PUNCH_PROGRESS:
		progress, err := decodeSessionPayload[p2p.P2PPunchProgress](msg)
		if err != nil {
			s.abortPending(role, sessionControlReadFailureReason(role, msg.flag))
			return false
		}
		s.handleProgress(role, &progress)
	case common.P2P_PUNCH_READY:
		ready, err := decodeSessionPayload[p2p.P2PPunchReady](msg)
		if err != nil {
			s.abortPending(role, sessionControlReadFailureReason(role, msg.flag))
			return false
		}
		s.handleReady(role, &ready)
	case common.P2P_PUNCH_ABORT:
		abortMsg, err := decodeSessionPayload[p2p.P2PPunchAbort](msg)
		if err != nil {
			s.abortPending(role, sessionControlReadFailureReason(role, msg.flag))
			return false
		}
		s.handleAbort(role, &abortMsg)
	}
	return true
}

func writeSessionMessage(control *conn.Conn, flag string, payload any) error {
	if control == nil {
		return nil
	}
	return p2p.WriteBridgeMessage(control, flag, payload)
}

func writeSessionAbort(control *conn.Conn, sessionID, role, reason string) {
	if control == nil {
		return
	}
	_ = control.SetWriteDeadline(time.Now().Add(p2pAbortWriteTimeout))
	defer func() {
		_ = control.SetWriteDeadline(time.Time{})
	}()
	_ = p2p.WriteBridgeMessage(control, common.P2P_PUNCH_ABORT, p2p.P2PPunchAbort{
		SessionID: sessionID,
		Role:      role,
		Reason:    reason,
	})
}

func (s *p2pBridgeSession) handleReport(role string, report *p2p.P2PProbeReport) {
	if !s.recordReport(role, report) {
		return
	}
	s.sendSummary()
}

func (s *p2pBridgeSession) recordReport(role string, report *p2p.P2PProbeReport) bool {
	s.mu.Lock()
	if s.closed || report == nil || report.SessionID != s.id || report.Token != s.token || report.Role != role {
		s.mu.Unlock()
		return false
	}
	switch role {
	case common.WORK_P2P_VISITOR:
		s.visitorReport = report
	case common.WORK_P2P_PROVIDER:
		s.providerReport = report
	}
	ready := s.visitorReport != nil && s.providerReport != nil
	s.mu.Unlock()
	return ready
}

func (s *p2pBridgeSession) handleReady(role string, ready *p2p.P2PPunchReady) {
	if !s.recordReady(role, ready) {
		return
	}
	s.sendGo()
}

func (s *p2pBridgeSession) recordReady(role string, ready *p2p.P2PPunchReady) bool {
	s.mu.Lock()
	if s.closed || ready == nil || ready.SessionID != s.id || ready.Role != role || !s.summarySent {
		s.mu.Unlock()
		return false
	}
	switch role {
	case common.WORK_P2P_VISITOR:
		s.visitorReady = true
	case common.WORK_P2P_PROVIDER:
		s.providerReady = true
	}
	readyToGo := s.visitorReady && s.providerReady && !s.goSent
	s.mu.Unlock()
	return readyToGo
}

func (s *p2pBridgeSession) sendSummary() {
	dispatch, ok := s.prepareSummaryDispatch()
	if !ok {
		return
	}
	if err := writeSessionMessage(dispatch.visitorControl, common.P2P_PROBE_SUMMARY, dispatch.visitorSummary); err != nil {
		s.abort("send visitor summary failed")
		return
	}
	if err := writeSessionMessage(dispatch.providerControl, common.P2P_PROBE_SUMMARY, dispatch.providerSummary); err != nil {
		s.abort("send provider summary failed")
		return
	}
	s.completeSummaryDispatch(dispatch)
}

func (s *p2pBridgeSession) prepareSummaryDispatch() (p2pSessionSummaryDispatch, bool) {
	var zero p2pSessionSummaryDispatch
	s.mu.Lock()
	if s.closed || s.summarySent || s.visitorReport == nil || s.providerReport == nil {
		s.mu.Unlock()
		return zero, false
	}
	now := time.Now()
	visitorSummary, providerSummary := buildSessionSummaries(s.id, s.token, s.timeouts, s.visitorReport, s.providerReport)
	s.summarySent = true
	s.ensureTelemetryLocked(now)
	s.telemetry.recordSummary(visitorSummary.SummaryHints, now)
	dispatch := p2pSessionSummaryDispatch{
		visitorControl:  s.visitorControl,
		providerControl: s.providerControl,
		visitorSummary:  visitorSummary,
		providerSummary: providerSummary,
		timeout:         postSummaryTTL(s.timeouts),
	}
	s.mu.Unlock()
	return dispatch, true
}

func (s *p2pBridgeSession) completeSummaryDispatch(dispatch p2pSessionSummaryDispatch) {
	if !s.schedulePostSummaryTimeout(dispatch.timeout) {
		return
	}
	logs.Info("[P2P] session=%s summary sent via bridge", s.id)
	p2pstate.Unregister(s.id)
}

func (s *p2pBridgeSession) schedulePostSummaryTimeout(timeout time.Duration) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	if s.timer == nil {
		s.timer = time.AfterFunc(timeout, func() {
			s.abort("post-summary timeout")
		})
	} else {
		s.timer.Reset(timeout)
	}
	s.mu.Unlock()
	return true
}

func (s *p2pBridgeSession) sendGo() {
	dispatch, ok := s.prepareGoDispatch()
	if !ok {
		return
	}
	msg := dispatch.goMsg
	msg.Role = common.WORK_P2P_VISITOR
	if err := writeSessionMessage(dispatch.visitorControl, common.P2P_PUNCH_GO, msg); err != nil {
		s.abort("send visitor punch go failed")
		return
	}
	msg = dispatch.goMsg
	msg.Role = common.WORK_P2P_PROVIDER
	if err := writeSessionMessage(dispatch.providerControl, common.P2P_PUNCH_GO, msg); err != nil {
		s.abort("send provider punch go failed")
		return
	}
	logs.Info("[P2P] session=%s punch go sent delay=%dms", s.id, dispatch.goMsg.DelayMs)
	s.tryFinalizeTransportEstablished()
}

func (s *p2pBridgeSession) prepareGoDispatch() (p2pSessionGoDispatch, bool) {
	var zero p2pSessionGoDispatch
	s.mu.Lock()
	if s.closed || !s.summarySent || s.goSent || s.visitorControl == nil || s.providerControl == nil {
		s.mu.Unlock()
		return zero, false
	}
	now := time.Now()
	delayMs := punchGoDelayMs(s.timeouts, s.telemetry.summaryHints)
	dispatch := p2pSessionGoDispatch{
		visitorControl:  s.visitorControl,
		providerControl: s.providerControl,
		goMsg: p2p.P2PPunchGo{
			SessionID: s.id,
			DelayMs:   delayMs,
			SentAtMs:  now.UnixMilli(),
		},
	}
	s.goSent = true
	s.ensureTelemetryLocked(now)
	s.telemetry.recordGo(now)
	s.mu.Unlock()
	return dispatch, true
}

func (s *p2pBridgeSession) abortPending(role, reason string) {
	if !s.shouldAbortPending(role, time.Now()) {
		return
	}
	s.abort(reason)
}

func (s *p2pBridgeSession) handleAbort(role string, abortMsg *p2p.P2PPunchAbort) {
	if !s.acceptsAbort(role, abortMsg) {
		return
	}
	s.abort(abortMsg.Reason)
}

func (s *p2pBridgeSession) abort(reason string) {
	if s == nil {
		return
	}
	completion, ok := s.prepareAbortCompletion(reason)
	if !ok {
		return
	}
	s.applySessionCompletion(completion)
}

func (s *p2pBridgeSession) prepareAbortCompletion(reason string) (p2pSessionCompletion, bool) {
	var zero p2pSessionCompletion
	now := time.Now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return zero, false
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.ensureTelemetryLocked(now)
	snapshot, emitTelemetry := s.telemetry.finalizeOutcome("aborted", reason, now)
	completion := p2pSessionCompletion{
		visitorControl:     s.visitorControl,
		providerControl:    s.providerControl,
		associationID:      s.associationID,
		markFailed:         true,
		abortVisitorRole:   s.visitorStart.Role,
		abortProviderRole:  s.providerStart.Role,
		abortReason:        reason,
		telemetrySnapshot:  snapshot,
		emitTelemetry:      emitTelemetry,
		unregisterP2PState: true,
	}
	s.visitorControl = nil
	s.providerControl = nil
	s.mu.Unlock()
	return completion, true
}

func (s *p2pBridgeSession) applySessionCompletion(completion p2pSessionCompletion) {
	if completion.abortReason != "" {
		writeSessionAbort(completion.visitorControl, s.id, completion.abortVisitorRole, completion.abortReason)
		writeSessionAbort(completion.providerControl, s.id, completion.abortProviderRole, completion.abortReason)
	}
	if completion.visitorControl != nil {
		_ = completion.visitorControl.Close()
	}
	if completion.providerControl != nil {
		_ = completion.providerControl.Close()
	}
	if completion.unregisterP2PState {
		p2pstate.Unregister(s.id)
	}
	if s.mgr != nil {
		s.mgr.deleteSessionIfCurrent(s.id, s)
		if completion.associationID != "" && s.mgr.associations != nil {
			if completion.markEstablished {
				s.mgr.associations.markEstablished(completion.associationID)
			}
			if completion.markFailed {
				s.mgr.associations.markFailed(completion.associationID)
			}
		}
	}
	if completion.emitTelemetry {
		emitP2PSessionTelemetry(s.id, completion.telemetrySnapshot)
	}
}

func (s *p2pBridgeSession) shouldAbortPending(role string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.ensureTelemetryLocked(now)
	return !s.telemetry.roleTransportEstablished(role)
}

func (s *p2pBridgeSession) acceptsAbort(role string, abortMsg *p2p.P2PPunchAbort) bool {
	if abortMsg == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	return abortMsg.SessionID == s.id && abortMsg.Role == role
}

type p2pSessionTelemetry struct {
	createdAt    time.Time
	summaryAt    time.Time
	goAt         time.Time
	outcomeAt    time.Time
	outcome      string
	reason       string
	summaryHints *p2p.P2PSummaryHints
	roles        map[string]*p2pRoleTelemetry
	finalLogged  bool
}

type p2pRoleTelemetry struct {
	LastStage            string
	LastStatus           string
	LastDetail           string
	LastLocalAddr        string
	LastRemoteAddr       string
	LastFamily           string
	TransportMode        string
	TransportEstablished bool
	Counters             map[string]int
	Meta                 map[string]string
	Stages               map[string]*p2pStageTelemetry
	ProbeFamilies        map[string]p2p.P2PProbeTelemetrySnapshot
	PortMappings         map[string]p2p.P2PPortMappingTelemetrySnapshot
}

type p2pStageTelemetry struct {
	FirstAt time.Time
	LastAt  time.Time
	Count   int
	Status  string
	Detail  string
	Family  string
}

type p2pSessionTelemetrySnapshot = p2p.P2PSessionTelemetrySnapshot
type p2pRoleTelemetrySnapshot = p2p.P2PRoleTelemetrySnapshot
type p2pStageTelemetrySnapshot = p2p.P2PStageTelemetrySnapshot

type p2pSessionTelemetrySink interface {
	EmitSessionTelemetry(record p2p.P2PSessionTelemetryRecord)
}

func newP2PSessionTelemetry(now time.Time) p2pSessionTelemetry {
	return p2pSessionTelemetry{
		createdAt: now,
		roles:     make(map[string]*p2pRoleTelemetry, 2),
	}
}

func setP2PSessionTelemetrySinkForTest(sink p2pSessionTelemetrySink) func() {
	return p2p.SetP2PTelemetrySink(sink)
}

func emitP2PSessionTelemetry(sessionID string, snapshot p2pSessionTelemetrySnapshot) {
	p2p.EmitP2PSessionTelemetry(sessionID, snapshot)
}

func (t *p2pSessionTelemetry) ensureRole(role string) *p2pRoleTelemetry {
	if t.roles == nil {
		t.roles = make(map[string]*p2pRoleTelemetry, 2)
	}
	telemetry := t.roles[role]
	if telemetry != nil {
		return telemetry
	}
	telemetry = &p2pRoleTelemetry{
		Counters:      make(map[string]int),
		Meta:          make(map[string]string),
		Stages:        make(map[string]*p2pStageTelemetry),
		ProbeFamilies: make(map[string]p2p.P2PProbeTelemetrySnapshot),
		PortMappings:  make(map[string]p2p.P2PPortMappingTelemetrySnapshot),
	}
	t.roles[role] = telemetry
	return telemetry
}

func (t *p2pSessionTelemetry) recordProgress(progress p2p.P2PPunchProgress) {
	if progress.Role == "" {
		return
	}
	at := time.UnixMilli(progress.Timestamp)
	if progress.Timestamp == 0 {
		at = time.Now()
	}
	role := t.ensureRole(progress.Role)
	role.LastStage = progress.Stage
	role.LastStatus = progress.Status
	role.LastDetail = progress.Detail
	role.LastLocalAddr = progress.LocalAddr
	role.LastRemoteAddr = progress.RemoteAddr
	role.LastFamily = progressFamily(progress)
	if mode := progressTransportMode(progress); mode != "" {
		role.TransportMode = mode
	}
	if progress.Stage == "transport_established" && progress.Status != "fail" {
		role.TransportEstablished = true
	}
	if len(progress.Counters) > 0 {
		role.Counters = cloneIntMap(progress.Counters)
	}
	role.Meta = mergeStringMaps(role.Meta, progress.Meta)
	family := progressFamily(progress)
	if probe, ok := progressProbeTelemetry(progress, family); ok {
		role.ProbeFamilies[family] = mergeProbeTelemetry(role.ProbeFamilies[family], probe)
	}
	if portMapping, ok := progressPortMappingTelemetry(progress, family); ok {
		role.PortMappings[family] = mergePortMappingTelemetry(role.PortMappings[family], portMapping)
	}
	stage := role.Stages[progress.Stage]
	if stage == nil {
		stage = &p2pStageTelemetry{FirstAt: at}
		role.Stages[progress.Stage] = stage
	}
	if stage.FirstAt.IsZero() {
		stage.FirstAt = at
	}
	stage.LastAt = at
	stage.Count++
	stage.Status = progress.Status
	stage.Detail = progress.Detail
	stage.Family = progressFamily(progress)
}

func (t *p2pSessionTelemetry) recordSummary(hints *p2p.P2PSummaryHints, at time.Time) {
	t.summaryHints = p2p.CloneP2PSummaryHints(hints)
	t.summaryAt = at
}

func (t *p2pSessionTelemetry) recordGo(at time.Time) {
	t.goAt = at
}

func (t *p2pSessionTelemetry) maybeFinalizeSuccess(at time.Time) (p2pSessionTelemetrySnapshot, bool) {
	if t.finalLogged {
		return p2pSessionTelemetrySnapshot{}, false
	}
	if !t.allTransportEstablished() {
		return p2pSessionTelemetrySnapshot{}, false
	}
	t.outcome = "transport_established"
	t.outcomeAt = at
	t.finalLogged = true
	return t.snapshot(), true
}

func (t *p2pSessionTelemetry) roleTransportEstablished(role string) bool {
	if t == nil || role == "" {
		return false
	}
	telemetry := t.roles[role]
	return telemetry != nil && telemetry.TransportEstablished
}

func (t *p2pSessionTelemetry) allTransportEstablished() bool {
	if t == nil {
		return false
	}
	visitor := t.roles[common.WORK_P2P_VISITOR]
	provider := t.roles[common.WORK_P2P_PROVIDER]
	return visitor != nil && provider != nil && visitor.TransportEstablished && provider.TransportEstablished
}

func (t *p2pSessionTelemetry) finalizeOutcome(outcome, reason string, at time.Time) (p2pSessionTelemetrySnapshot, bool) {
	if t.finalLogged {
		return p2pSessionTelemetrySnapshot{}, false
	}
	t.outcome = outcome
	t.reason = reason
	t.outcomeAt = at
	t.finalLogged = true
	return t.snapshot(), true
}

func (t *p2pSessionTelemetry) snapshot() p2pSessionTelemetrySnapshot {
	snapshot := p2pSessionTelemetrySnapshot{
		CreatedAtMs:  timestampMillis(t.createdAt),
		SummaryAtMs:  timestampMillis(t.summaryAt),
		GoAtMs:       timestampMillis(t.goAt),
		OutcomeAtMs:  timestampMillis(t.outcomeAt),
		Outcome:      t.outcome,
		Reason:       t.reason,
		SummaryHints: p2p.CloneP2PSummaryHints(t.summaryHints),
		Roles:        make(map[string]p2pRoleTelemetrySnapshot, len(t.roles)),
	}
	for role, telemetry := range t.roles {
		if telemetry == nil {
			continue
		}
		roleSnapshot := p2pRoleTelemetrySnapshot{
			LastStage:            telemetry.LastStage,
			LastStatus:           telemetry.LastStatus,
			LastDetail:           telemetry.LastDetail,
			LastLocalAddr:        telemetry.LastLocalAddr,
			LastRemoteAddr:       telemetry.LastRemoteAddr,
			LastFamily:           telemetry.LastFamily,
			TransportMode:        telemetry.TransportMode,
			TransportEstablished: telemetry.TransportEstablished,
			Counters:             cloneIntMap(telemetry.Counters),
			Meta:                 cloneStringMap(telemetry.Meta),
			Stages:               make(map[string]p2pStageTelemetrySnapshot, len(telemetry.Stages)),
			ProbeFamilies:        cloneProbeTelemetryMap(telemetry.ProbeFamilies),
			PortMappings:         clonePortMappingTelemetryMap(telemetry.PortMappings),
		}
		for stage, details := range telemetry.Stages {
			if details == nil {
				continue
			}
			roleSnapshot.Stages[stage] = p2pStageTelemetrySnapshot{
				FirstAtMs: timestampMillis(details.FirstAt),
				LastAtMs:  timestampMillis(details.LastAt),
				Count:     details.Count,
				Status:    details.Status,
				Detail:    details.Detail,
				Family:    details.Family,
			}
		}
		snapshot.Roles[role] = roleSnapshot
	}
	return snapshot
}

func timestampMillis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func cloneIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneProbeTelemetryMap(values map[string]p2p.P2PProbeTelemetrySnapshot) map[string]p2p.P2PProbeTelemetrySnapshot {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]p2p.P2PProbeTelemetrySnapshot, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func clonePortMappingTelemetryMap(values map[string]p2p.P2PPortMappingTelemetrySnapshot) map[string]p2p.P2PPortMappingTelemetrySnapshot {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]p2p.P2PPortMappingTelemetrySnapshot, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func mergeStringMaps(current, update map[string]string) map[string]string {
	if len(current) == 0 && len(update) == 0 {
		return nil
	}
	out := cloneStringMap(current)
	if out == nil {
		out = make(map[string]string, len(update))
	}
	for key, value := range update {
		out[key] = value
	}
	return out
}

func mergeProbeTelemetry(current, update p2p.P2PProbeTelemetrySnapshot) p2p.P2PProbeTelemetrySnapshot {
	if update.PublicIP != "" {
		current.PublicIP = update.PublicIP
	}
	if update.NATType != "" {
		current.NATType = update.NATType
	}
	if update.MappingBehavior != "" {
		current.MappingBehavior = update.MappingBehavior
	}
	if update.FilteringBehavior != "" {
		current.FilteringBehavior = update.FilteringBehavior
	}
	if update.ClassificationLevel != "" {
		current.ClassificationLevel = update.ClassificationLevel
	}
	if update.ProbeEndpointCount != 0 {
		current.ProbeEndpointCount = update.ProbeEndpointCount
	}
	if update.ProbeProviderCount != 0 {
		current.ProbeProviderCount = update.ProbeProviderCount
	}
	if update.ObservedBasePort != 0 {
		current.ObservedBasePort = update.ObservedBasePort
	}
	if update.ObservedInterval != 0 {
		current.ObservedInterval = update.ObservedInterval
	}
	current.ProbePortRestricted = current.ProbePortRestricted || update.ProbePortRestricted
	current.MappingConfidenceLow = current.MappingConfidenceLow || update.MappingConfidenceLow
	current.FilteringTested = current.FilteringTested || update.FilteringTested
	return current
}

func mergePortMappingTelemetry(current, update p2p.P2PPortMappingTelemetrySnapshot) p2p.P2PPortMappingTelemetrySnapshot {
	if update.Method != "" {
		current.Method = update.Method
	}
	if update.ExternalAddr != "" {
		current.ExternalAddr = update.ExternalAddr
	}
	if update.InternalAddr != "" {
		current.InternalAddr = update.InternalAddr
	}
	if update.LeaseSeconds != 0 {
		current.LeaseSeconds = update.LeaseSeconds
	}
	return current
}

func progressProbeTelemetry(progress p2p.P2PPunchProgress, family string) (p2p.P2PProbeTelemetrySnapshot, bool) {
	if progress.Meta == nil || family == "" {
		return p2p.P2PProbeTelemetrySnapshot{}, false
	}
	meta := progress.Meta
	telemetry := p2p.P2PProbeTelemetrySnapshot{
		PublicIP:             meta["probe_public_ip"],
		NATType:              meta["nat_type"],
		MappingBehavior:      meta["mapping_behavior"],
		FilteringBehavior:    meta["filtering_behavior"],
		ClassificationLevel:  meta["classification_level"],
		ProbeEndpointCount:   parseIntMeta(meta, "probe_endpoint_count"),
		ProbeProviderCount:   parseIntMeta(meta, "probe_provider_count"),
		ObservedBasePort:     parseIntMeta(meta, "probe_observed_base_port"),
		ObservedInterval:     parseIntMeta(meta, "probe_observed_interval"),
		ProbePortRestricted:  parseBoolMeta(meta, "probe_port_restricted"),
		MappingConfidenceLow: parseBoolMeta(meta, "mapping_confidence_low"),
		FilteringTested:      parseBoolMeta(meta, "probe_filtering_tested"),
	}
	if telemetry == (p2p.P2PProbeTelemetrySnapshot{}) {
		return p2p.P2PProbeTelemetrySnapshot{}, false
	}
	return telemetry, true
}

func progressPortMappingTelemetry(progress p2p.P2PPunchProgress, family string) (p2p.P2PPortMappingTelemetrySnapshot, bool) {
	if progress.Meta == nil || family == "" {
		return p2p.P2PPortMappingTelemetrySnapshot{}, false
	}
	meta := progress.Meta
	telemetry := p2p.P2PPortMappingTelemetrySnapshot{
		Method:       meta["port_mapping_method"],
		ExternalAddr: meta["port_mapping_external_addr"],
		InternalAddr: meta["port_mapping_internal_addr"],
		LeaseSeconds: parseIntMeta(meta, "port_mapping_lease_seconds"),
	}
	if telemetry == (p2p.P2PPortMappingTelemetrySnapshot{}) {
		return p2p.P2PPortMappingTelemetrySnapshot{}, false
	}
	return telemetry, true
}

func parseIntMeta(meta map[string]string, key string) int {
	if len(meta) == 0 {
		return 0
	}
	value := strings.TrimSpace(meta[key])
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func parseBoolMeta(meta map[string]string, key string) bool {
	if len(meta) == 0 {
		return false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(meta[key]))
	if err != nil {
		return false
	}
	return parsed
}

func progressFamily(progress p2p.P2PPunchProgress) string {
	if progress.Meta != nil && progress.Meta["family"] != "" {
		return progress.Meta["family"]
	}
	if ip := net.ParseIP(strings.Trim(common.GetIpByAddr(progress.LocalAddr), "[]")); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	if ip := net.ParseIP(strings.Trim(common.GetIpByAddr(progress.RemoteAddr), "[]")); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return ""
}

func progressTransportMode(progress p2p.P2PPunchProgress) string {
	if progress.Meta != nil && progress.Meta["transport_mode"] != "" {
		return progress.Meta["transport_mode"]
	}
	if progress.Stage == "transport_established" || progress.Stage == "transport_start" || progress.Stage == "handover_begin" {
		return progress.Detail
	}
	return ""
}
