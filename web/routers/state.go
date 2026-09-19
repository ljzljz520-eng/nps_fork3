package routers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server"
	webapi "github.com/djylb/nps/web/api"
	webservice "github.com/djylb/nps/web/service"
)

const (
	nodeEventLogStateFile    = "node_changes_state.json"
	nodeEventLogJournalFile  = "node_changes_journal.jsonl"
	nodeIdempotencyStateFile = "node_idempotency_state.json"
	nodeCallbackStateFile    = "node_callbacks_state.json"
	nodeWebhookStateFile     = "node_webhooks_state.json"
	nodeOperationsStateFile  = "node_operations_state.json"
	nodeRuntimeStateVersion  = 1
	nodeRuntimePersistDelay  = 50 * time.Millisecond
)

var (
	nodeRuntimeStateWritersMu sync.Mutex
	nodeRuntimeStateWriters   = make(map[string]map[*nodeRuntimeStateWriter]struct{})
	nodeRuntimeAppendWriters  = make(map[string]map[*nodeRuntimeAppendWriter]struct{})
)

type nodeRuntimeStateWriter struct {
	path      string
	delay     time.Duration
	mu        sync.Mutex
	pending   []byte
	scheduled bool
	closed    bool
	stopCh    chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

type nodeRuntimeAppendWriter struct {
	path      string
	delay     time.Duration
	mu        sync.Mutex
	pending   []byte
	scheduled bool
	closed    bool
	stopCh    chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

type compositeManagementHooks struct {
	primary  webapi.Hooks
	hub      *nodeEventHub
	log      *nodeEventLog
	webhooks *nodeWebhookStore
}

func (h compositeManagementHooks) OnManagementEvent(ctx context.Context, event webapi.Event) error {
	if h.log != nil {
		if shouldPersistNodeEvent(event) {
			event = h.log.Record(event)
		} else {
			event = h.log.RecordLiveOnly(event)
		}
	}
	if h.hub != nil {
		h.hub.Publish(event)
	}
	if h.webhooks != nil && nodeEventMayInvalidateSelectors(event) {
		h.webhooks.ScrubEvent(ctx, event)
	}
	if h.primary == nil {
		return nil
	}
	return h.primary.OnManagementEvent(ctx, event)
}

func shouldPersistNodeEvent(event webapi.Event) bool {
	return webapi.ShouldPersistNodeEventName(event.Name)
}

type nodeEventHub struct {
	mu     sync.RWMutex
	nextID int64
	authz  webservice.AuthorizationService
	subs   map[int64]*nodeEventSubscription
}

type nodeEventSubscription struct {
	id        int64
	actor     *webapi.Actor
	actorMu   sync.RWMutex
	matcher   func(webapi.Event) bool
	ch        chan webapi.Event
	done      chan struct{}
	hub       *nodeEventHub
	closeOnce sync.Once

	overflowMu       sync.RWMutex
	overflowSequence int64
}

func newNodeEventHub(authz webservice.AuthorizationService) *nodeEventHub {
	if isNilRouterServiceValue(authz) {
		authz = webservice.DefaultAuthorizationService{}
	}
	return &nodeEventHub{
		authz: authz,
		subs:  make(map[int64]*nodeEventSubscription),
	}
}

func (h *nodeEventHub) Reset() {
	if h == nil {
		return
	}
	h.mu.Lock()
	subs := make([]*nodeEventSubscription, 0, len(h.subs))
	for _, sub := range h.subs {
		subs = append(subs, sub)
	}
	h.subs = make(map[int64]*nodeEventSubscription)
	h.mu.Unlock()
	for _, sub := range subs {
		if sub != nil {
			sub.closeOnce.Do(func() {
				close(sub.done)
			})
		}
	}
}

func (h *nodeEventHub) Subscribe(actor *webapi.Actor) *nodeEventSubscription {
	return h.SubscribeWithOptions(actor, nil, 32)
}

func (h *nodeEventHub) SubscribeWithOptions(actor *webapi.Actor, matcher func(webapi.Event) bool, buffer int) *nodeEventSubscription {
	if h == nil {
		return nil
	}
	if buffer <= 0 {
		buffer = 32
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	sub := &nodeEventSubscription{
		id:      h.nextID,
		actor:   cloneActor(actor),
		matcher: matcher,
		ch:      make(chan webapi.Event, buffer),
		done:    make(chan struct{}),
		hub:     h,
	}
	h.subs[sub.id] = sub
	return sub
}

func (h *nodeEventHub) removeSubscription(sub *nodeEventSubscription, overflowSequence int64) {
	if sub == nil {
		return
	}
	sub.closeOnce.Do(func() {
		if overflowSequence > 0 {
			sub.overflowMu.Lock()
			sub.overflowSequence = overflowSequence
			sub.overflowMu.Unlock()
		}
		if h != nil {
			h.mu.Lock()
			if current, ok := h.subs[sub.id]; ok && current == sub {
				delete(h.subs, sub.id)
			}
			h.mu.Unlock()
		}
		close(sub.done)
	})
}

func (h *nodeEventHub) Publish(event webapi.Event) {
	if h == nil {
		return
	}
	h.mu.RLock()
	subs := make([]*nodeEventSubscription, 0, len(h.subs))
	for _, sub := range h.subs {
		subs = append(subs, sub)
	}
	h.mu.RUnlock()
	for _, sub := range subs {
		if sub == nil || !h.allowsEvent(sub.Actor(), event) {
			continue
		}
		if sub.matcher != nil && !sub.matcher(event) {
			continue
		}
		select {
		case <-sub.done:
			continue
		default:
		}
		select {
		case sub.ch <- event:
		default:
			h.removeSubscription(sub, event.Sequence)
		}
	}
}

func (s *nodeEventSubscription) Actor() *webapi.Actor {
	if s == nil {
		return nil
	}
	s.actorMu.RLock()
	defer s.actorMu.RUnlock()
	return cloneActor(s.actor)
}

func (s *nodeEventSubscription) SetActor(actor *webapi.Actor) {
	if s == nil {
		return
	}
	s.actorMu.Lock()
	s.actor = cloneActor(actor)
	s.actorMu.Unlock()
}

func (s *nodeEventSubscription) Events() <-chan webapi.Event {
	if s == nil {
		return nil
	}
	return s.ch
}

func (s *nodeEventSubscription) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *nodeEventSubscription) OverflowSequence() (int64, bool) {
	if s == nil {
		return 0, false
	}
	s.overflowMu.RLock()
	defer s.overflowMu.RUnlock()
	return s.overflowSequence, s.overflowSequence > 0
}

func (s *nodeEventSubscription) Close() {
	if s == nil || s.hub == nil {
		return
	}
	s.hub.removeSubscription(s, 0)
}

func drainNodeSubscriptionEvents(sub *nodeEventSubscription, handle func(webapi.Event)) {
	if sub == nil {
		return
	}
	for {
		select {
		case event := <-sub.Events():
			if handle != nil {
				handle(event)
			}
		default:
			return
		}
	}
}

func (h *nodeEventHub) allowsEvent(actor *webapi.Actor, event webapi.Event) bool {
	if actor == nil || strings.TrimSpace(actor.Kind) == "" || strings.EqualFold(actor.Kind, webservice.RoleAnonymous) {
		return false
	}
	if actor.IsAdmin {
		return true
	}
	principal := webapi.PrincipalFromActor(actor)
	resource := strings.ToLower(strings.TrimSpace(event.Resource))
	switch resource {
	case "client":
		return h.allowsClientResource(actor, principal, eventFieldInt(event.Fields, "id"), event.Fields)
	case "tunnel":
		return h.allowsTunnelResource(actor, principal, eventFieldInt(event.Fields, "id"), event.Fields)
	case "host":
		return h.allowsHostResource(actor, principal, eventFieldInt(event.Fields, "id"), event.Fields)
	case "user":
		return allowsUserEvent(actor, eventFieldInt(event.Fields, "id"))
	case "node", "global", "auth", "login", "webhook", "callbacks_queue":
		return strings.EqualFold(actor.Kind, "platform_admin")
	case "operations", "management_platforms":
		return strings.EqualFold(actor.Kind, "platform_admin") || strings.EqualFold(actor.Kind, "platform_user")
	default:
		if id := eventFieldInt(event.Fields, "id"); id > 0 {
			if h.allowsClientResource(actor, principal, id, event.Fields) {
				return true
			}
			if h.allowsTunnelResource(actor, principal, id, event.Fields) {
				return true
			}
			if h.allowsHostResource(actor, principal, id, event.Fields) {
				return true
			}
		}
	}
	return false
}

func (h *nodeEventHub) allowsClientResource(actor *webapi.Actor, principal webservice.Principal, clientID int, fields map[string]interface{}) bool {
	if clientID <= 0 {
		return allowsClientEventFallback(actor, fields)
	}
	if h.authz.RequireClient(principal, clientID) == nil {
		return true
	}
	return allowsClientEventFallback(actor, fields)
}

func (h *nodeEventHub) allowsTunnelResource(actor *webapi.Actor, principal webservice.Principal, tunnelID int, fields map[string]interface{}) bool {
	if tunnelID <= 0 {
		return h.allowsClientResource(actor, principal, eventFieldInt(fields, "client_id"), fields)
	}
	if h.authz.RequireTunnel(principal, tunnelID) == nil {
		return true
	}
	return h.allowsClientResource(actor, principal, eventFieldInt(fields, "client_id"), fields)
}

func (h *nodeEventHub) allowsHostResource(actor *webapi.Actor, principal webservice.Principal, hostID int, fields map[string]interface{}) bool {
	if hostID <= 0 {
		return h.allowsClientResource(actor, principal, eventFieldInt(fields, "client_id"), fields)
	}
	if h.authz.RequireHost(principal, hostID) == nil {
		return true
	}
	return h.allowsClientResource(actor, principal, eventFieldInt(fields, "client_id"), fields)
}

func allowsUserEvent(actor *webapi.Actor, userID int) bool {
	if actor == nil || userID <= 0 {
		return false
	}
	if actor.IsAdmin {
		return true
	}
	if serviceUserID := webapi.NodeActorServiceUserID(actor); serviceUserID > 0 && serviceUserID == userID {
		return true
	}
	if currentUserID := webapi.NodeActorUserID(actor); currentUserID > 0 && currentUserID == userID {
		return true
	}
	return false
}

func eventFieldInt(fields map[string]interface{}, key string) int {
	if len(fields) == 0 {
		return 0
	}
	raw, ok := fields[key]
	if !ok || raw == nil {
		return 0
	}
	switch value := raw.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(value))
		return parsed
	default:
		return 0
	}
}

func eventFieldIntList(fields map[string]interface{}, key string) []int {
	if len(fields) == 0 {
		return nil
	}
	raw, ok := fields[key]
	if !ok || raw == nil {
		return nil
	}
	values := make([]int, 0)
	appendValue := func(item interface{}) {
		switch value := item.(type) {
		case int:
			if value > 0 {
				values = append(values, value)
			}
		case int64:
			if value > 0 {
				values = append(values, int(value))
			}
		case float64:
			if value > 0 {
				values = append(values, int(value))
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && parsed > 0 {
				values = append(values, parsed)
			}
		}
	}
	switch typed := raw.(type) {
	case []int:
		for _, value := range typed {
			appendValue(value)
		}
	case []int64:
		for _, value := range typed {
			appendValue(value)
		}
	case []float64:
		for _, value := range typed {
			appendValue(value)
		}
	case []string:
		for _, value := range typed {
			appendValue(value)
		}
	case []interface{}:
		for _, value := range typed {
			appendValue(value)
		}
	default:
		appendValue(raw)
	}
	return values
}

func allowsClientEventFallback(actor *webapi.Actor, fields map[string]interface{}) bool {
	if actor == nil {
		return false
	}
	if actor.IsAdmin {
		return true
	}
	ownerUserID := eventFieldInt(fields, "owner_user_id")
	if serviceUserID := webapi.NodeActorServiceUserID(actor); serviceUserID > 0 && ownerUserID == serviceUserID {
		return true
	}
	if currentUserID := webapi.NodeActorUserID(actor); currentUserID > 0 {
		if ownerUserID == currentUserID {
			return true
		}
		for _, managerUserID := range eventFieldIntList(fields, "manager_user_ids") {
			if managerUserID == currentUserID {
				return true
			}
		}
	}
	return false
}

func cloneActor(actor *webapi.Actor) *webapi.Actor {
	if actor == nil {
		return nil
	}
	cloned := &webapi.Actor{
		Kind:        actor.Kind,
		SubjectID:   actor.SubjectID,
		Username:    actor.Username,
		IsAdmin:     actor.IsAdmin,
		ClientIDs:   append([]int(nil), actor.ClientIDs...),
		Roles:       append([]string(nil), actor.Roles...),
		Permissions: append([]string(nil), actor.Permissions...),
	}
	if len(actor.Attributes) > 0 {
		cloned.Attributes = make(map[string]string, len(actor.Attributes))
		for key, value := range actor.Attributes {
			cloned.Attributes[key] = value
		}
	}
	return cloned
}

func isNilRouterServiceValue(value interface{}) bool {
	if value == nil {
		return true
	}
	current := reflect.ValueOf(value)
	switch current.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return current.IsNil()
	default:
		return false
	}
}

// State centralizes router-side dependencies so transport code does not reach
// into global singletons directly.
type State struct {
	App               *webapi.App
	ConfigProvider    func() *servercfg.Snapshot
	ctx               context.Context
	cancel            context.CancelFunc
	servicesMu        sync.Mutex
	NodeEvents        *nodeEventHub
	NodeEventLog      *nodeEventLog
	NodeCallbackQueue *nodeCallbackQueueStore
	NodeWebhooks      *nodeWebhookStore
	RealtimeSessions  *nodeRealtimeSessionRegistry
	Idempotency       *nodeIdempotencyStore
	NodeBatchMaxItems int
	SessionActions    []webapi.ActionSpec
	ProtectedActions  []webapi.ActionSpec
}

func NewState(cfg *servercfg.Snapshot) *State {
	return NewStateWithApp(webapi.New(cfg))
}

func NewStateWithApp(app *webapi.App) *State {
	if app == nil {
		app = webapi.New(nil)
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	state := &State{
		App:            app,
		ConfigProvider: app.CurrentConfig,
		ctx:            baseCtx,
		cancel:         cancel,
	}
	cfg := state.CurrentConfig()
	hub := newNodeEventHub(state.Authorization())
	log := newNodeEventLog(cfg.Runtime.NodeEventLogSizeValue(), nodeEventLogPersistencePath())
	callbackConfigs := make([]nodeCallbackWorkerConfig, 0, len(cfg.Runtime.EnabledCallbackManagementPlatforms()))
	for _, platform := range cfg.Runtime.EnabledCallbackManagementPlatforms() {
		callbackConfigs = append(callbackConfigs, nodeCallbackWorkerConfig{
			PlatformID:       platform.PlatformID,
			Platform:         platform,
			CallbackQueueMax: platform.CallbackQueueMax,
		})
	}
	app.Hooks = compositeManagementHooks{
		primary: app.Hooks,
		hub:     hub,
		log:     log,
	}
	idempotency := newNodeIdempotencyStore(time.Duration(cfg.Runtime.NodeIdempotencyTTLSeconds())*time.Second, nodeIdempotencyPersistencePath())
	idempotency.BindRuntimeStatus(state.RuntimeStatus())
	stateBaseContext := func() context.Context {
		return state.BaseContext()
	}
	operationsEmit := func(ctx context.Context, event webapi.Event) {
		emitNodeManagementEvent(state, ctx, event)
	}
	switch current := state.NodeOperations().(type) {
	case *webservice.InMemoryNodeOperationStore:
		state.App.Services.NodeOperations = newNodeOperationRuntimeStore(
			nodeOperationsPersistencePath(),
			webservice.NodeOperationDefaultHistoryLimit,
			operationsEmit,
			stateBaseContext,
		)
	case *nodeOperationRuntimeStore:
		if current != nil {
			current.emit = operationsEmit
			current.baseCtx = stateBaseContext
		}
	}
	state.NodeEvents = hub
	state.NodeEventLog = log
	state.NodeCallbackQueue = newNodeCallbackQueueStore(
		nodeCallbackPersistencePath(),
		callbackConfigs,
		state.ManagementPlatformRuntimeStatus(),
		func(ctx context.Context, event webapi.Event) {
			emitNodeManagementEvent(state, ctx, event)
		},
		stateBaseContext,
	)
	state.RealtimeSessions = newNodeRealtimeSessionRegistry()
	state.Idempotency = idempotency
	state.NodeBatchMaxItems = cfg.Runtime.NodeBatchMaxItemsValue()
	state.SessionActions = webapi.SessionActionCatalog(app)
	state.ProtectedActions = webapi.ProtectedActionCatalog(app)
	state.NodeWebhooks = newNodeWebhookStore(
		nodeWebhookPersistencePath(),
		buildNodeWebhookResourceLookup(state),
		func(ctx context.Context, event webapi.Event) {
			emitNodeManagementEvent(state, ctx, event)
		},
		stateBaseContext,
	)
	if hooks, ok := app.Hooks.(compositeManagementHooks); ok {
		hooks.webhooks = state.NodeWebhooks
		app.Hooks = hooks
	}
	// Register the global management event hook so web/service can emit events.
	// Must be done after state is fully initialized to avoid nil pointer dereferences
	// if an event is emitted concurrently during startup.
	server.ManagementEventHook = func(eventName, resource, action string, fields map[string]interface{}) {
		emitNodeManagementEvent(state, state.BaseContext(), webapi.Event{
			Name:     eventName,
			Resource: resource,
			Action:   action,
			Fields:   fields,
		})
	}
	// Register bounded flush/close of asynchronous node state (event) writers
	// so shutdown drains them before force-closing sessions.
	server.RegisterEventWriterFlush(func(ctx context.Context) error {
		done := make(chan struct{})
		go func() {
			closeAllNodeRuntimeStateWriters()
			close(done)
		}()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	return state
}

func emitNodeManagementEvent(state *State, ctx context.Context, event webapi.Event) {
	if state == nil || state.App == nil || state.App.Hooks == nil {
		return
	}
	if ctx == nil {
		ctx = state.BaseContext()
	}
	_ = state.App.Hooks.OnManagementEvent(ctx, event)
}

func (s *State) CurrentConfig() *servercfg.Snapshot {
	if s != nil && s.App != nil {
		if s.ConfigProvider == nil {
			return s.App.CurrentConfig()
		}
	}
	if s == nil {
		return servercfg.Current()
	}
	return servercfg.ResolveProvider(s.ConfigProvider)
}

func (s *State) BaseURL() string {
	return s.CurrentConfig().Web.BaseURL
}

func (s *State) BaseContext() context.Context {
	if s != nil && s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *State) AdminUsername() string {
	return s.CurrentConfig().Web.Username
}

func (s *State) PermissionResolver() webservice.PermissionResolver {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.Permissions) {
		return s.App.Services.Permissions
	}
	return webservice.DefaultPermissionResolver()
}

func (s *State) Authorization() webservice.AuthorizationService {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.Authz) {
		return s.App.Services.Authz
	}
	return webservice.DefaultAuthorizationService{Resolver: s.PermissionResolver()}
}

func (s *State) System() webservice.SystemService {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.System) {
		return s.App.Services.System
	}
	return webservice.DefaultSystemService{}
}

func (s *State) LoginPolicy() webservice.LoginPolicyService {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.LoginPolicy) {
		return s.App.Services.LoginPolicy
	}
	return webservice.SharedLoginPolicy()
}

func (s *State) backend() webservice.Backend {
	if s != nil && s.App != nil {
		if !isNilRouterServiceValue(s.App.Services.Backend.Repository) || !isNilRouterServiceValue(s.App.Services.Backend.Runtime) {
			return s.App.Services.Backend
		}
	}
	return webservice.DefaultBackend()
}

func (s *State) NodeControl() webservice.NodeControlService {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.NodeControl) {
		return s.App.Services.NodeControl
	}
	return webservice.DefaultNodeControlService{
		System:  s.System(),
		Authz:   s.Authorization(),
		Backend: s.backend(),
	}
}

func (s *State) NodeStorage() webservice.NodeStorage {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.NodeStorage) {
		return s.App.Services.NodeStorage
	}
	return webservice.DefaultNodeStorage{}
}

func (s *State) ManagementPlatforms() webservice.ManagementPlatformStore {
	if s != nil && s.App != nil && !isNilRouterServiceValue(s.App.Services.ManagementPlatforms) {
		return s.App.Services.ManagementPlatforms
	}
	return webservice.DefaultManagementPlatformStore{Backend: s.backend()}
}

func (s *State) ManagementPlatformRuntimeStatus() webservice.ManagementPlatformRuntimeStatusStore {
	if s == nil || s.App == nil {
		return webservice.NewInMemoryManagementPlatformRuntimeStatusStore()
	}
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	if isNilRouterServiceValue(s.App.Services.ManagementPlatformRuntimeStatus) {
		s.App.Services.ManagementPlatformRuntimeStatus = webservice.NewInMemoryManagementPlatformRuntimeStatusStore()
	}
	return s.App.Services.ManagementPlatformRuntimeStatus
}

func (s *State) RuntimeStatus() webservice.NodeRuntimeStatusStore {
	if s == nil || s.App == nil {
		return webservice.NewInMemoryNodeRuntimeStatusStore()
	}
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	if isNilRouterServiceValue(s.App.Services.NodeRuntimeStatus) {
		s.App.Services.NodeRuntimeStatus = webservice.NewInMemoryNodeRuntimeStatusStore()
	}
	return s.App.Services.NodeRuntimeStatus
}

func (s *State) NodeOperations() webservice.NodeOperationStore {
	if s == nil || s.App == nil {
		return webservice.NewInMemoryNodeOperationStore(webservice.NodeOperationDefaultHistoryLimit)
	}
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	if isNilRouterServiceValue(s.App.Services.NodeOperations) {
		s.App.Services.NodeOperations = webservice.NewInMemoryNodeOperationStore(webservice.NodeOperationDefaultHistoryLimit)
	}
	return s.App.Services.NodeOperations
}

func (s *State) RuntimeIdentity() webservice.NodeRuntimeIdentity {
	if s == nil || s.App == nil {
		return webservice.NewNodeRuntimeIdentity()
	}
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()
	if isNilRouterServiceValue(s.App.Services.NodeRuntimeIdentity) {
		s.App.Services.NodeRuntimeIdentity = webservice.NewNodeRuntimeIdentity()
	}
	return s.App.Services.NodeRuntimeIdentity
}

func (s *State) ResetProtocolState() {
	if s == nil {
		return
	}
	if s.NodeEvents != nil {
		s.NodeEvents.Reset()
	}
	if s.NodeEventLog != nil {
		s.NodeEventLog.Reset()
	}
	if s.NodeCallbackQueue != nil {
		s.NodeCallbackQueue.Reset()
	}
	if s.NodeWebhooks != nil {
		s.NodeWebhooks.Reset()
	}
	if s.Idempotency != nil {
		s.Idempotency.Reset()
	}
	if resetter, ok := s.NodeOperations().(interface{ Reset() }); ok {
		resetter.Reset()
	}
	if status := s.RuntimeStatus(); status != nil {
		status.ResetOperations()
	}
	if runtimeStatus := s.ManagementPlatformRuntimeStatus(); runtimeStatus != nil {
		runtimeStatus.Reset()
	}
}

func (s *State) InvalidateRealtimeSessions(reason, configEpoch string) {
	if s == nil || s.RealtimeSessions == nil {
		return
	}
	s.RealtimeSessions.InvalidateAll(reason, configEpoch)
}

func (s *State) Close() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.NodeCallbackQueue != nil {
		s.NodeCallbackQueue.Close()
	}
	if s.NodeWebhooks != nil {
		s.NodeWebhooks.Close()
	}
	if s.NodeEventLog != nil {
		s.NodeEventLog.Close()
	}
	if s.RealtimeSessions != nil {
		s.RealtimeSessions.InvalidateAll("state_close", "")
	}
	if s.Idempotency != nil {
		s.Idempotency.Close()
	}
	if closer, ok := s.NodeOperations().(interface{ Close() }); ok {
		closer.Close()
	}
}

func newNodeRuntimeStateWriter(path string) *nodeRuntimeStateWriter {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !nodeRuntimeStateAsyncEnabled() {
		return nil
	}
	writer := &nodeRuntimeStateWriter{
		path:   path,
		delay:  nodeRuntimePersistDelay,
		stopCh: make(chan struct{}),
	}
	registerNodeRuntimeStateWriter(writer)
	return writer
}

func newNodeRuntimeAppendWriter(path string) *nodeRuntimeAppendWriter {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !nodeRuntimeStateAsyncEnabled() {
		return nil
	}
	writer := &nodeRuntimeAppendWriter{
		path:   path,
		delay:  nodeRuntimePersistDelay,
		stopCh: make(chan struct{}),
	}
	registerNodeRuntimeAppendWriter(writer)
	return writer
}

func nodeEventLogPersistencePath() string {
	return nodeRuntimeStatePath(nodeEventLogStateFile)
}

func nodeIdempotencyPersistencePath() string {
	return nodeRuntimeStatePath(nodeIdempotencyStateFile)
}

func nodeEventLogJournalPath(persistPath string) string {
	persistPath = strings.TrimSpace(persistPath)
	if persistPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(persistPath), nodeEventLogJournalFile)
}

func nodeCallbackPersistencePath() string {
	return nodeRuntimeStatePath(nodeCallbackStateFile)
}

func nodeWebhookPersistencePath() string {
	return nodeRuntimeStatePath(nodeWebhookStateFile)
}

func nodeOperationsPersistencePath() string {
	return nodeRuntimeStatePath(nodeOperationsStateFile)
}

func nodeRuntimeStatePath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	root := nodeRuntimeStateRoot()
	if strings.TrimSpace(root) == "" {
		return ""
	}
	return filepath.Join(root, "conf", name)
}

func nodeRuntimeStateRoot() string {
	if configPath := strings.TrimSpace(servercfg.Path()); configPath != "" {
		if root := strings.TrimSpace(filepath.Dir(configPath)); root != "" {
			return root
		}
	}
	return common.GetRunPath()
}

func nodeRuntimeStateAsyncEnabled() bool {
	base := strings.ToLower(filepath.Base(os.Args[0]))
	return !strings.Contains(base, ".test")
}

func readNodeRuntimeState(path string, dest interface{}) error {
	path = strings.TrimSpace(path)
	if path == "" || dest == nil {
		return nil
	}
	flushNodeRuntimeState(path)
	if !common.FileExists(path) {
		return os.ErrNotExist
	}
	data, err := common.ReadAllFromFile(path)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, dest)
}

func isIgnorableNodeRuntimeStateError(err error) bool {
	return err == nil || errors.Is(err, os.ErrNotExist)
}

func nodeRuntimeStateVersionSupported(version int) bool {
	return version == 0 || version == nodeRuntimeStateVersion
}

func writeNodeRuntimeState(path string, value interface{}) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		logs.Warn("marshal node runtime state %s error: %v", path, err)
		return
	}
	writeNodeRuntimeStateBytes(path, data)
}

func writeNodeRuntimeStateBytes(path string, data []byte) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if !common.FileExists(dir) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			logs.Warn("create node runtime state dir %s error: %v", dir, err)
			return
		}
	}
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		logs.Warn("create node runtime temp state %s error: %v", tmpPath, err)
		return
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		logs.Warn("write node runtime temp state %s error: %v", tmpPath, err)
		return
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		logs.Warn("sync node runtime temp state %s error: %v", tmpPath, err)
		return
	}
	if err = file.Close(); err != nil {
		logs.Warn("close node runtime temp state %s error: %v", tmpPath, err)
		return
	}
	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(path)
		if err = os.Rename(tmpPath, path); err != nil {
			logs.Warn("replace node runtime state %s error: %v", path, err)
			return
		}
	}
}

func appendNodeRuntimeStateBytes(path string, data []byte) {
	path = strings.TrimSpace(path)
	if path == "" || len(data) == 0 {
		return
	}
	dir := filepath.Dir(path)
	if !common.FileExists(dir) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			logs.Warn("create node runtime state dir %s error: %v", dir, err)
			return
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		logs.Warn("open node runtime append state %s error: %v", path, err)
		return
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		logs.Warn("append node runtime state %s error: %v", path, err)
		return
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		logs.Warn("sync node runtime append state %s error: %v", path, err)
		return
	}
	if err = file.Close(); err != nil {
		logs.Warn("close node runtime append state %s error: %v", path, err)
	}
}

func (w *nodeRuntimeStateWriter) Store(value interface{}) {
	if w == nil {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		logs.Warn("marshal node runtime state %s error: %v", w.path, err)
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		writeNodeRuntimeStateBytes(w.path, data)
		return
	}
	w.pending = append(w.pending[:0], data...)
	if !w.scheduled {
		w.scheduled = true
		w.wg.Add(1)
		go w.run()
	}
	w.mu.Unlock()
}

func (w *nodeRuntimeStateWriter) run() {
	defer w.wg.Done()
	for {
		if !waitNodeRuntimePersistDelay(w.delay, w.stopCh) {
			w.flushPending()
			w.mu.Lock()
			w.scheduled = false
			w.mu.Unlock()
			return
		}
		w.flushPending()
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.scheduled = false
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()
	}
}

func (w *nodeRuntimeStateWriter) flushPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	data := w.pending
	w.pending = nil
	w.mu.Unlock()
	if len(data) == 0 {
		return
	}
	writeNodeRuntimeStateBytes(w.path, data)
}

func (w *nodeRuntimeStateWriter) Flush() {
	if w == nil {
		return
	}
	w.flushPending()
}

func (w *nodeRuntimeStateWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.stopOnce.Do(func() {
		if w.stopCh != nil {
			close(w.stopCh)
		}
	})
	w.flushPending()
	w.wg.Wait()
	w.flushPending()
	unregisterNodeRuntimeStateWriter(w)
}

func (w *nodeRuntimeAppendWriter) Store(data []byte) {
	if w == nil || len(data) == 0 {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		appendNodeRuntimeStateBytes(w.path, data)
		return
	}
	w.pending = append(w.pending, data...)
	if !w.scheduled {
		w.scheduled = true
		w.wg.Add(1)
		go w.run()
	}
	w.mu.Unlock()
}

func (w *nodeRuntimeAppendWriter) run() {
	defer w.wg.Done()
	for {
		if !waitNodeRuntimePersistDelay(w.delay, w.stopCh) {
			w.flushPending()
			w.mu.Lock()
			w.scheduled = false
			w.mu.Unlock()
			return
		}
		w.flushPending()
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.scheduled = false
			w.mu.Unlock()
			return
		}
		w.mu.Unlock()
	}
}

func (w *nodeRuntimeAppendWriter) flushPending() {
	if w == nil {
		return
	}
	w.mu.Lock()
	data := w.pending
	w.pending = nil
	w.mu.Unlock()
	if len(data) == 0 {
		return
	}
	appendNodeRuntimeStateBytes(w.path, data)
}

func (w *nodeRuntimeAppendWriter) Flush() {
	if w == nil {
		return
	}
	w.flushPending()
}

func (w *nodeRuntimeAppendWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.stopOnce.Do(func() {
		if w.stopCh != nil {
			close(w.stopCh)
		}
	})
	w.flushPending()
	w.wg.Wait()
	w.flushPending()
	unregisterNodeRuntimeAppendWriter(w)
}

func waitNodeRuntimePersistDelay(delay time.Duration, stop <-chan struct{}) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	}
}

func registerNodeRuntimeStateWriter(writer *nodeRuntimeStateWriter) {
	if writer == nil || strings.TrimSpace(writer.path) == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	defer nodeRuntimeStateWritersMu.Unlock()
	path := strings.TrimSpace(writer.path)
	if nodeRuntimeStateWriters[path] == nil {
		nodeRuntimeStateWriters[path] = make(map[*nodeRuntimeStateWriter]struct{})
	}
	nodeRuntimeStateWriters[path][writer] = struct{}{}
}

func registerNodeRuntimeAppendWriter(writer *nodeRuntimeAppendWriter) {
	if writer == nil || strings.TrimSpace(writer.path) == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	defer nodeRuntimeStateWritersMu.Unlock()
	path := strings.TrimSpace(writer.path)
	if nodeRuntimeAppendWriters[path] == nil {
		nodeRuntimeAppendWriters[path] = make(map[*nodeRuntimeAppendWriter]struct{})
	}
	nodeRuntimeAppendWriters[path][writer] = struct{}{}
}

func unregisterNodeRuntimeStateWriter(writer *nodeRuntimeStateWriter) {
	if writer == nil || strings.TrimSpace(writer.path) == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	defer nodeRuntimeStateWritersMu.Unlock()
	path := strings.TrimSpace(writer.path)
	writers := nodeRuntimeStateWriters[path]
	delete(writers, writer)
	if len(writers) == 0 {
		delete(nodeRuntimeStateWriters, path)
	}
}

func unregisterNodeRuntimeAppendWriter(writer *nodeRuntimeAppendWriter) {
	if writer == nil || strings.TrimSpace(writer.path) == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	defer nodeRuntimeStateWritersMu.Unlock()
	path := strings.TrimSpace(writer.path)
	writers := nodeRuntimeAppendWriters[path]
	delete(writers, writer)
	if len(writers) == 0 {
		delete(nodeRuntimeAppendWriters, path)
	}
}

func flushNodeRuntimeState(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	writers := nodeRuntimeStateWriters[path]
	active := make([]*nodeRuntimeStateWriter, 0, len(writers))
	for writer := range writers {
		active = append(active, writer)
	}
	nodeRuntimeStateWritersMu.Unlock()
	for _, writer := range active {
		writer.Flush()
	}
}

func flushNodeRuntimeAppendState(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	nodeRuntimeStateWritersMu.Lock()
	writers := nodeRuntimeAppendWriters[path]
	active := make([]*nodeRuntimeAppendWriter, 0, len(writers))
	for writer := range writers {
		active = append(active, writer)
	}
	nodeRuntimeStateWritersMu.Unlock()
	for _, writer := range active {
		writer.Flush()
	}
}

func closeAllNodeRuntimeStateWriters() {
	nodeRuntimeStateWritersMu.Lock()
	active := make([]*nodeRuntimeStateWriter, 0)
	for _, writers := range nodeRuntimeStateWriters {
		for writer := range writers {
			active = append(active, writer)
		}
	}
	appendActive := make([]*nodeRuntimeAppendWriter, 0)
	for _, writers := range nodeRuntimeAppendWriters {
		for writer := range writers {
			appendActive = append(appendActive, writer)
		}
	}
	nodeRuntimeStateWritersMu.Unlock()
	for _, writer := range active {
		writer.Close()
	}
	for _, writer := range appendActive {
		writer.Close()
	}
}
