package server

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/server/proxy"
	"github.com/djylb/nps/server/proxy/httpproxy"
	"github.com/djylb/nps/server/tool"
)

var (
	Bridge         *bridge.Bridge
	RunList        sync.Map //map[int]interface{}
	HttpProxyCache = index.NewAnyIntIndex()

	// ManagementEventHook is called when tunnel/client/host resources are mutated.
	// It is set by web/routers/state.go during node initialization.
	// The hook receives: eventName, resource, action, fields.
	ManagementEventHook func(eventName, resource, action string, fields map[string]interface{})
)

func ClearProxyCache() {
	if HttpProxyCache == nil {
		return
	}
	HttpProxyCache.Clear()
}

func RemoveHostCache(id int) {
	runtimeState.RemoveHostCache(id)
}

const pingTimeout = 15 * time.Second

const registerCleanupInterval = 10 * time.Minute

type flowSessionTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realFlowSessionTicker struct {
	*time.Ticker
}

func (t realFlowSessionTicker) Chan() <-chan time.Time {
	return t.C
}

type lifecycleMonitorRuntime struct {
	startOnce sync.Once
	newTicker func(time.Duration) flowSessionTicker
	monitor   func(int64)
	now       func() int64
}

var runtimeLifecycleMonitor = newLifecycleMonitorRuntime()

func newLifecycleMonitorRuntime() *lifecycleMonitorRuntime {
	return &lifecycleMonitorRuntime{
		newTicker: func(d time.Duration) flowSessionTicker {
			return realFlowSessionTicker{Ticker: time.NewTicker(d)}
		},
		monitor: monitorClientLifecycle,
		now: func() int64 {
			return time.Now().Unix()
		},
	}
}

func init() {
	RunList = sync.Map{}
	tool.SetLookup(runtimeTasks.LookupDialer)
}

func StartNewServer(cnf *file.Tunnel, bridgeDisconnect int) {
	if runtimeEngine == nil {
		return
	}
	runtimeEngine.startup.Start(cnf != nil && cnf.Mode == "webServer", bridgeDisconnect)
}

func hasSharedRuntimeAccessVKey(cfg *servercfg.Snapshot) bool {
	if cfg == nil {
		return false
	}
	publicVKey := strings.TrimSpace(cfg.Runtime.PublicVKey)
	visitorVKey := strings.TrimSpace(cfg.Runtime.VisitorVKey)
	return publicVKey != "" && publicVKey == visitorVKey
}

func syncRuntimeSpecialClients(cfg *servercfg.Snapshot) {
	if cfg == nil {
		return
	}
	runtimeSpecialClients.EnsureLocalProxy(cfg.AllowLocalProxyEnabled())
	runtimeSpecialClients.SyncVKeys(cfg)
}

func trafficLimitReached(limit, total int64) bool {
	return limit > 0 && total >= limit
}

func expirationReached(now, expireAt int64) bool {
	return expireAt > 0 && now >= expireAt
}

// InitFromDb init task from db
func InitFromDb() {
	cfg := servercfg.Current()
	if hasSharedRuntimeAccessVKey(cfg) {
		logs.Info("public_vkey matches visitor_vkey; shared access-only key will allow config/register plus secret/p2p visitor flows, but still no control-plane connection")
	}
	syncRuntimeSpecialClients(cfg)
	StartManagedTasksFromDB()
}

func ApplyRuntimeConfig(cfg *servercfg.Snapshot) {
	cfg = servercfg.Resolve(cfg)
	updateFlowSession(cfg.FlowStoreIntervalDuration())
	runtimeState.ApplyBridgeConfig(common.GetBoolByStr(cfg.Runtime.IPLimit), cfg.Runtime.DisconnectTimeoutSeconds())
	syncRuntimeSpecialClients(cfg)
}

func StartManagedTasksFromDB() {
	persistedManagedTasks.StartPersisted()
}

func StopManagedTasksPreserveStatus() {
	persistedManagedTasks.StopPreserveStatus()
}

func DisconnectOrphanClients() {
	runtimeOrphanClients.DisconnectOrphans()
}

func RefreshClientDataByID(clientID int) {
	runtimeFlow.RefreshClient(clientID)
}

func RefreshClientDataSet(clientIDs map[int]struct{}) {
	runtimeFlow.RefreshClientSet(clientIDs)
}

func TaskRunning(id int) bool {
	return runtimeTasks.Contains(id)
}

func DelClientConnect(clientID int) {
	runtimeState.DeleteBridgeClient(clientID)
}

func StartLifecycleMonitor() {
	runtimeLifecycleMonitor.Start()
}

func (m *lifecycleMonitorRuntime) Start() {
	if m == nil {
		return
	}
	m.startOnce.Do(func() {
		tickerFactory := m.newTicker
		if tickerFactory == nil {
			return
		}
		ticker := tickerFactory(10 * time.Second)
		if ticker == nil {
			return
		}
		go m.run(ticker)
	})
}

func (m *lifecycleMonitorRuntime) run(ticker flowSessionTicker) {
	if ticker == nil {
		return
	}
	defer ticker.Stop()
	for range ticker.Chan() {
		monitor := m.monitor
		if monitor == nil {
			continue
		}
		now := int64(0)
		if m.now != nil {
			now = m.now()
		}
		monitor(now)
	}
}

func monitorClientLifecycle(now int64) {
	if file.GlobalStore == nil {
		return
	}
	for _, client := range file.GlobalStore.GetAllClients() {
		if client == nil || client.Id <= 0 {
			continue
		}
		if shouldDisconnectClient(now, client) {
			runtimeState.DeleteBridgeClient(client.Id)
		}
	}
}

func shouldDisconnectClient(now int64, client *file.Client) bool {
	if client == nil {
		return false
	}
	if !client.Status {
		return true
	}
	if client.OwnerID() > 0 && file.GlobalStore != nil {
		return shouldDisconnectUserOwnedClient(now, client)
	}
	return shouldDisconnectStandaloneClient(now, client)
}

func shouldDisconnectUserOwnedClient(now int64, client *file.Client) bool {
	ownerID := 0
	if client != nil {
		ownerID = client.OwnerID()
	}
	user, err := file.GlobalStore.GetUser(ownerID)
	if err != nil || user == nil {
		return true
	}
	if user.Status == 0 {
		return true
	}
	if expirationReached(now, user.ExpireAt) {
		return true
	}
	_, _, total := user.TotalTrafficTotals()
	return trafficLimitReached(user.FlowLimit, total)
}

func shouldDisconnectStandaloneClient(now int64, client *file.Client) bool {
	if expirationReached(now, client.EffectiveExpireAt()) {
		return true
	}
	_, _, total := client.TotalTrafficTotals()
	return trafficLimitReached(client.EffectiveFlowLimitBytes(), total)
}

var errRuntimeBridgeUnavailable = errors.New("runtime bridge unavailable")

type ClientConnectionInfo struct {
	UUID                   string
	Version                string
	BaseVer                int
	RemoteAddr             string
	LocalAddr              string
	HasSignal              bool
	HasTunnel              bool
	Online                 bool
	ConnectedAt            int64
	NowConn                int32
	BridgeInBytes          int64
	BridgeOutBytes         int64
	BridgeTotalBytes       int64
	ServiceInBytes         int64
	ServiceOutBytes        int64
	ServiceTotalBytes      int64
	TotalInBytes           int64
	TotalOutBytes          int64
	TotalBytes             int64
	BridgeNowRateInBps     int64
	BridgeNowRateOutBps    int64
	BridgeNowRateTotalBps  int64
	ServiceNowRateInBps    int64
	ServiceNowRateOutBps   int64
	ServiceNowRateTotalBps int64
	TotalNowRateInBps      int64
	TotalNowRateOutBps     int64
	TotalNowRateTotalBps   int64
}

type bridgeEventSource struct {
	openHost <-chan *file.Host
	openTask <-chan *file.Tunnel
	secret   <-chan *conn.Secret
}

func newClientConnectionInfo(snapshot bridge.NodeRuntimeSnapshot) ClientConnectionInfo {
	return ClientConnectionInfo{
		UUID:                   snapshot.UUID,
		Version:                snapshot.Version,
		BaseVer:                snapshot.BaseVer,
		RemoteAddr:             snapshot.RemoteAddr,
		LocalAddr:              snapshot.LocalAddr,
		HasSignal:              snapshot.HasSignal,
		HasTunnel:              snapshot.HasTunnel,
		Online:                 snapshot.Online,
		ConnectedAt:            snapshot.ConnectedAt,
		NowConn:                snapshot.NowConn,
		BridgeInBytes:          snapshot.BridgeInBytes,
		BridgeOutBytes:         snapshot.BridgeOutBytes,
		BridgeTotalBytes:       snapshot.BridgeTotalBytes,
		ServiceInBytes:         snapshot.ServiceInBytes,
		ServiceOutBytes:        snapshot.ServiceOutBytes,
		ServiceTotalBytes:      snapshot.ServiceTotalBytes,
		TotalInBytes:           snapshot.TotalInBytes,
		TotalOutBytes:          snapshot.TotalOutBytes,
		TotalBytes:             snapshot.TotalBytes,
		BridgeNowRateInBps:     snapshot.BridgeNowRateInBps,
		BridgeNowRateOutBps:    snapshot.BridgeNowRateOutBps,
		BridgeNowRateTotalBps:  snapshot.BridgeNowRateTotalBps,
		ServiceNowRateInBps:    snapshot.ServiceNowRateInBps,
		ServiceNowRateOutBps:   snapshot.ServiceNowRateOutBps,
		ServiceNowRateTotalBps: snapshot.ServiceNowRateTotalBps,
		TotalNowRateInBps:      snapshot.TotalNowRateInBps,
		TotalNowRateOutBps:     snapshot.TotalNowRateOutBps,
		TotalNowRateTotalBps:   snapshot.TotalNowRateTotalBps,
	}
}

type serverRuntimeState struct {
	currentBridge  func() *bridge.Bridge
	assignBridge   func(*bridge.Bridge)
	taskEntries    func() *sync.Map
	httpProxyCache func() *index.AnyIntIndex
	sendLinkInfo   func(int, *conn.Link, *file.Tunnel) (net.Conn, error)
}

type idleConnectionCloser interface {
	CloseIdleConnections()
}

var runtimeState = serverRuntimeState{
	currentBridge: func() *bridge.Bridge {
		return Bridge
	},
	assignBridge: func(runtimeBridge *bridge.Bridge) {
		Bridge = runtimeBridge
	},
	taskEntries: func() *sync.Map {
		return &RunList
	},
	httpProxyCache: func() *index.AnyIntIndex {
		return HttpProxyCache
	},
}

func (s serverRuntimeState) Bridge() *bridge.Bridge {
	if s.currentBridge == nil {
		return nil
	}
	return s.currentBridge()
}

func (s serverRuntimeState) AssignBridge(runtimeBridge *bridge.Bridge) {
	if s.assignBridge == nil {
		return
	}
	s.assignBridge(runtimeBridge)
}

func (s serverRuntimeState) RemoveHostCache(id int) {
	if s.httpProxyCache == nil {
		return
	}
	cache := s.httpProxyCache()
	if cache == nil {
		return
	}
	if cached, ok := cache.Get(id); ok {
		if closer, ok := cached.(idleConnectionCloser); ok {
			closer.CloseIdleConnections()
		}
	}
	cache.Remove(id)
}

func (s serverRuntimeState) DeleteBridgeClient(id int) {
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil {
		return
	}
	runtimeBridge.DelClient(id)
}

func (s serverRuntimeState) LoadBridgeClient(id int) (*bridge.Client, bool) {
	if id <= 0 {
		return nil, false
	}
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil || runtimeBridge.Client == nil {
		return nil, false
	}
	return loadOnlineBridgeClientEntry(runtimeBridge.Client, id)
}

func (s serverRuntimeState) HasBridgeClient(id int) bool {
	_, ok := s.LoadBridgeClient(id)
	return ok
}

func (s serverRuntimeState) ApplyBridgeConfig(ipVerify bool, disconnectTimeout int) {
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil {
		return
	}
	runtimeBridge.SetIPVerify(ipVerify)
	runtimeBridge.SetDisconnectTimeout(disconnectTimeout)
}

func (s serverRuntimeState) CleanupExpiredRegistrations(now time.Time) int {
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil {
		return 0
	}
	return runtimeBridge.CleanupExpiredRegistrations(now)
}

func (s serverRuntimeState) OpenBridgeLink(clientID int, link *conn.Link, tunnel *file.Tunnel) (net.Conn, error) {
	if s.sendLinkInfo != nil {
		return s.sendLinkInfo(clientID, link, tunnel)
	}
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil {
		return nil, errRuntimeBridgeUnavailable
	}
	return runtimeBridge.SendLinkInfo(clientID, link, tunnel)
}

func (s serverRuntimeState) BridgeEvents() bridgeEventSource {
	runtimeBridge := s.Bridge()
	if runtimeBridge == nil {
		return bridgeEventSource{}
	}
	return bridgeEventSource{
		openHost: runtimeBridge.OpenHost,
		openTask: runtimeBridge.OpenTask,
		secret:   runtimeBridge.SecretChan,
	}
}

func GetClientConnections(clientID int) []ClientConnectionInfo {
	client, ok := runtimeState.LoadBridgeClient(clientID)
	if !ok {
		return nil
	}
	snapshots := client.OnlineNodeSnapshots()
	if len(snapshots) == 0 {
		return nil
	}
	items := make([]ClientConnectionInfo, 0, len(snapshots))
	for _, snapshot := range snapshots {
		items = append(items, newClientConnectionInfo(snapshot))
	}
	return items
}

func GetClientConnectionCount(clientID int) int {
	client, ok := runtimeState.LoadBridgeClient(clientID)
	if !ok || client == nil {
		return 0
	}
	return client.OnlineNodeCount()
}

func loadOnlineBridgeClientEntry(entries *sync.Map, id int) (*bridge.Client, bool) {
	if entries == nil {
		return nil, false
	}
	value, ok := entries.Load(id)
	if !ok {
		return nil, false
	}
	client, ok := value.(*bridge.Client)
	if !ok || client == nil {
		entries.CompareAndDelete(id, value)
		return nil, false
	}
	if !client.HasOnlineNode() {
		return nil, false
	}
	return client, true
}

var errTaskNotRunning = errors.New("task is not running")
var errNoServeTarget = errors.New("no http serve target")
var errTaskIsNil = errors.New("task is nil")

type storedTaskStopState struct {
	taskID         int
	previousStatus bool
	task           *file.Tunnel
}

type taskModeDependencies struct {
	Bridge     *bridge.Bridge
	HTTP       connection.HTTPRuntimeConfig
	ProxyCache *index.AnyIntIndex
}

type taskModeFactory func(taskModeDependencies, *file.Tunnel) proxy.Service

type taskModeRegistry struct {
	mu        sync.RWMutex
	factories map[string]taskModeFactory
}

func newTaskModeRegistry() *taskModeRegistry {
	return &taskModeRegistry{
		factories: make(map[string]taskModeFactory),
	}
}

func (r *taskModeRegistry) Register(mode string, factory taskModeFactory) {
	if r == nil || mode == "" || factory == nil {
		return
	}
	r.mu.Lock()
	r.factories[mode] = factory
	r.mu.Unlock()
}

func (r *taskModeRegistry) New(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
	if r == nil || tunnel == nil {
		return nil
	}
	r.mu.RLock()
	factory, ok := r.factories[tunnel.Mode]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	return factory(deps, tunnel)
}

var defaultTaskModeRegistry = buildDefaultTaskModeRegistry()

func buildDefaultTaskModeRegistry() *taskModeRegistry {
	registry := newTaskModeRegistry()
	registerDefaultTaskModes(registry)
	return registry
}

func NewMode(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
	return defaultTaskModeRegistry.New(deps, tunnel)
}

func registerDefaultTaskModes(registry *taskModeRegistry) {
	if registry == nil {
		return
	}
	registry.Register("tcp", newTCPModeFactory())
	registry.Register("file", newTCPModeFactory())
	registry.Register("mixProxy", newMixModeFactory())
	registry.Register("socks5", newMixModeFactory())
	registry.Register("httpProxy", newMixModeFactory())
	registry.Register("tcpTrans", newTransparentTCPModeFactory())
	registry.Register("udp", newUDPModeFactory())
	registry.Register("webServer", newWebServerModeFactory())
	registry.Register("httpHostServer", newHTTPHostModeFactory())
}

func newTCPModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return proxy.NewTunnelModeServer(proxy.ProcessTunnel, deps.Bridge, tunnel)
	}
}

func newMixModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return proxy.NewTunnelModeServer(proxy.ProcessMix, deps.Bridge, tunnel)
	}
}

func newTransparentTCPModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return proxy.NewTunnelModeServer(proxy.HandleTrans, deps.Bridge, tunnel)
	}
}

func newUDPModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return proxy.NewUdpModeServer(deps.Bridge, tunnel)
	}
}

func newWebServerModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return NewWebServer(deps.Bridge)
	}
}

func newHTTPHostModeFactory() taskModeFactory {
	return func(deps taskModeDependencies, tunnel *file.Tunnel) proxy.Service {
		return httpproxy.NewHttpProxy(
			deps.Bridge,
			tunnel,
			deps.HTTP.Port,
			deps.HTTP.HTTPSPort,
			deps.HTTP.HTTP3Port,
			deps.ProxyCache,
		)
	}
}

type WebServer struct {
	proxy.BaseServer
	tcpListener     net.Listener
	virtualListener *conn.VirtualListener
	webRuntimeRoot  func() connection.WebRuntimeConfig
	configRoot      func() *servercfg.Snapshot
	closeOnce       sync.Once
	closeErr        error
}

type httpServeTarget struct {
	listener net.Listener
	serve    func(net.Listener) error
}

var currentWebHandler atomic.Value
var currentWebRuntimeRoot = connection.CurrentWebRuntime
var currentWebConfigRoot = servercfg.Current

type dynamicWebHandler struct{}

func SetWebHandler(handler http.Handler) {
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	currentWebHandler.Store(handler)
}

func (dynamicWebHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler, _ := currentWebHandler.Load().(http.Handler)
	if handler == nil {
		http.NotFoundHandler().ServeHTTP(w, r)
		return
	}
	handler.ServeHTTP(w, r)
}

func (s *WebServer) currentWebRuntime() connection.WebRuntimeConfig {
	if s != nil && s.webRuntimeRoot != nil {
		return s.webRuntimeRoot()
	}
	return connection.CurrentWebRuntime()
}

func (s *WebServer) currentConfig() *servercfg.Snapshot {
	if s != nil && s.configRoot != nil {
		return servercfg.ResolveProvider(s.configRoot)
	}
	return servercfg.Current()
}

func (s *WebServer) Start() error {
	webCfg := s.currentWebRuntime()
	ip := webCfg.IP
	p := webCfg.Port
	handler := dynamicWebHandler{}

	lAddr := &net.TCPAddr{IP: net.ParseIP(ip), Port: p}
	s.replaceVirtualListener(conn.NewVirtualListener(lAddr))
	targets := []httpServeTarget{{
		listener: s.virtualListener,
		serve: func(l net.Listener) error {
			return http.Serve(l, handler)
		},
	}}

	if p > 0 {
		if l, err := connection.GetWebManagerListener(); err == nil {
			s.tcpListener = l
			cfg := s.currentConfig()
			if cfg.Web.OpenSSL {
				targets = append(targets, httpServeTarget{
					listener: l,
					serve: func(l net.Listener) error {
						return http.ServeTLS(l, handler, cfg.Web.CertFile, cfg.Web.KeyFile)
					},
				})
			} else {
				targets = append(targets, httpServeTarget{
					listener: l,
					serve: func(l net.Listener) error {
						return http.Serve(l, handler)
					},
				})
			}
		} else {
			logs.Error("%v", err)
		}
	} else {
		logs.Info("web_port=0: only virtual listener is active (plain HTTP)")
	}

	return serveHTTPListeners(targets...)
}

func (s *WebServer) Close() error {
	s.closeOnce.Do(func() {
		if s.tcpListener != nil {
			s.closeErr = s.tcpListener.Close()
		}
		s.closeVirtualListener()
	})
	return s.closeErr
}

func NewWebServer(bridge *bridge.Bridge) *WebServer {
	return NewWebServerWithRoots(bridge, currentWebRuntimeRoot, currentWebConfigRoot)
}

func NewWebServerWithRoots(bridge *bridge.Bridge, webRuntimeRoot func() connection.WebRuntimeConfig, configRoot func() *servercfg.Snapshot) *WebServer {
	s := new(WebServer)
	s.BaseServer = *proxy.NewBaseServer(bridge, nil)
	s.webRuntimeRoot = webRuntimeRoot
	s.configRoot = configRoot
	return s
}

func (s *WebServer) replaceVirtualListener(listener *conn.VirtualListener) {
	if tool.WebServerListener != nil && tool.WebServerListener != listener {
		_ = tool.WebServerListener.Close()
	}
	tool.WebServerListener = listener
	s.virtualListener = listener
}

func (s *WebServer) closeVirtualListener() {
	if s == nil || s.virtualListener == nil {
		return
	}
	_ = s.virtualListener.Close()
	if tool.WebServerListener == s.virtualListener {
		tool.WebServerListener = nil
	}
	s.virtualListener = nil
}

func serveHTTPListeners(targets ...httpServeTarget) error {
	validTargets := make([]httpServeTarget, 0, len(targets))
	for _, target := range targets {
		if target.listener == nil || target.serve == nil {
			continue
		}
		validTargets = append(validTargets, target)
	}
	if len(validTargets) == 0 {
		return errNoServeTarget
	}

	errCh := make(chan error, 1)
	var once sync.Once

	closeAll := func() {
		for _, target := range validTargets {
			if target.listener != nil {
				_ = target.listener.Close()
			}
		}
	}

	for _, target := range validTargets {
		go func(target httpServeTarget) {
			err := target.serve(target.listener)
			once.Do(func() {
				closeAll()
				errCh <- err
			})
		}(target)
	}

	return <-errCh
}

type taskModeRuntime struct {
	currentBridge func() *bridge.Bridge
	currentHTTP   func() connection.HTTPRuntimeConfig
	proxyCache    func() *index.AnyIntIndex
	newMode       func(taskModeDependencies, *file.Tunnel) proxy.Service
}

var runtimeTaskModes = taskModeRuntime{
	currentBridge: runtimeState.Bridge,
	currentHTTP:   connection.CurrentHTTPRuntime,
	proxyCache: func() *index.AnyIntIndex {
		if runtimeState.httpProxyCache == nil {
			return nil
		}
		return runtimeState.httpProxyCache()
	},
	newMode: NewMode,
}

func (r taskModeRuntime) Dependencies() taskModeDependencies {
	deps := taskModeDependencies{}
	if r.currentBridge != nil {
		deps.Bridge = r.currentBridge()
	}
	if r.currentHTTP != nil {
		deps.HTTP = r.currentHTTP()
	}
	if r.proxyCache != nil {
		deps.ProxyCache = r.proxyCache()
	}
	return deps
}

func (r taskModeRuntime) New(tunnel *file.Tunnel) proxy.Service {
	if r.newMode == nil {
		return nil
	}
	return r.newMode(r.Dependencies(), tunnel)
}

type runtimeRegistry struct {
	entries func() *sync.Map
}

var runtimeTasks = runtimeRegistry{
	entries: func() *sync.Map {
		if runtimeState.taskEntries == nil {
			return nil
		}
		return runtimeState.taskEntries()
	},
}

type taskStartFailureHookFunc func(int)

var taskStartFailureHook atomic.Value

type taskStartFailureContext struct {
	taskID   int
	clientID int
}

func (r runtimeRegistry) raw() *sync.Map {
	if r.entries == nil {
		return nil
	}
	return r.entries()
}

func (r runtimeRegistry) Load(id int) (interface{}, bool) {
	entries := r.raw()
	if entries == nil {
		return nil, false
	}
	return entries.Load(id)
}

func (r runtimeRegistry) Store(id int, value interface{}) {
	entries := r.raw()
	if entries == nil {
		return
	}
	entries.Store(id, value)
}

func (r runtimeRegistry) Delete(id int) {
	entries := r.raw()
	if entries == nil {
		return
	}
	entries.Delete(id)
}

func (r runtimeRegistry) DeleteIfEqual(id int, expected interface{}) bool {
	entries := r.raw()
	if entries == nil {
		return false
	}
	return entries.CompareAndDelete(id, expected)
}

func (r runtimeRegistry) Range(fn func(key, value interface{}) bool) {
	if fn == nil {
		return
	}
	entries := r.raw()
	if entries == nil {
		return
	}
	entries.Range(fn)
}

func (r runtimeRegistry) Contains(id int) bool {
	_, ok := r.Load(id)
	return ok
}

func (r runtimeRegistry) LookupDialer(id int) (tool.Dialer, bool) {
	value, ok := r.Load(id)
	if !ok {
		return nil, false
	}
	svr, ok := value.(*proxy.TunnelModeServer)
	if !ok {
		return nil, false
	}
	if svr == nil || svr.Task == nil || svr.Task.Target == nil {
		return nil, false
	}
	if strings.Contains(svr.Task.Target.TargetStr, "tunnel://") {
		return nil, false
	}
	return svr, true
}

func StopServer(id int) error {
	state, err := markStoredTaskStopped(id)
	if err != nil {
		return err
	}
	if err := closeRunningTask(id); err != nil {
		if !errors.Is(err, errTaskNotRunning) {
			rollbackStoredTaskStop(state)
		}
		return err
	}
	return nil
}

func markStoredTaskStopped(id int) (storedTaskStopState, error) {
	t, err := file.GetDb().GetTask(id)
	if err != nil {
		return storedTaskStopState{}, err
	}
	state := storedTaskStopState{
		taskID:         t.Id,
		previousStatus: t.Status,
		task:           t,
	}
	logs.Info("close port %d,remark %s,client id %d,task id %d", t.Port, t.Remark, taskClientID(t), t.Id)
	if err := file.GetDb().UpdateTaskStatus(t.Id, false); err != nil {
		return storedTaskStopState{}, err
	}
	if t.Rate != nil {
		t.Rate.Stop()
	}
	return state, nil
}

func rollbackStoredTaskStop(state storedTaskStopState) {
	if state.taskID <= 0 {
		return
	}
	if err := file.GetDb().UpdateTaskStatus(state.taskID, state.previousStatus); err != nil {
		logs.Warn("rollback task %d status after stop failure error: %v", state.taskID, err)
		return
	}
	if state.previousStatus && state.task != nil && state.task.Rate != nil {
		state.task.Rate.Start()
	}
}

func closeRunningTask(id int) error {
	v, ok := runtimeTasks.Load(id)
	if !ok {
		return errTaskNotRunning
	}
	if svr, ok := v.(proxy.Service); ok {
		if err := svr.Close(); err != nil {
			return err
		}
		logs.Info("stop server id %d", id)
	} else {
		logs.Warn("stop server id %d error", id)
	}
	runtimeTasks.DeleteIfEqual(id, v)
	return nil
}

func stopTaskRuntime(id int) {
	if v, ok := runtimeTasks.Load(id); ok {
		if svr, ok := v.(proxy.Service); ok {
			if err := svr.Close(); err != nil {
				logs.Warn("stop runtime task id %d error %v", id, err)
			}
		}
		runtimeTasks.DeleteIfEqual(id, v)
	}
}

func StopTaskRuntime(id int) error {
	return closeRunningTask(id)
}

func PingClient(id int, addr string) int {
	if id <= 0 {
		return 0
	}
	link := newPingLink(addr)
	start := time.Now()
	target, err := runtimeState.OpenBridgeLink(id, link, nil)
	if err != nil {
		logs.Warn("get connection from client Id %d error %v", id, err)
		return -1
	}
	rtt := int(time.Since(start).Milliseconds())
	_ = target.Close()
	return rtt
}

func newPingLink(addr string) *conn.Link {
	link := conn.NewLink("ping", "", false, false, addr, false)
	link.Option.NeedAck = true
	link.Option.Timeout = pingTimeout
	return link
}

func AddTask(t *file.Tunnel) error {
	if t == nil {
		return errTaskIsNil
	}
	file.InitializeTunnelRuntime(t)
	if handled, err := registerPassiveTaskRuntime(t); handled || err != nil {
		return err
	}
	return startActiveTaskRuntime(t)
}

func startActiveTaskRuntime(t *file.Tunnel) error {
	if err := prepareActiveTaskRuntimeStart(t); err != nil {
		return err
	}
	svr, err := newTaskRuntimeService(t)
	if err != nil {
		return err
	}
	launchTaskRuntime(t, svr)
	return nil
}

func registerPassiveTaskRuntime(t *file.Tunnel) (bool, error) {
	if t == nil {
		return false, nil
	}
	if t.Mode != "secret" && t.Mode != "p2p" {
		return false, nil
	}
	logs.Info("secret task %s start ", t.Remark)
	runtimeTasks.Store(t.Id, nil)
	return true, nil
}

func prepareActiveTaskRuntimeStart(t *file.Tunnel) error {
	if t == nil {
		return errTaskIsNil
	}
	if tool.TestTunnelPort(t) || t.Mode == "httpHostServer" {
		updateFlowSession(servercfg.Current().FlowStoreIntervalDuration())
		return nil
	}
	logs.Error("taskId %d start error port %d open failed", t.Id, t.Port)
	return errors.New("the port open error")
}

func newTaskRuntimeService(t *file.Tunnel) (proxy.Service, error) {
	svr := runtimeTaskModes.New(t)
	if svr == nil {
		return nil, errors.New("the mode is not correct")
	}
	return svr, nil
}

func launchTaskRuntime(t *file.Tunnel, svr proxy.Service) {
	logs.Info("tunnel task %s start mode：%s port %d", t.Remark, t.Mode, t.Port)
	runtimeTasks.Store(t.Id, svr)
	go func() {
		if err := svr.Start(); err != nil {
			handleTaskStartFailure(t, svr, err)
		}
	}()
}

func handleTaskStartFailure(t *file.Tunnel, svr proxy.Service, err error) {
	context := resolveTaskStartFailureContext(t)
	defer notifyTaskStartFailure(context.taskID)
	logs.Error("clientId %d taskId %d start error %v", context.clientID, context.taskID, err)

	closeFailedTaskRuntime(context.taskID, svr)
	if t == nil {
		return
	}
	if !clearFailedTaskRuntimeEntry(context.taskID, svr) {
		return
	}
	persistTaskStoppedAfterStartFailure(context.taskID)
}

func resolveTaskStartFailureContext(t *file.Tunnel) taskStartFailureContext {
	context := taskStartFailureContext{}
	if t == nil {
		return context
	}
	context.taskID = t.Id
	if t.Client != nil {
		context.clientID = t.Client.Id
	}
	return context
}

func closeFailedTaskRuntime(taskID int, svr proxy.Service) {
	if svr == nil {
		return
	}
	if closeErr := svr.Close(); closeErr != nil {
		logs.Warn("cleanup failed after task %d start error: %v", taskID, closeErr)
	}
}

func clearFailedTaskRuntimeEntry(taskID int, expected proxy.Service) bool {
	current, ok := runtimeTasks.Load(taskID)
	if !ok || current != expected {
		return false
	}
	return runtimeTasks.DeleteIfEqual(taskID, expected)
}

func persistTaskStoppedAfterStartFailure(taskID int) {
	if taskID <= 0 {
		return
	}
	stored, getErr := file.GetDb().GetTask(taskID)
	if getErr != nil {
		logs.Warn("load task %d after start failure error: %v", taskID, getErr)
		return
	}
	if !stored.Status {
		return
	}
	if updateErr := file.GetDb().UpdateTaskStatus(stored.Id, false); updateErr != nil {
		logs.Warn("persist task %d stopped after start failure error: %v", taskID, updateErr)
	}
}

func notifyTaskStartFailure(taskID int) {
	v := taskStartFailureHook.Load()
	if v == nil {
		return
	}
	hook, ok := v.(taskStartFailureHookFunc)
	if !ok || hook == nil {
		return
	}
	hook(taskID)
}

func StartTask(id int) error {
	task, err := loadStoredTaskForStart(id)
	if err != nil {
		return err
	}
	if err := AddTask(task); err != nil {
		return err
	}
	if err := file.GetDb().UpdateTaskStatus(task.Id, true); err != nil {
		stopTaskRuntime(task.Id)
		return err
	}
	return nil
}

func loadStoredTaskForStart(id int) (*file.Tunnel, error) {
	return file.GetDb().GetTask(id)
}

func taskClientID(task *file.Tunnel) int {
	if task == nil || task.Client == nil {
		return 0
	}
	return task.Client.Id
}

func DelTask(id int) error {
	if runtimeTasks.Contains(id) {
		if err := StopServer(id); err != nil {
			return err
		}
	}
	return file.GetDb().DelTask(id)
}
