package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/rate"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/lib/version"
	"github.com/djylb/nps/server/proxy"
)

type serverEngineContext struct {
	bridgeFactory      bridgeFactory
	bridgeLauncher     bridgeRuntimeLauncher
	p2pProbeLauncher   p2pProbeLauncher
	backgroundLauncher backgroundRuntimeLauncher
	httpHostLauncher   httpHostRuntimeLauncher
	webLauncher        webRuntimeLauncher
	startup            serverEngineStartup
}

var runtimeEngine = newServerEngineContext()

func newServerEngineContext() *serverEngineContext {
	ctx := &serverEngineContext{}
	ctx.bridgeFactory = bridgeFactory{
		resolveRunList:  runtimeTasks.raw,
		newBridge:       bridge.NewTunnel,
		closeClientHook: runtimeBridgeEvents.HandleCloseClient,
		closeNodeHook:   runtimeBridgeEvents.HandleCloseNode,
	}
	ctx.bridgeLauncher = bridgeRuntimeLauncher{
		currentBridge: runtimeState.Bridge,
		start: func(runtimeBridge *bridge.Bridge) error {
			return runtimeBridge.StartTunnel()
		},
		launch: func(run func()) {
			go run()
		},
	}
	ctx.p2pProbeLauncher = p2pProbeLauncher{
		checkPort: common.TestUdpPort,
		start: func(basePort int, enableExtraReply bool) error {
			p2pServer := proxy.NewP2PServer(basePort, enableExtraReply)
			if err := p2pServer.StartBackground(); err != nil {
				return err
			}
			currentP2PServer.set(p2pServer)
			return nil
		},
	}
	ctx.backgroundLauncher = newBackgroundRuntimeLauncher(
		DealBridgeTask,
		cleanupRegisteredIPs,
		InitDashboardData,
		InitFromDb,
	)
	ctx.httpHostLauncher = httpHostRuntimeLauncher{
		newTask: func() *file.Tunnel {
			return &file.Tunnel{
				Port:   0,
				Mode:   "httpHostServer",
				Status: true,
			}
		},
		start: AddTask,
	}
	ctx.webLauncher = webRuntimeLauncher{
		modeRuntime: runtimeTaskModes,
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Mode: "webServer"}
		},
		publish: func(id int, service proxy.Service) {
			runtimeTasks.Store(id, service)
		},
	}
	ctx.startup = serverEngineStartup{
		currentConfig: servercfg.Current,
		createBridge: func(cfg *servercfg.Snapshot, bridgeDisconnect int) *bridge.Bridge {
			return ctx.bridgeFactory.New(cfg, bridgeDisconnect)
		},
		assignBridge: func(runtimeBridge *bridge.Bridge) {
			runtimeState.AssignBridge(runtimeBridge)
		},
		startBridge:   ctx.bridgeLauncher.Start,
		startP2PProbe: ctx.p2pProbeLauncher.Start,
		startBackgrounds: func() {
			ctx.backgroundLauncher.Start()
		},
		startHTTPHost: func() {
			if err := ctx.httpHostLauncher.Start(); err != nil {
				logs.Error("start http host runtime error %v", err)
			}
		},
		startWeb: func(enable bool) {
			ctx.webLauncher.Start(enable)
		},
	}
	return ctx
}

type serverEngineStartup struct {
	currentConfig    func() *servercfg.Snapshot
	createBridge     func(*servercfg.Snapshot, int) *bridge.Bridge
	assignBridge     func(*bridge.Bridge)
	startBridge      func()
	startP2PProbe    func(*servercfg.Snapshot)
	startBackgrounds func()
	startHTTPHost    func()
	startWeb         func(bool)
}

type p2pProbeBootstrap struct {
	basePort   int
	extraReply bool
}

func StartServerEngine(enableWeb bool, bridgeDisconnect int) {
	if runtimeEngine == nil {
		return
	}
	runtimeEngine.startup.Start(enableWeb, bridgeDisconnect)
}

func (b serverEngineStartup) Start(enableWeb bool, bridgeDisconnect int) {
	cfg := servercfg.ResolveProvider(b.currentConfig)
	b.startBridgeRuntime(cfg, bridgeDisconnect)
	b.startAncillaryRuntimes(cfg, enableWeb)
}

func (b serverEngineStartup) startBridgeRuntime(cfg *servercfg.Snapshot, bridgeDisconnect int) {
	if b.createBridge != nil {
		b.assignBridge(b.createBridge(cfg, bridgeDisconnect))
	}
	if b.startBridge != nil {
		b.startBridge()
	}
}

func (b serverEngineStartup) startAncillaryRuntimes(cfg *servercfg.Snapshot, enableWeb bool) {
	if b.startP2PProbe != nil {
		b.startP2PProbe(cfg)
	}
	if b.startBackgrounds != nil {
		b.startBackgrounds()
	}
	if b.startHTTPHost != nil {
		b.startHTTPHost()
	}
	if b.startWeb != nil {
		b.startWeb(enableWeb)
	}
}

type backgroundRuntimeLauncher struct {
	startBridgeEvents    func()
	startRegisterCleanup func()
	initDashboard        func()
	initRuntime          func()
}

func newBackgroundRuntimeLauncher(
	startBridgeEvents func(),
	startRegisterCleanup func(),
	initDashboard func(),
	initRuntime func(),
) backgroundRuntimeLauncher {
	return backgroundRuntimeLauncher{
		startBridgeEvents:    wrapBackgroundLoopStart(startBridgeEvents),
		startRegisterCleanup: wrapBackgroundLoopStart(startRegisterCleanup),
		initDashboard:        initDashboard,
		initRuntime:          initRuntime,
	}
}

func wrapBackgroundLoopStart(start func()) func() {
	if start == nil {
		return nil
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			engineBackgroundWG.Add(1)
			go func() {
				defer engineBackgroundWG.Done()
				start()
			}()
		})
	}
}

func (l backgroundRuntimeLauncher) Start() {
	if l.startBridgeEvents != nil {
		l.startBridgeEvents()
	}
	if l.startRegisterCleanup != nil {
		l.startRegisterCleanup()
	}
	if l.initRuntime != nil {
		l.initRuntime()
	}
	if l.initDashboard != nil {
		l.initDashboard()
	}
}

type bridgeFactory struct {
	resolveRunList  func() *sync.Map
	newBridge       func(bool, *sync.Map, int) *bridge.Bridge
	closeClientHook func(int)
	closeNodeHook   func(int, string)
}

func (f bridgeFactory) New(cfg *servercfg.Snapshot, bridgeDisconnect int) *bridge.Bridge {
	if f.resolveRunList == nil {
		return nil
	}
	runList := f.resolveRunList()
	if f.newBridge == nil || runList == nil {
		return nil
	}
	cfg = servercfg.Resolve(cfg)
	runtimeBridge := f.newBridge(common.GetBoolByStr(cfg.Runtime.IPLimit), runList, bridgeDisconnect)
	if runtimeBridge != nil {
		runtimeBridge.SetCloseClientHook(f.closeClientHook)
		runtimeBridge.SetCloseNodeHook(f.closeNodeHook)
	}
	return runtimeBridge
}

type bridgeRuntimeLauncher struct {
	currentBridge func() *bridge.Bridge
	start         func(*bridge.Bridge) error
	launch        func(func())
}

func (l bridgeRuntimeLauncher) Start() {
	var runtimeBridge *bridge.Bridge
	if l.currentBridge != nil {
		runtimeBridge = l.currentBridge()
	}
	if runtimeBridge == nil || l.start == nil {
		return
	}
	run := func() {
		if err := l.start(runtimeBridge); err != nil {
			logs.Error("start server bridge error %v", err)
		}
	}
	if l.launch != nil {
		l.launch(run)
		return
	}
	run()
}

type p2pProbeLauncher struct {
	checkPort func(int) bool
	start     func(int, bool) error
}

func (l p2pProbeLauncher) Start(cfg *servercfg.Snapshot) {
	bootstrap, ok := resolveP2PProbeBootstrap(cfg)
	if !ok || l.start == nil {
		return
	}
	if !l.portsAvailable(bootstrap.basePort) {
		return
	}
	if err := l.start(bootstrap.basePort, bootstrap.extraReply); err != nil {
		logs.Error("Failed to start P2P probe server on ports %d-%d: %v", bootstrap.basePort, bootstrap.basePort+2, err)
		return
	}
	logs.Info("Started P2P probe server on ports %d-%d", bootstrap.basePort, bootstrap.basePort+2)
}

func resolveP2PProbeBootstrap(cfg *servercfg.Snapshot) (p2pProbeBootstrap, bool) {
	if cfg == nil {
		return p2pProbeBootstrap{}, false
	}
	basePort := cfg.P2PProbeBasePort()
	if basePort == 0 {
		return p2pProbeBootstrap{}, false
	}
	return p2pProbeBootstrap{
		basePort:   basePort,
		extraReply: cfg.P2P.ProbeExtraReply,
	}, true
}

func (l p2pProbeLauncher) portsAvailable(basePort int) bool {
	ok := true
	for i := 0; i < 3; i++ {
		port := basePort + i
		if l.checkPort != nil && l.checkPort(port) {
			logs.Info("P2P probe port %d available", port)
			continue
		}
		logs.Error("Port %d is unavailable.", port)
		ok = false
	}
	return ok
}

type httpHostRuntimeLauncher struct {
	newTask func() *file.Tunnel
	start   func(*file.Tunnel) error
}

type webRuntimeLauncher struct {
	modeRuntime taskModeRuntime
	newTask     func() *file.Tunnel
	publish     func(int, proxy.Service)
}

func (l httpHostRuntimeLauncher) Start() error {
	if l.newTask == nil || l.start == nil {
		return nil
	}
	task := l.newTask()
	if task == nil {
		return nil
	}
	return l.start(task)
}

func (l webRuntimeLauncher) Start(enable bool) {
	if !enable {
		logs.Info("web management is disabled in current run mode")
		return
	}
	if l.newTask == nil || l.modeRuntime.newMode == nil {
		return
	}
	task := l.newTask()
	if task == nil {
		return
	}
	service := l.modeRuntime.New(task)
	if service == nil {
		logs.Error("Incorrect startup mode %s", task.Mode)
		return
	}
	if webSrv, ok := service.(*WebServer); ok {
		currentWebServer.set(webSrv)
	}
	if err := service.Start(); err != nil {
		logs.Error("%v", err)
		if closeErr := service.Close(); closeErr != nil {
			logs.Warn("cleanup web runtime after start error: %v", closeErr)
		}
		return
	}
	if l.publish != nil {
		l.publish(task.Id, service)
	}
}

var errRuntimeSpecialClientStoreUnavailable = errors.New("runtime special client store unavailable")

type managedTaskStore interface {
	RangeTasks(func(*file.Tunnel) bool)
}

type runtimeTaskPresence interface {
	Contains(id int) bool
}

type managedTaskCoordinator struct {
	store   managedTaskStore
	runtime runtimeTaskPresence
	start   func(*file.Tunnel) error
	stop    func(int)
}

type dbManagedTaskStore struct{}

type persistedClientPresence interface {
	HasClient(id int) bool
}

type activeBridgeClients interface {
	RangeClientIDs(func(int) bool)
	Disconnect(id int)
}

type orphanClientCoordinator struct {
	active    activeBridgeClients
	persisted persistedClientPresence
}

type bridgeRuntimeClients struct {
	resolve func() *bridge.Bridge
}

type dbPersistedClientPresence struct{}

type runtimeSpecialClientStore interface {
	GetClient(id int) (*file.Client, error)
	GetClientByVerifyKey(vkey string) (*file.Client, error)
	CreateClient(*file.Client) error
	DeleteClient(id int) error
	RangeClients(func(*file.Client) bool)
}

type runtimeSpecialClientRuntime interface {
	Publish(id int)
	Unpublish(id int)
	DropBridgeClient(id int)
}

type runtimeSpecialClientCoordinator struct {
	store   runtimeSpecialClientStore
	runtime runtimeSpecialClientRuntime
}

type bridgeRuntimeSpecialClients struct {
	tasks  runtimeRegistry
	bridge func() *bridge.Bridge
}

type bridgeEventStore interface {
	GetClient(id int) (*file.Client, error)
	DeleteClient(id int) error
	GetTaskBySecret(password string) *file.Tunnel
}

type bridgeEventRuntime interface {
	RemoveHostCache(id int)
	RestartTask(id int) error
	DeleteClientResources(id int)
	DeleteClientResourcesByUUID(int, string)
	HandleSecretTask(task *file.Tunnel, src *conn.Conn, cfg *servercfg.Snapshot)
}

type bridgeEventCoordinator struct {
	store         bridgeEventStore
	runtime       bridgeEventRuntime
	currentConfig func() *servercfg.Snapshot
}

type secretTaskDispatch struct {
	task *file.Tunnel
	src  *conn.Conn
	cfg  *servercfg.Snapshot
}

type clientRuntimeCleanupPlan struct {
	taskIDs []int
	hostIDs []int
}

type clientRuntimeOwnerCleanupPlan struct {
	ownerlessTasks []*file.Tunnel
	ownerlessHosts []*file.Host
	refreshHostIDs []int
}

type serverBridgeEventRuntime struct{}

type dbBridgeEventStore struct{}

var persistedManagedTasks = managedTaskCoordinator{
	store:   dbManagedTaskStore{},
	runtime: runtimeTasks,
	start:   AddTask,
	stop:    stopTaskRuntime,
}

var runtimeOrphanClients = orphanClientCoordinator{
	active:    bridgeRuntimeClients{resolve: runtimeState.Bridge},
	persisted: dbPersistedClientPresence{},
}

var runtimeSpecialClients = runtimeSpecialClientCoordinator{
	store:   dbRuntimeSpecialClientStore{},
	runtime: bridgeRuntimeSpecialClients{tasks: runtimeTasks, bridge: runtimeState.Bridge},
}

var runtimeBridgeEvents = bridgeEventCoordinator{
	store:         dbBridgeEventStore{},
	runtime:       serverBridgeEventRuntime{},
	currentConfig: servercfg.Current,
}

func (c managedTaskCoordinator) StartPersisted() {
	if c.store == nil || c.start == nil {
		return
	}
	c.store.RangeTasks(func(task *file.Tunnel) bool {
		if task == nil || !task.Status {
			return true
		}
		if c.runtime != nil && c.runtime.Contains(task.Id) {
			return true
		}
		_ = c.start(task)
		return true
	})
}

func (c managedTaskCoordinator) StopPreserveStatus() {
	if c.store == nil || c.stop == nil {
		return
	}
	c.store.RangeTasks(func(task *file.Tunnel) bool {
		if task != nil {
			c.stop(task.Id)
		}
		return true
	})
}

func (dbManagedTaskStore) RangeTasks(fn func(*file.Tunnel) bool) {
	if fn == nil {
		return
	}
	file.GetDb().RangeTasks(fn)
}

func (c orphanClientCoordinator) DisconnectOrphans() {
	if c.active == nil || c.persisted == nil {
		return
	}
	orphanIDs := make([]int, 0)
	c.active.RangeClientIDs(func(clientID int) bool {
		if !c.persisted.HasClient(clientID) {
			orphanIDs = append(orphanIDs, clientID)
		}
		return true
	})
	for _, clientID := range orphanIDs {
		c.active.Disconnect(clientID)
	}
}

func (c bridgeRuntimeClients) RangeClientIDs(fn func(int) bool) {
	if fn == nil || c.resolve == nil {
		return
	}
	bridgeRuntime := c.resolve()
	if bridgeRuntime == nil || bridgeRuntime.Client == nil {
		return
	}
	bridgeRuntime.Client.Range(func(key, value interface{}) bool {
		clientID, ok := key.(int)
		if !ok {
			bridgeRuntime.Client.CompareAndDelete(key, value)
			return true
		}
		if clientID <= 0 {
			return true
		}
		client, ok := value.(*bridge.Client)
		if !ok || client == nil {
			bridgeRuntime.Client.CompareAndDelete(key, value)
			return true
		}
		return fn(clientID)
	})
}

func (c bridgeRuntimeClients) Disconnect(id int) {
	if c.resolve == nil {
		return
	}
	bridgeRuntime := c.resolve()
	if bridgeRuntime == nil {
		return
	}
	bridgeRuntime.DelClient(id)
}

func (dbPersistedClientPresence) HasClient(id int) bool {
	db := file.GetDb()
	if !db.Ready() {
		return false
	}
	_, err := db.GetClient(id)
	return err == nil
}

func (c runtimeSpecialClientCoordinator) EnsureLocalProxy(enabled bool) {
	if c.store == nil {
		return
	}
	if enabled {
		if _, err := c.store.GetClient(-1); err == nil {
			return
		}
		if err := c.store.CreateClient(newLocalProxyRuntimeClient()); err != nil {
			logs.Warn("auto create local proxy client failed: %v", err)
			return
		}
		logs.Info("Auto create local proxy client.")
		return
	}
	if _, err := c.store.GetClient(-1); err != nil {
		return
	}
	if c.runtime != nil {
		c.runtime.DropBridgeClient(-1)
		c.runtime.Unpublish(-1)
	}
	_ = c.store.DeleteClient(-1)
}

func (c runtimeSpecialClientCoordinator) SyncVKeys(cfg *servercfg.Snapshot) {
	if c.store == nil {
		return
	}
	cfg = servercfg.Resolve(cfg)
	desiredByKey := desiredRuntimeVKeyLabels(cfg)
	publicKey := strings.TrimSpace(cfg.Runtime.PublicVKey)
	c.reconcileStoredVKeyClients(desiredByKey, publicKey)
	c.publishDesiredVKeyClients(desiredByKey, publicKey)
}

func (c runtimeSpecialClientCoordinator) publishDesiredVKeyClients(desiredByKey map[string]string, publicKey string) {
	for key, label := range desiredByKey {
		client, created := c.ensureVKeyClient(key, label)
		if client == nil {
			continue
		}
		client.Remark = label
		if created {
			c.applyRuntimeVKeyPublication(client.Id, key, publicKey)
		}
	}
}

func (c runtimeSpecialClientCoordinator) reconcileStoredVKeyClients(desiredByKey map[string]string, publicKey string) {
	c.store.RangeClients(func(client *file.Client) bool {
		if !isManagedRuntimeVKeyClient(client) {
			return true
		}
		verifyKey := strings.TrimSpace(client.VerifyKey)
		if label, exists := desiredByKey[verifyKey]; exists {
			if client.Remark != label {
				client.Remark = label
			}
			c.applyRuntimeVKeyPublication(client.Id, verifyKey, publicKey)
			return true
		}
		c.removeRuntimeVKeyClient(client)
		return true
	})
}

func isManagedRuntimeVKeyClient(client *file.Client) bool {
	if client == nil || !client.NoStore || !client.NoDisplay {
		return false
	}
	remark := strings.TrimSpace(client.Remark)
	return remark == "public_vkey" || remark == "visitor_vkey"
}

func (c runtimeSpecialClientCoordinator) applyRuntimeVKeyPublication(clientID int, verifyKey string, publicKey string) {
	if c.runtime == nil {
		return
	}
	if verifyKey == publicKey {
		c.runtime.Publish(clientID)
		return
	}
	c.runtime.Unpublish(clientID)
}

func (c runtimeSpecialClientCoordinator) removeRuntimeVKeyClient(client *file.Client) {
	if client == nil {
		return
	}
	if c.runtime != nil {
		c.runtime.DropBridgeClient(client.Id)
		c.runtime.Unpublish(client.Id)
	}
	_ = c.store.DeleteClient(client.Id)
}

func (c runtimeSpecialClientCoordinator) ensureVKeyClient(vkey string, label string) (*file.Client, bool) {
	vkey = strings.TrimSpace(vkey)
	if vkey == "" || c.store == nil {
		return nil, false
	}
	if existing, err := c.store.GetClientByVerifyKey(vkey); err == nil && existing != nil {
		if existing.NoStore && existing.NoDisplay {
			return existing, false
		}
		logs.Warn("%s conflicts with existing client id=%d; use a dedicated vkey to keep access scope isolated", label, existing.Id)
		return nil, false
	}
	client := file.NewClient(vkey, true, true)
	client.Remark = label
	if err := c.store.CreateClient(client); err != nil {
		logs.Warn("auto create %s client failed: %v", label, err)
		return nil, false
	}
	logs.Info("Auto create %s client.", label)
	return client, true
}

func desiredRuntimeVKeyLabels(cfg *servercfg.Snapshot) map[string]string {
	desiredByKey := make(map[string]string, 2)
	if cfg == nil {
		return desiredByKey
	}
	publicKey := strings.TrimSpace(cfg.Runtime.PublicVKey)
	visitorKey := strings.TrimSpace(cfg.Runtime.VisitorVKey)
	if publicKey != "" {
		desiredByKey[publicKey] = "public_vkey"
	}
	if visitorKey != "" {
		if _, exists := desiredByKey[visitorKey]; !exists {
			desiredByKey[visitorKey] = "visitor_vkey"
		}
	}
	return desiredByKey
}

func newLocalProxyRuntimeClient() *file.Client {
	local := file.NewClient("localproxy", true, false)
	local.Id = -1
	local.Remark = "Local Proxy"
	local.Addr = "127.0.0.1"
	local.Rate = rate.NewRate(0)
	local.Rate.Start()
	local.ConfigConnAllow = true
	local.Version = version.VERSION
	return local
}

func DealBridgeTask() {
	dealBridgeTaskWithSource(
		runtimeState.BridgeEvents(),
		runtimeBridgeEvents.HandleOpenHost,
		runtimeBridgeEvents.HandleOpenTask,
		runtimeBridgeEvents.HandleSecret,
		engineStop.stop(),
	)
}

func dealBridgeTaskWithSource(
	source bridgeEventSource,
	handleOpenHost func(*file.Host),
	handleOpenTask func(*file.Tunnel),
	handleSecret func(*conn.Secret),
	stop <-chan struct{},
) {
	openHost := source.openHost
	openTask := source.openTask
	secret := source.secret
	for {
		if stop == nil && openHost == nil && openTask == nil && secret == nil {
			return
		}
		select {
		case <-stop:
			return
		case h, ok := <-openHost:
			if !ok {
				openHost = nil
				continue
			}
			if handleOpenHost != nil {
				handleOpenHost(h)
			}
		case t, ok := <-openTask:
			if !ok {
				openTask = nil
				continue
			}
			if handleOpenTask != nil {
				handleOpenTask(t)
			}
		case s, ok := <-secret:
			if !ok {
				secret = nil
				continue
			}
			if handleSecret != nil {
				handleSecret(s)
			}
		}
	}
}

func (r bridgeRuntimeSpecialClients) Publish(id int) {
	r.tasks.Store(id, nil)
}

func (r bridgeRuntimeSpecialClients) Unpublish(id int) {
	r.tasks.DeleteIfEqual(id, nil)
}

func (r bridgeRuntimeSpecialClients) DropBridgeClient(id int) {
	bridgeRuntime := runtimeState.Bridge()
	if r.bridge != nil {
		bridgeRuntime = r.bridge()
	}
	if bridgeRuntime == nil {
		return
	}
	bridgeRuntime.DelClient(id)
}

func (c bridgeEventCoordinator) HandleOpenHost(host *file.Host) {
	if host == nil || c.runtime == nil {
		return
	}
	c.runtime.RemoveHostCache(host.Id)
}

func (c bridgeEventCoordinator) HandleOpenTask(task *file.Tunnel) {
	if task == nil || c.runtime == nil {
		return
	}
	if err := c.runtime.RestartTask(task.Id); err != nil {
		logs.Error("StartTask(%d) error: %v", task.Id, err)
	}
}

func (c bridgeEventCoordinator) HandleCloseClient(clientID int) {
	if c.runtime == nil || c.store == nil {
		return
	}
	c.runtime.DeleteClientResources(clientID)
	c.deleteTransientClosedClient(clientID)
}

func (c bridgeEventCoordinator) HandleCloseNode(clientID int, uuid string) {
	if c.runtime == nil || clientID == 0 || strings.TrimSpace(uuid) == "" {
		return
	}
	c.runtime.DeleteClientResourcesByUUID(clientID, uuid)
}

func (c bridgeEventCoordinator) HandleSecret(secret *conn.Secret) {
	dispatch, ok := c.resolveSecretTaskDispatch(secret)
	if !ok {
		return
	}
	c.dispatchSecretTask(dispatch)
}

func (c bridgeEventCoordinator) deleteTransientClosedClient(clientID int) {
	client, err := c.store.GetClient(clientID)
	if err == nil && client != nil && client.NoStore {
		_ = c.store.DeleteClient(clientID)
	}
}

func (c bridgeEventCoordinator) resolveActiveSecretTask(secret *conn.Secret) (*file.Tunnel, bool) {
	if secret == nil {
		return nil, false
	}
	logs.Trace("New secret connection, addr %v", secret.Conn.Conn.RemoteAddr())
	task := c.lookupSecretTask(secret.Password)
	if task == nil {
		logs.Trace("This key %s cannot be processed", secret.Password)
		_ = secret.Conn.Close()
		return nil, false
	}
	if !task.Status {
		_ = secret.Conn.Close()
		logs.Trace("This key %s cannot be processed,status is close", secret.Password)
		return nil, false
	}
	return task, true
}

func (c bridgeEventCoordinator) resolveSecretTaskDispatch(secret *conn.Secret) (secretTaskDispatch, bool) {
	task, ok := c.resolveActiveSecretTask(secret)
	if !ok {
		return secretTaskDispatch{}, false
	}
	return secretTaskDispatch{
		task: task,
		src:  secret.Conn,
		cfg:  servercfg.ResolveProvider(c.currentConfig),
	}, true
}

func (c bridgeEventCoordinator) dispatchSecretTask(dispatch secretTaskDispatch) {
	if c.runtime == nil || dispatch.task == nil || dispatch.src == nil {
		return
	}
	go c.runtime.HandleSecretTask(dispatch.task, dispatch.src, dispatch.cfg)
}

func (c bridgeEventCoordinator) lookupSecretTask(password string) *file.Tunnel {
	if c.store == nil {
		return nil
	}
	return c.store.GetTaskBySecret(password)
}

func (serverBridgeEventRuntime) RemoveHostCache(id int) {
	runtimeState.RemoveHostCache(id)
}

func (serverBridgeEventRuntime) RestartTask(id int) error {
	_ = StopServer(id)
	return StartTask(id)
}

func (serverBridgeEventRuntime) DeleteClientResources(id int) {
	DelTunnelAndHostByClientId(id, true)
}

func (serverBridgeEventRuntime) DeleteClientResourcesByUUID(id int, uuid string) {
	DelTunnelAndHostByClientUUID(id, uuid)
}

func (serverBridgeEventRuntime) HandleSecretTask(task *file.Tunnel, src *conn.Conn, cfg *servercfg.Snapshot) {
	runtimeBridge := runtimeState.Bridge()
	if runtimeBridge == nil {
		return
	}
	_ = proxy.NewSecretServer(
		runtimeBridge,
		task,
		cfg.AllowSecretLocalEnabled(),
	).HandleSecret(src)
}

type dbRuntimeSpecialClientStore struct{}

func (dbRuntimeSpecialClientStore) GetClient(id int) (*file.Client, error) {
	db := file.GetDb()
	if !db.Ready() {
		return nil, errRuntimeSpecialClientStoreUnavailable
	}
	return db.GetClient(id)
}

func (dbRuntimeSpecialClientStore) GetClientByVerifyKey(vkey string) (*file.Client, error) {
	db := file.GetDb()
	if !db.Ready() {
		return nil, errRuntimeSpecialClientStoreUnavailable
	}
	return db.GetClientByVerifyKey(vkey)
}

func (dbRuntimeSpecialClientStore) CreateClient(client *file.Client) error {
	db := file.GetDb()
	if !db.Ready() {
		return errRuntimeSpecialClientStoreUnavailable
	}
	return db.NewClient(client)
}

func (dbRuntimeSpecialClientStore) DeleteClient(id int) error {
	db := file.GetDb()
	if !db.Ready() {
		return errRuntimeSpecialClientStoreUnavailable
	}
	return db.DelClient(id)
}

func (dbRuntimeSpecialClientStore) RangeClients(fn func(*file.Client) bool) {
	if fn == nil {
		return
	}
	file.GetDb().RangeClients(fn)
}

func (dbBridgeEventStore) GetClient(id int) (*file.Client, error) {
	db := file.GetDb()
	if !db.Ready() {
		return nil, errRuntimeSpecialClientStoreUnavailable
	}
	return db.GetClient(id)
}

func (dbBridgeEventStore) DeleteClient(id int) error {
	db := file.GetDb()
	if !db.Ready() {
		return errRuntimeSpecialClientStoreUnavailable
	}
	return db.DelClient(id)
}

func (dbBridgeEventStore) GetTaskBySecret(password string) *file.Tunnel {
	db := file.GetDb()
	if !db.Ready() {
		return nil
	}
	return db.GetTaskByMd5Password(password)
}

func cleanupRegisteredIPs() {
	ticker := time.NewTicker(registerCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-engineStop.stop():
			return
		case <-ticker.C:
			removed := runtimeState.CleanupExpiredRegistrations(time.Now())
			if removed > 0 {
				logs.Info("Cleaned %d expired ip_limit registrations", removed)
			}
		}
	}
}

func DelTunnelAndHostByClientId(clientId int, justDelNoStore bool) {
	collectClientRuntimeCleanup(clientId, justDelNoStore).Apply()
}

func DelTunnelAndHostByClientUUID(clientId int, uuid string) {
	uuid = strings.TrimSpace(uuid)
	if clientId == 0 || uuid == "" {
		return
	}
	collectClientRuntimeOwnerCleanup(clientId, uuid).Apply()
}

func collectClientRuntimeCleanup(clientId int, justDelNoStore bool) clientRuntimeCleanupPlan {
	db := file.GetDb()
	if !db.Ready() || clientId == 0 {
		return clientRuntimeCleanupPlan{}
	}
	return clientRuntimeCleanupPlan{
		taskIDs: collectClientTaskIDs(db, clientId, justDelNoStore),
		hostIDs: collectClientHostIDs(db, clientId, justDelNoStore),
	}
}

func (p clientRuntimeCleanupPlan) Apply() {
	db := file.GetDb()
	if !db.Ready() {
		return
	}
	for _, id := range p.taskIDs {
		_ = DelTask(id)
	}
	for _, id := range p.hostIDs {
		runtimeState.RemoveHostCache(id)
		_ = db.DelHost(id)
	}
}

func collectClientRuntimeOwnerCleanup(clientId int, uuid string) clientRuntimeOwnerCleanupPlan {
	db := file.GetDb()
	if !db.Ready() || clientId == 0 || uuid == "" {
		return clientRuntimeOwnerCleanupPlan{}
	}
	hostDelete, hostRefreshIDs := collectRuntimeHostsByClientUUID(db, clientId, uuid)
	return clientRuntimeOwnerCleanupPlan{
		ownerlessTasks: collectOwnerlessRuntimeTasksByClientUUID(db, clientId, uuid),
		ownerlessHosts: hostDelete,
		refreshHostIDs: hostRefreshIDs,
	}
}

func (p clientRuntimeOwnerCleanupPlan) Apply() {
	db := file.GetDb()
	if !db.Ready() {
		return
	}
	for _, task := range p.ownerlessTasks {
		_ = db.DeleteNoStoreTaskIfCurrentOwnerless(task)
	}
	for _, id := range p.refreshHostIDs {
		runtimeState.RemoveHostCache(id)
	}
	for _, host := range p.ownerlessHosts {
		if db.DeleteNoStoreHostIfCurrentOwnerless(host) {
			runtimeState.RemoveHostCache(host.Id)
		}
	}
}

func collectClientTaskIDs(db *file.DbUtils, clientId int, justDelNoStore bool) []int {
	if db == nil || clientId == 0 {
		return nil
	}
	ids := make([]int, 0)
	db.RangeTunnelsByClientID(clientId, func(task *file.Tunnel) bool {
		if task == nil {
			return true
		}
		if justDelNoStore && !task.NoStore {
			return true
		}
		ids = append(ids, task.Id)
		return true
	})
	return ids
}

func collectClientHostIDs(db *file.DbUtils, clientId int, justDelNoStore bool) []int {
	if db == nil || clientId == 0 {
		return nil
	}
	ids := make([]int, 0)
	db.RangeHostsByClientID(clientId, func(host *file.Host) bool {
		if host == nil {
			return true
		}
		if justDelNoStore && !host.NoStore {
			return true
		}
		ids = append(ids, host.Id)
		return true
	})
	return ids
}

func collectOwnerlessRuntimeTasksByClientUUID(db *file.DbUtils, clientId int, uuid string) []*file.Tunnel {
	if db == nil || clientId == 0 || uuid == "" {
		return nil
	}
	taskDelete := make([]*file.Tunnel, 0)
	db.RangeTunnelsByClientID(clientId, func(task *file.Tunnel) bool {
		if task == nil || !task.NoStore {
			return true
		}
		if remaining := task.RemoveRuntimeOwner(uuid); remaining == 0 {
			taskDelete = append(taskDelete, task)
		}
		return true
	})
	return taskDelete
}

func collectRuntimeHostsByClientUUID(db *file.DbUtils, clientId int, uuid string) ([]*file.Host, []int) {
	if db == nil || clientId == 0 || uuid == "" {
		return nil, nil
	}
	hostDelete := make([]*file.Host, 0)
	hostRefreshIDs := make([]int, 0)
	db.RangeHostsByClientID(clientId, func(host *file.Host) bool {
		if host == nil || !host.NoStore {
			return true
		}
		if remaining := host.RemoveRuntimeOwner(uuid); remaining == 0 {
			hostDelete = append(hostDelete, host)
			return true
		}
		hostRefreshIDs = append(hostRefreshIDs, host.Id)
		return true
	})
	return hostDelete, hostRefreshIDs
}

// Bounded shutdown timing. The caller supplies the overall deadline ctx.
const (
	engineSessionGrace          = 5 * time.Second
	engineFlushTimeout          = 5 * time.Second
	engineBackgroundStopTimeout = 3 * time.Second
)

// engineStopSignals provides a process-wide channel closed when shutdown
// begins, used by background loops to stop pulling new work.
type engineStopSignals struct {
	once sync.Once
	ch   chan struct{}
}

func newEngineStopSignals() *engineStopSignals {
	return &engineStopSignals{ch: make(chan struct{})}
}

func (e *engineStopSignals) begin() {
	e.once.Do(func() { close(e.ch) })
}

func (e *engineStopSignals) stop() <-chan struct{} { return e.ch }

var (
	engineStop         = newEngineStopSignals()
	engineBackgroundWG sync.WaitGroup // tracks background loop goroutines
)

// p2pServerHolder retains the running P2P probe server so it can be closed.
type p2pServerHolder struct {
	mu sync.Mutex
	s  *proxy.P2PServer
}

func (h *p2pServerHolder) set(s *proxy.P2PServer) {
	h.mu.Lock()
	h.s = s
	h.mu.Unlock()
}

func (h *p2pServerHolder) close() {
	h.mu.Lock()
	s := h.s
	h.s = nil
	h.mu.Unlock()
	if s != nil {
		if err := s.Close(); err != nil {
			logs.Error("close p2p probe server error: %v", err)
		}
	}
}

// webServerHolder retains the running web management server so it can be
// closed (its Start blocks until the listeners are closed).
type webServerHolder struct {
	mu sync.Mutex
	s  *WebServer
}

func (h *webServerHolder) set(s *WebServer) {
	h.mu.Lock()
	h.s = s
	h.mu.Unlock()
}

func (h *webServerHolder) close() {
	h.mu.Lock()
	s := h.s
	h.s = nil
	h.mu.Unlock()
	if s != nil {
		if err := s.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logs.Error("close web server error: %v", err)
		}
	}
}

var (
	currentP2PServer  p2pServerHolder
	currentWebServer  webServerHolder
	eventWriterFlush  func(context.Context) error
	engineShutdownMu  sync.Mutex
	engineShutdownRan bool
	engineShutdownErr error
)

// RegisterEventWriterFlush registers a bounded flush for asynchronous event
// writers. It is invoked before sessions are force-closed.
func RegisterEventWriterFlush(fn func(context.Context) error) {
	eventWriterFlush = fn
}

// runBounded runs fn in a goroutine and returns its result, or ctx.Err() if fn
// does not return before ctx is done.
func runBounded(ctx context.Context, fn func() error) error {
	if fn == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitEngineWG blocks until wg is drained or ctx is done.
func waitEngineWG(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// flushConfigStore flushes the on-disk configuration store.
func flushConfigStore() error {
	file.GetDb().FlushToDisk()
	return nil
}

// flushRuntimeWriters performs bounded flushing of config, traffic and event
// writers before sessions are force-closed. Any flush failure is returned.
func flushRuntimeWriters(ctx context.Context) error {
	var failures []error
	flushCtx, cancel := context.WithTimeout(ctx, engineFlushTimeout)
	defer cancel()

	if err := runBounded(flushCtx, flushConfigStore); err != nil {
		failures = append(failures, fmt.Errorf("config flush: %w", err))
	}
	if err := runBounded(flushCtx, func() error { runtimeFlow.Flush(); return nil }); err != nil {
		failures = append(failures, fmt.Errorf("traffic flush: %w", err))
	}
	if eventWriterFlush != nil {
		if err := eventWriterFlush(flushCtx); err != nil {
			failures = append(failures, fmt.Errorf("event flush: %w", err))
		}
	}
	return errors.Join(failures...)
}

// ShutdownServerEngine performs a bounded graceful shutdown of the whole
// server. It is idempotent and safe for concurrent invocation: all callers
// block until the first orchestration finishes and share its result.
func ShutdownServerEngine(ctx context.Context) error {
	// Signal loops to stop accepting new work as early as possible.
	engineStop.begin()

	engineShutdownMu.Lock()
	defer engineShutdownMu.Unlock()
	if engineShutdownRan {
		return engineShutdownErr
	}
	engineShutdownErr = runServerEngineShutdown(ctx)
	engineShutdownRan = true
	return engineShutdownErr
}

func runServerEngineShutdown(ctx context.Context) error {
	var failures []error

	// 1. Reject new intake on every protocol immediately, before any flushing
	//    or draining work that could otherwise take seconds.
	if b := runtimeState.Bridge(); b != nil {
		b.BeginShutdown()
	}

	// 2. Flush config/event/traffic writers while existing sessions are still
	//    alive inside the grace window.
	if err := flushRuntimeWriters(ctx); err != nil {
		failures = append(failures, err)
	}

	// 3. Drain bridge sessions within grace, force close the rest, and reclaim
	//    bridge goroutines (intake rejection is already in effect).
	if b := runtimeState.Bridge(); b != nil {
		if err := b.Shutdown(ctx, engineSessionGrace); err != nil {
			failures = append(failures, err)
		}
	}

	// 4. Stop managed proxy tasks without changing on-disk status.
	StopManagedTasksPreserveStatus()

	// 5. Close web management and P2P probe runtimes (release their ports).
	currentWebServer.close()
	currentP2PServer.close()

	// 6. Wait for background loops to exit (bridge events, register cleanup).
	bgCtx, cancel := context.WithTimeout(ctx, engineBackgroundStopTimeout)
	if err := waitEngineWG(bgCtx, &engineBackgroundWG); err != nil {
		failures = append(failures, err)
	}
	cancel()

	if err := errors.Join(failures...); err != nil {
		logs.Error("server engine shutdown completed with failures: %v", err)
		return err
	}
	return nil
}

// notifyEngineSignals subscribes to the process termination signals. It is a
// variable so tests can replace it with a synthetic signal source.
var notifyEngineSignals = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// InstallShutdownSignalHandler performs a bounded graceful shutdown of the
// server engine when SIGTERM or SIGINT is received. The returned channel is
// closed once the shutdown has finished.
func InstallShutdownSignalHandler(totalTimeout time.Duration) <-chan struct{} {
	finished := make(chan struct{})
	sigCh, stopNotify := notifyEngineSignals()
	go func() {
		defer close(finished)
		defer stopNotify()
		<-sigCh
		logs.Info("received termination signal, shutting down server engine")
		ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
		defer cancel()
		_ = ShutdownServerEngine(ctx)
	}()
	return finished
}
