package server

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/index"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/server/proxy"
)

func TestNewServerEngineContextWiresSharedDefaults(t *testing.T) {
	ctx := newServerEngineContext()
	if ctx == nil {
		t.Fatal("engine context should not be nil")
	}
	if ctx.startup.currentConfig == nil || ctx.startup.startBridge == nil || ctx.startup.startWeb == nil {
		t.Fatalf("engine startup wiring = %+v", ctx.startup)
	}
	if ctx.bridgeFactory.resolveRunList == nil || ctx.bridgeFactory.newBridge == nil {
		t.Fatalf("engine bridge factory wiring = %+v", ctx.bridgeFactory)
	}
	if ctx.backgroundLauncher.initDashboard == nil || ctx.backgroundLauncher.initRuntime == nil {
		t.Fatalf("engine background launcher wiring = %+v", ctx.backgroundLauncher)
	}
	if ctx.webLauncher.newTask == nil || ctx.webLauncher.modeRuntime.newMode == nil || ctx.webLauncher.publish == nil {
		t.Fatalf("engine web launcher wiring = %+v", ctx.webLauncher)
	}
}

func TestStartNewServerDelegatesToRuntimeEngine(t *testing.T) {
	oldEngine := runtimeEngine
	t.Cleanup(func() {
		runtimeEngine = oldEngine
	})

	gotEnableWeb := false
	gotDisconnect := 0
	runtimeEngine = &serverEngineContext{
		startup: serverEngineStartup{
			createBridge: func(_ *servercfg.Snapshot, disconnect int) *bridge.Bridge {
				gotDisconnect = disconnect
				return nil
			},
			assignBridge: func(*bridge.Bridge) {},
			startWeb: func(enable bool) {
				gotEnableWeb = enable
			},
		},
	}

	StartNewServer(&file.Tunnel{Mode: "webServer"}, 17)

	if !gotEnableWeb {
		t.Fatal("StartNewServer() should enable web startup for webServer mode")
	}
	if gotDisconnect != 17 {
		t.Fatalf("StartNewServer() disconnect = %d, want 17", gotDisconnect)
	}
}

func TestServerEngineStartupStartRunsConfiguredStepsInOrder(t *testing.T) {
	cfg := &servercfg.Snapshot{
		Runtime: servercfg.RuntimeConfig{
			IPLimit: "true",
		},
	}
	runtimeBridge := &bridge.Bridge{}
	steps := make([]string, 0, 7)

	serverEngineStartup{
		currentConfig: func() *servercfg.Snapshot {
			steps = append(steps, "config")
			return cfg
		},
		createBridge: func(gotCfg *servercfg.Snapshot, disconnect int) *bridge.Bridge {
			steps = append(steps, "createBridge")
			if gotCfg != cfg {
				t.Fatalf("createBridge cfg = %+v, want %+v", gotCfg, cfg)
			}
			if disconnect != 17 {
				t.Fatalf("createBridge disconnect = %d, want 17", disconnect)
			}
			return runtimeBridge
		},
		assignBridge: func(got *bridge.Bridge) {
			steps = append(steps, "assignBridge")
			if got != runtimeBridge {
				t.Fatalf("assignBridge runtime bridge = %+v, want %+v", got, runtimeBridge)
			}
		},
		startBridge: func() {
			steps = append(steps, "startBridge")
		},
		startP2PProbe: func(gotCfg *servercfg.Snapshot) {
			steps = append(steps, "startP2PProbe")
			if gotCfg != cfg {
				t.Fatalf("startP2PProbe cfg = %+v, want %+v", gotCfg, cfg)
			}
		},
		startBackgrounds: func() {
			steps = append(steps, "startBackgrounds")
		},
		startHTTPHost: func() {
			steps = append(steps, "startHTTPHost")
		},
		startWeb: func(enable bool) {
			steps = append(steps, "startWeb")
			if !enable {
				t.Fatal("startWeb enable = false, want true")
			}
		},
	}.Start(true, 17)

	want := []string{
		"config",
		"createBridge",
		"assignBridge",
		"startBridge",
		"startP2PProbe",
		"startBackgrounds",
		"startHTTPHost",
		"startWeb",
	}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("startup steps = %v, want %v", steps, want)
	}
}

func TestServerEngineStartupStartSkipsMissingSteps(t *testing.T) {
	serverEngineStartup{}.Start(false, 0)
}

func TestBackgroundRuntimeLauncherStartRunsStepsInOrder(t *testing.T) {
	steps := make([]string, 0, 4)

	backgroundRuntimeLauncher{
		startBridgeEvents: func() {
			steps = append(steps, "bridgeEvents")
		},
		startRegisterCleanup: func() {
			steps = append(steps, "registerCleanup")
		},
		initDashboard: func() {
			steps = append(steps, "initDashboard")
		},
		initRuntime: func() {
			steps = append(steps, "initRuntime")
		},
	}.Start()

	want := []string{
		"bridgeEvents",
		"registerCleanup",
		"initRuntime",
		"initDashboard",
	}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("background runtime steps = %v, want %v", steps, want)
	}
}

func TestBackgroundRuntimeLauncherStartSkipsMissingSteps(t *testing.T) {
	backgroundRuntimeLauncher{}.Start()
}

func TestNewBackgroundRuntimeLauncherStartsLongLivedLoopsOnlyOnce(t *testing.T) {
	// Wrapped long-lived loops run in tracked goroutines and start at most
	// once; init steps run synchronously on every Start call.
	var bridgeEvents, registerCleanup, initDashboard, initRuntime atomic.Int32

	launcher := newBackgroundRuntimeLauncher(
		func() { bridgeEvents.Add(1) },
		func() { registerCleanup.Add(1) },
		func() { initDashboard.Add(1) },
		func() { initRuntime.Add(1) },
	)

	launcher.Start()
	launcher.Start()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bridgeEvents.Load() == 1 && registerCleanup.Load() == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := bridgeEvents.Load(); got != 1 {
		t.Fatalf("bridgeEvents runs = %d, want 1", got)
	}
	if got := registerCleanup.Load(); got != 1 {
		t.Fatalf("registerCleanup runs = %d, want 1", got)
	}
	if got := initRuntime.Load(); got != 2 {
		t.Fatalf("initRuntime runs = %d, want 2", got)
	}
	if got := initDashboard.Load(); got != 2 {
		t.Fatalf("initDashboard runs = %d, want 2", got)
	}
}

func TestBridgeFactoryNewBuildsBridgeWithResolvedConfigAndRunList(t *testing.T) {
	resetServerTestDB(t)
	runList := &sync.Map{}
	var (
		gotIPVerify   bool
		gotRunList    *sync.Map
		gotDisconnect int
		closedClient  int
	)
	expected := bridge.NewTunnel(false, runList, 0)

	factory := bridgeFactory{
		resolveRunList: func() *sync.Map {
			return runList
		},
		newBridge: func(ipVerify bool, currentRunList *sync.Map, disconnect int) *bridge.Bridge {
			gotIPVerify = ipVerify
			gotRunList = currentRunList
			gotDisconnect = disconnect
			return expected
		},
		closeClientHook: func(id int) {
			closedClient = id
		},
	}

	got := factory.New(&servercfg.Snapshot{
		Runtime: servercfg.RuntimeConfig{IPLimit: "true"},
	}, 17)

	if got != expected {
		t.Fatalf("factory.New() bridge = %+v, want %+v", got, expected)
	}
	if !gotIPVerify {
		t.Fatal("factory.New() should enable ip verification from config")
	}
	if gotRunList != runList {
		t.Fatalf("factory.New() runList = %+v, want %+v", gotRunList, runList)
	}
	if gotDisconnect != 17 {
		t.Fatalf("factory.New() disconnect = %d, want 17", gotDisconnect)
	}

	dbClient := file.NewClient("bridge-factory-test", false, false)
	if err := file.GetDb().NewClient(dbClient); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	got.Client.Store(dbClient.Id, bridge.NewClient(dbClient.Id, bridge.NewNode("node-1", "test", 0)))
	got.DelClient(dbClient.Id)
	if closedClient != dbClient.Id {
		t.Fatalf("close client hook = %d, want %d", closedClient, dbClient.Id)
	}
}

func TestBridgeFactoryNewSkipsMissingDependencies(t *testing.T) {
	if got := (bridgeFactory{}).New(&servercfg.Snapshot{}, 1); got != nil {
		t.Fatalf("factory.New() = %+v, want nil when dependencies are missing", got)
	}
	if got := (bridgeFactory{
		resolveRunList: func() *sync.Map { return nil },
		newBridge:      bridge.NewTunnel,
	}).New(&servercfg.Snapshot{}, 1); got != nil {
		t.Fatalf("factory.New() = %+v, want nil when runList resolver returns nil", got)
	}
}

func TestBridgeRuntimeLauncherStartLaunchesCurrentBridge(t *testing.T) {
	runtimeBridge := &bridge.Bridge{}
	steps := make([]string, 0, 2)

	bridgeRuntimeLauncher{
		currentBridge: func() *bridge.Bridge {
			steps = append(steps, "bridge")
			return runtimeBridge
		},
		start: func(got *bridge.Bridge) error {
			steps = append(steps, "start")
			if got != runtimeBridge {
				t.Fatalf("start bridge = %+v, want %+v", got, runtimeBridge)
			}
			return nil
		},
		launch: func(run func()) {
			steps = append(steps, "launch")
			run()
		},
	}.Start()

	want := []string{"bridge", "launch", "start"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("launcher steps = %v, want %v", steps, want)
	}
}

func TestBridgeRuntimeLauncherStartReturnsOnStartError(t *testing.T) {
	// A start failure must be logged, not terminate the whole process, so the
	// caller (e.g. a service manager) stays in control of the lifecycle.
	startCalls := 0
	returned := make(chan struct{})

	go func() {
		defer close(returned)
		bridgeRuntimeLauncher{
			currentBridge: func() *bridge.Bridge {
				return &bridge.Bridge{}
			},
			start: func(*bridge.Bridge) error {
				startCalls++
				return errors.New("boom")
			},
			launch: func(run func()) {
				run()
			},
		}.Start()
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge launcher did not return after start error")
	}
	if startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", startCalls)
	}
}

func TestBridgeRuntimeLauncherStartSkipsMissingBridge(t *testing.T) {
	launched := false

	bridgeRuntimeLauncher{
		currentBridge: func() *bridge.Bridge { return nil },
		start: func(*bridge.Bridge) error {
			t.Fatal("start should not run when bridge is nil")
			return nil
		},
		launch: func(func()) {
			launched = true
		},
	}.Start()

	if launched {
		t.Fatal("launch should not run when bridge is nil")
	}
}

func TestP2PProbeLauncherStartChecksPortsAndLaunchesServer(t *testing.T) {
	checked := make([]int, 0, 3)
	starts := make([]struct {
		port       int
		extraReply bool
	}, 0, 1)

	launcher := p2pProbeLauncher{
		checkPort: func(port int) bool {
			checked = append(checked, port)
			return true
		},
		start: func(port int, extraReply bool) error {
			starts = append(starts, struct {
				port       int
				extraReply bool
			}{port: port, extraReply: extraReply})
			return nil
		},
	}

	launcher.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 9000},
		P2P:     servercfg.P2PConfig{ProbeExtraReply: true},
	})

	if !reflect.DeepEqual(checked, []int{9000, 9001, 9002}) {
		t.Fatalf("checked ports = %v, want [9000 9001 9002]", checked)
	}
	if len(starts) != 1 || starts[0].port != 9000 || !starts[0].extraReply {
		t.Fatalf("start calls = %+v, want one launch on 9000 with extraReply=true", starts)
	}
}

func TestP2PProbeLauncherStartSkipsLaunchWhenAnyPortUnavailable(t *testing.T) {
	checked := make([]int, 0, 3)
	launched := false

	launcher := p2pProbeLauncher{
		checkPort: func(port int) bool {
			checked = append(checked, port)
			return port != 9101
		},
		start: func(int, bool) error {
			launched = true
			return nil
		},
	}

	launcher.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 9100},
	})

	if !reflect.DeepEqual(checked, []int{9100, 9101, 9102}) {
		t.Fatalf("checked ports = %v, want [9100 9101 9102]", checked)
	}
	if launched {
		t.Fatal("launcher should not start when any required port is unavailable")
	}
}

func TestP2PProbeLauncherStartSkipsNilAndDisabledConfigs(t *testing.T) {
	launches := 0
	launcher := p2pProbeLauncher{
		checkPort: func(int) bool { return true },
		start: func(int, bool) error {
			launches++
			return nil
		},
	}

	launcher.Start(nil)
	launcher.Start(&servercfg.Snapshot{})

	if launches != 0 {
		t.Fatalf("launches = %d, want 0", launches)
	}
}

func TestP2PProbeLauncherStartSkipsWhenStartHookMissing(t *testing.T) {
	checks := 0
	p2pProbeLauncher{
		checkPort: func(int) bool {
			checks++
			return true
		},
	}.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 9300},
	})

	if checks != 0 {
		t.Fatalf("checks = %d, want 0 when start hook is missing", checks)
	}
}

func TestP2PProbeLauncherStartSkipsInvalidBasePortRange(t *testing.T) {
	checks := 0
	launches := 0
	launcher := p2pProbeLauncher{
		checkPort: func(int) bool {
			checks++
			return true
		},
		start: func(int, bool) error {
			launches++
			return nil
		},
	}

	launcher.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 65534},
	})
	launcher.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 70000},
	})

	if checks != 0 {
		t.Fatalf("checks = %d, want 0", checks)
	}
	if launches != 0 {
		t.Fatalf("launches = %d, want 0", launches)
	}
}

func TestP2PProbeLauncherStartSkipsSuccessPathWhenStartFails(t *testing.T) {
	launches := 0

	launcher := p2pProbeLauncher{
		checkPort: func(int) bool { return true },
		start: func(int, bool) error {
			launches++
			return errors.New("bootstrap failed")
		},
	}

	launcher.Start(&servercfg.Snapshot{
		Network: servercfg.NetworkConfig{P2PPort: 9200},
	})

	if launches != 1 {
		t.Fatalf("launches = %d, want 1", launches)
	}
}

func TestHTTPHostRuntimeLauncherStartBuildsAndStartsTask(t *testing.T) {
	var started *file.Tunnel

	if err := (httpHostRuntimeLauncher{
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 7, Mode: "httpHostServer", Status: true}
		},
		start: func(task *file.Tunnel) error {
			started = task
			return nil
		},
	}).Start(); err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}

	if started == nil || started.Id != 7 || started.Mode != "httpHostServer" || !started.Status {
		t.Fatalf("Start() task = %+v, want httpHost runtime task", started)
	}
}

func TestHTTPHostRuntimeLauncherStartReturnsStartError(t *testing.T) {
	wantErr := errors.New("start failed")

	err := httpHostRuntimeLauncher{
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 8, Mode: "httpHostServer", Status: true}
		},
		start: func(*file.Tunnel) error {
			return wantErr
		},
	}.Start()

	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestWebRuntimeLauncherStartBuildsStartsAndPublishesService(t *testing.T) {
	service := &stubServerService{}
	published := make([]int, 0, 1)
	cache := index.NewAnyIntIndex()
	httpCfg := connection.HTTPRuntimeConfig{Port: 80, HTTPSPort: 443, HTTP3Port: 8443}
	gotDeps := taskModeDependencies{}
	var gotTask *file.Tunnel

	webRuntimeLauncher{
		modeRuntime: taskModeRuntime{
			currentHTTP: func() connection.HTTPRuntimeConfig { return httpCfg },
			proxyCache:  func() *index.AnyIntIndex { return cache },
			newMode: func(deps taskModeDependencies, task *file.Tunnel) proxy.Service {
				gotDeps = deps
				gotTask = task
				return service
			},
		},
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 9, Mode: "webServer"}
		},
		publish: func(id int, _ proxy.Service) {
			published = append(published, id)
		},
	}.Start(true)

	if gotDeps.HTTP != httpCfg {
		t.Fatalf("newService http deps = %+v, want %+v", gotDeps.HTTP, httpCfg)
	}
	if gotDeps.ProxyCache != cache {
		t.Fatalf("newService cache deps = %+v, want %+v", gotDeps.ProxyCache, cache)
	}
	if gotTask == nil || gotTask.Id != 9 || gotTask.Mode != "webServer" {
		t.Fatalf("newService task = %+v, want web runtime task", gotTask)
	}
	if !reflect.DeepEqual(published, []int{9}) {
		t.Fatalf("publish ids = %v, want [9]", published)
	}
}

func TestWebRuntimeLauncherStartSkipsPublishWhenServiceStartErrors(t *testing.T) {
	service := &failingLaunchService{}
	published := make([]int, 0, 1)

	webRuntimeLauncher{
		modeRuntime: taskModeRuntime{
			newMode: func(taskModeDependencies, *file.Tunnel) proxy.Service {
				return service
			},
		},
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 12, Mode: "webServer"}
		},
		publish: func(id int, _ proxy.Service) {
			published = append(published, id)
		},
	}.Start(true)

	if service.startCalls != 1 {
		t.Fatalf("Start() calls = %d, want 1", service.startCalls)
	}
	if service.closeCalls != 1 {
		t.Fatalf("Close() calls = %d, want 1", service.closeCalls)
	}
	if len(published) != 0 {
		t.Fatalf("publish ids = %v, want none after start failure", published)
	}
}

func TestWebRuntimeLauncherStartSkipsDisabledAndNilService(t *testing.T) {
	published := false

	webRuntimeLauncher{
		modeRuntime: taskModeRuntime{
			newMode: func(taskModeDependencies, *file.Tunnel) proxy.Service {
				return nil
			},
		},
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 13, Mode: "webServer"}
		},
		publish: func(int, proxy.Service) {
			published = true
		},
	}.Start(false)

	webRuntimeLauncher{
		modeRuntime: taskModeRuntime{
			newMode: func(taskModeDependencies, *file.Tunnel) proxy.Service {
				return nil
			},
		},
		newTask: func() *file.Tunnel {
			return &file.Tunnel{Id: 14, Mode: "webServer"}
		},
		publish: func(int, proxy.Service) {
			published = true
		},
	}.Start(true)

	if published {
		t.Fatal("publish should not run for disabled launcher or nil service")
	}
}

func TestWebRuntimeLauncherStartSkipsNilTask(t *testing.T) {
	builtService := false
	published := false

	webRuntimeLauncher{
		modeRuntime: taskModeRuntime{
			newMode: func(taskModeDependencies, *file.Tunnel) proxy.Service {
				builtService = true
				return &stubServerService{}
			},
		},
		newTask: func() *file.Tunnel {
			return nil
		},
		publish: func(int, proxy.Service) {
			published = true
		},
	}.Start(true)

	if builtService {
		t.Fatal("newMode should not run when newTask returns nil")
	}
	if published {
		t.Fatal("publish should not run when newTask returns nil")
	}
}

type failingLaunchService struct {
	startCalls int
	closeCalls int
}

func (s *failingLaunchService) Start() error {
	s.startCalls++
	return errors.New("start failed")
}

func (s *failingLaunchService) Close() error {
	s.closeCalls++
	return nil
}
