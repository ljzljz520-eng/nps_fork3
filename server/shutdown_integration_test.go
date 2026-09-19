package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/client"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/server/connection"
	"github.com/gorilla/websocket"
	quic "github.com/quic-go/quic-go"
)

func freeTestTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("probe free tcp port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("FD accounting unavailable: %v", err)
	}
	return len(entries)
}

// applyTestBridgeNetwork points bridge TCP/WS/QUIC listeners at loopback
// ports chosen by the test and restores the previous global state.
func applyTestBridgeNetwork(t *testing.T, tcpPort, wsPort, quicPort int) {
	t.Helper()
	oldTCPIP, oldTCPPort := connection.BridgeTcpIp, connection.BridgeTcpPort
	oldWSIP, oldWSPort := connection.BridgeWsIp, connection.BridgeWsPort
	oldQUICIP, oldQUICPort := connection.BridgeQuicIp, connection.BridgeQuicPort
	oldPath := connection.BridgePath
	oldALPN := append([]string(nil), connection.QuicAlpn...)

	connection.BridgeTcpIp, connection.BridgeTcpPort = "127.0.0.1", tcpPort
	connection.BridgeWsIp, connection.BridgeWsPort = "127.0.0.1", wsPort
	connection.BridgeQuicIp, connection.BridgeQuicPort = "127.0.0.1", quicPort
	connection.BridgePath = "/bridge"
	connection.QuicAlpn = []string{"nps"}

	t.Cleanup(func() {
		connection.BridgeTcpIp, connection.BridgeTcpPort = oldTCPIP, oldTCPPort
		connection.BridgeWsIp, connection.BridgeWsPort = oldWSIP, oldWSPort
		connection.BridgeQuicIp, connection.BridgeQuicPort = oldQUICIP, oldQUICPort
		connection.BridgePath = oldPath
		connection.QuicAlpn = oldALPN
	})
}

func isTimeoutError(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) || os.IsTimeout(err)
}

// isOrdinaryDisconnect reports a normal close: EOF / closed listener,
// WebSocket normal closure (1000), or QUIC application/stream error code 0.
// A TCP RST would surface as a connection-reset error and is not accepted.
func isOrdinaryDisconnect(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var wsClose *websocket.CloseError
	if errors.As(err, &wsClose) && wsClose.Code == websocket.CloseNormalClosure {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
		return true
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) && streamErr.ErrorCode == 0 {
		return true
	}
	return false
}

// End-to-end: a running bridge with real TCP, WebSocket and QUIC old clients.
// On Stop, new intake is rejected immediately, existing sessions survive the
// grace period, are force-closed with an ordinary disconnect afterwards, all
// goroutines/FDs are reclaimed, and every port is rebindable at once.
func TestServerGracefulShutdownIntegration(t *testing.T) {
	resetServerTestDB(t)
	resetEngineShutdownState(t)
	crypt.InitTls(tls.Certificate{})

	tcpPort := freeTestTCPPort(t)
	wsPort := freeTestTCPPort(t)
	quicPort := freeTestTCPPort(t)
	applyTestBridgeNetwork(t, tcpPort, wsPort, quicPort)

	oldTCP, oldWS, oldQUIC := bridge.ServerTcpEnable, bridge.ServerWsEnable, bridge.ServerQuicEnable
	bridge.ServerTcpEnable = true
	bridge.ServerWsEnable = true
	bridge.ServerQuicEnable = true
	t.Cleanup(func() {
		bridge.ServerTcpEnable = oldTCP
		bridge.ServerWsEnable = oldWS
		bridge.ServerQuicEnable = oldQUIC
	})

	vkey := "shutdown-integration-vkey"
	dbClient := file.NewClient(vkey, false, false)
	if err := file.GetDb().NewClient(dbClient); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	b := bridge.NewTunnel(false, &sync.Map{}, 0)
	oldEngineBridge := Bridge
	Bridge = b
	t.Cleanup(func() { Bridge = oldEngineBridge })

	if err := b.StartTunnel(); err != nil {
		t.Fatalf("StartTunnel() error = %v", err)
	}

	// Baseline with the engine running but no client sessions.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()
	baseFDs := openFDCount(t)

	tcpC, tcpUUID, err := client.NewConn("tcp", vkey, net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)), "", "")
	if err != nil {
		t.Fatalf("tcp client connect error: %v", err)
	}
	if err := client.SendType(tcpC, common.WORK_MAIN, tcpUUID); err != nil {
		t.Fatalf("tcp WORK_MAIN error: %v", err)
	}
	wsC, wsUUID, err := client.NewConn("ws", vkey, net.JoinHostPort("127.0.0.1", strconv.Itoa(wsPort))+"/bridge", "", "")
	if err != nil {
		t.Fatalf("ws client connect error: %v", err)
	}
	if err := client.SendType(wsC, common.WORK_MAIN, wsUUID); err != nil {
		t.Fatalf("ws WORK_MAIN error: %v", err)
	}
	quicC, quicUUID, err := client.NewConn("quic", vkey, net.JoinHostPort("127.0.0.1", strconv.Itoa(quicPort)), "", "")
	if err != nil {
		t.Fatalf("quic client connect error: %v", err)
	}
	if err := client.SendType(quicC, common.WORK_MAIN, quicUUID); err != nil {
		t.Fatalf("quic WORK_MAIN error: %v", err)
	}
	t.Cleanup(func() {
		_ = tcpC.Close()
		_ = wsC.Close()
		_ = quicC.Close()
	})

	// Wait for the server to register all three nodes of the single client.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if value, ok := b.Client.Load(dbClient.Id); ok {
			if runtimeClient, ok := value.(*bridge.Client); ok && runtimeClient != nil && runtimeClient.NodeCount() == 3 {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if value, ok := b.Client.Load(dbClient.Id); !ok {
		t.Fatal("server never registered the connected client")
	} else if runtimeClient, ok := value.(*bridge.Client); !ok || runtimeClient.NodeCount() != 3 {
		t.Fatalf("server registered nodes = %d, want 3", runtimeClient.NodeCount())
	}

	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	goroutinesBefore := runtime.NumGoroutine()
	fdsBefore := openFDCount(t)
	if goroutinesBefore < baseGoroutines || fdsBefore < baseFDs {
		t.Fatalf("connected clients consumed no resources: goroutines %d->%d fds %d->%d",
			baseGoroutines, goroutinesBefore, baseFDs, fdsBefore)
	}

	shutdownResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		shutdownResult <- ShutdownServerEngine(ctx)
	}()
	// On a failing assertion, global-state cleanups must not run while the
	// shutdown goroutine still reads them (LIFO: this runs first).
	t.Cleanup(func() {
		select {
		case <-shutdownResult:
		case <-time.After(10 * time.Second):
		}
	})

	// (a) New intake is rejected on every protocol. QUIC dials take the full
	// handshake timeout on loopback (no ICMP feedback on macOS), so the probes
	// run concurrently with the survival check instead of serially.
	type intakeOutcome struct {
		tp  string
		err error
	}
	intakeResults := make(chan intakeOutcome, 3)
	for _, params := range []struct {
		tp   string
		addr string
	}{
		{"tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort))},
		{"ws", net.JoinHostPort("127.0.0.1", strconv.Itoa(wsPort)) + "/bridge"},
		{"quic", net.JoinHostPort("127.0.0.1", strconv.Itoa(quicPort))},
	} {
		go func(tp, addr string) {
			_, _, err := client.NewConn(tp, vkey, addr, "", "")
			intakeResults <- intakeOutcome{tp: tp, err: err}
		}(params.tp, params.addr)
	}

	// (b) Existing sessions stay up inside the grace window. TCP/QUIC prove
	// it with a bounded read that times out before the force boundary; WS
	// uses a ping round trip because gorilla treats read timeouts as
	// permanent, which would mask the later ordinary close.
	// The intake probes above run concurrently in the background.
	survivalErr := make(chan error, 3)
	var survivalWG sync.WaitGroup
	probeDeadlineRead := func(c *conn.Conn) {
		defer survivalWG.Done()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		survivalErr <- err
		_ = c.SetReadDeadline(time.Time{})
	}
	survivalWG.Add(2)
	go probeDeadlineRead(tcpC)
	go probeDeadlineRead(quicC)
	survivalWG.Add(1)
	go func() {
		defer survivalWG.Done()
		time.Sleep(2 * time.Second)
		if wsConn, ok := wsC.Conn.(*conn.WsConn); !ok {
			survivalErr <- fmt.Errorf("ws transport changed: %T", wsC.Conn)
		} else if err := wsConn.WriteControl(
			websocket.PingMessage, nil, time.Now().Add(2*time.Second)); err != nil {
			survivalErr <- err
		} else {
			survivalErr <- nil
		}
	}()
	survivalWG.Wait()
	close(survivalErr)
	for err := range survivalErr {
		if err != nil && !isTimeoutError(err) {
			t.Fatalf("session ended before the grace window: %v", err)
		}
	}

	// Collect the intake probes: every protocol must have refused the session.
	for i := 0; i < 3; i++ {
		select {
		case outcome := <-intakeResults:
			if outcome.err == nil {
				t.Fatalf("new %s session during shutdown should be rejected", outcome.tp)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("new intake was not rejected within the shutdown bound")
		}
	}

	// (c) After the deadline the same sessions receive an ordinary close.
	type closeOutcome struct {
		name string
		err  error
	}
	closeResults := make(chan closeOutcome, 3)
	go func() {
		probeClose := func(name string, c *conn.Conn) {
			_, err := c.Read(make([]byte, 1))
			closeResults <- closeOutcome{name: name, err: err}
		}
		probeClose("tcp", tcpC)
		probeClose("websocket", wsC)
		probeClose("quic", quicC)
	}()
	for i := 0; i < 3; i++ {
		select {
		case outcome := <-closeResults:
			if !isOrdinaryDisconnect(outcome.err) {
				t.Fatalf("%s after deadline error = %v, want ordinary close (EOF/closed/1000/quic-0)", outcome.name, outcome.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("existing sessions were not force-closed after the grace period")
		}
	}

	// (d) Shutdown itself completed successfully within its bound.
	select {
	case err := <-shutdownResult:
		if err != nil {
			t.Fatalf("ShutdownServerEngine() error = %v, want nil", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ShutdownServerEngine did not return within the strict bound")
	}

	// (e) All ports are immediately rebindable by a fresh process.
	rebindTCP := func(port int) {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatalf("rebind tcp port %d: %v", port, err)
		}
		_ = l.Close()
	}
	rebindTCP(tcpPort)
	rebindTCP(wsPort)
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: quicPort})
	if err != nil {
		if out, lsofErr := exec.Command("lsof", "-nP", "-iUDP:"+strconv.Itoa(quicPort)).CombinedOutput(); lsofErr == nil {
			t.Fatalf("rebind udp port %d: %v\nlsof:\n%s", quicPort, err, out)
		}
		t.Fatalf("rebind udp port %d: %v", quicPort, err)
	}
	_ = uconn.Close()

	// (f) Goroutines and file descriptors return to the engine-off baseline.
	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()
	fdsAfter := openFDCount(t)
	if goroutinesAfter > baseGoroutines+3 {
		t.Fatalf("goroutines after stop = %d, baseline %d (clients peaked at %d)", goroutinesAfter, baseGoroutines, goroutinesBefore)
	}
	if fdsAfter > baseFDs+3 {
		t.Fatalf("FDs after stop = %d, baseline %d (clients peaked at %d)", fdsAfter, baseFDs, fdsBefore)
	}
}
