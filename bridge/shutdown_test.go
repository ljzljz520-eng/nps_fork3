package bridge

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/nps/lib/conn"
)

// useBridgeTCPListener enables only the TCP bridge protocol and makes
// bootstrap return tcpListener. Restores all global state on cleanup.
func useBridgeTCPListener(t *testing.T, tcpListener net.Listener) {
	t.Helper()
	originalTCPEnabled := ServerTcpEnable
	originalTLSEnabled := ServerTlsEnable
	originalWsEnabled := ServerWsEnable
	originalWssEnabled := ServerWssEnable
	originalKCPEnabled := ServerKcpEnable
	originalQUICEnabled := ServerQuicEnable
	originalTCPGetter := bridgeGetTCPListener

	ServerTcpEnable = true
	ServerTlsEnable = false
	ServerWsEnable = false
	ServerWssEnable = false
	ServerKcpEnable = false
	ServerQuicEnable = false
	bridgeGetTCPListener = func() (net.Listener, error) { return tcpListener, nil }

	t.Cleanup(func() {
		ServerTcpEnable = originalTCPEnabled
		ServerTlsEnable = originalTLSEnabled
		ServerWsEnable = originalWsEnabled
		ServerWssEnable = originalWssEnabled
		ServerKcpEnable = originalKCPEnabled
		ServerQuicEnable = originalQUICEnabled
		bridgeGetTCPListener = originalTCPGetter
	})
}

// Repeated concurrent Shutdown calls must not deadlock, must not close
// listeners twice, and all callers share the first orchestration result.
func TestBridgeShutdownConcurrentCallsDedup(t *testing.T) {
	resetBridgeConfigTestDB(t)
	tcpListener := &bridgeTestListener{addr: conn.LocalTCPAddr}
	useBridgeTCPListener(t, tcpListener)

	b := NewTunnel(false, &sync.Map{}, 0)
	if err := b.StartTunnel(); err != nil {
		t.Fatalf("StartTunnel() error = %v", err)
	}

	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			errs[i] = b.Shutdown(ctx, 10*time.Millisecond)
		}(i)
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("concurrent Shutdown calls deadlocked")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Shutdown caller %d error = %v, want nil", i, err)
		}
	}
	if got := tcpListener.closeCount.Load(); got != 1 {
		t.Fatalf("tcp listener close count = %d, want exactly 1", got)
	}
	select {
	case <-b.Done():
	case <-time.After(time.Second):
		t.Fatal("Done channel not closed after Shutdown")
	}
}

// Sessions that finish naturally within the grace period are not force-closed.
func TestBridgeShutdownWaitsForSessionsWithinGrace(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	var completed atomic.Bool
	b.sessionGo(func() {
		time.Sleep(50 * time.Millisecond)
		completed.Store(true)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx, time.Second); err != nil {
		t.Fatalf("Shutdown() error = %v, want nil", err)
	}
	if !completed.Load() {
		t.Fatal("shutdown returned before naturally completing session")
	}
}

// A connection still inside intake after the deadline is force-closed so its
// handler returns and the session goroutine is reclaimed.
func TestBridgeShutdownForceClosesTrackedIntakeConn(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	raw, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })

	processing := make(chan struct{})
	intakeDone := make(chan struct{})
	go func() {
		defer close(intakeDone)
		b.intake(raw, func(c net.Conn) {
			close(processing)
			_, _ = c.Read(make([]byte, 1)) // blocks until force-close
		})
	}()

	select {
	case <-processing:
	case <-time.After(2 * time.Second):
		t.Fatal("intake process did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx, 0); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case <-intakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("intake did not return after tracked conn was force-closed")
	}
	if _, err := peer.Write([]byte{1}); err == nil {
		t.Fatal("expected peer write to fail after ordinary force close")
	}
}

// Once shutdown has begun, new intake conns are closed and their process
// function never runs.
func TestBridgeIntakeRejectedAfterShutdown(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	raw, peer := net.Pipe()
	t.Cleanup(func() {
		_ = raw.Close()
		_ = peer.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx, 0); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	ran := false
	b.intake(raw, func(net.Conn) { ran = true })
	if ran {
		t.Fatal("process must not run when shutdown already began")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected peer read error after intake rejected conn")
	}
}

// StartTunnel is rejected once shutdown has blocked new starts.
func TestStartTunnelRejectedAfterShutdown(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx, 0); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := b.StartTunnel(); !errors.Is(err, ErrBridgeShuttingDown) {
		t.Fatalf("StartTunnel() error = %v, want %v", err, ErrBridgeShuttingDown)
	}
}

// A second StartTunnel call while running reports ErrBridgeAlreadyStarted.
func TestStartTunnelTwiceReturnsAlreadyStarted(t *testing.T) {
	resetBridgeConfigTestDB(t)
	tcpListener := &bridgeTestListener{addr: conn.LocalTCPAddr}
	useBridgeTCPListener(t, tcpListener)

	b := NewTunnel(false, &sync.Map{}, 0)
	if err := b.StartTunnel(); err != nil {
		t.Fatalf("first StartTunnel() error = %v", err)
	}
	if err := b.StartTunnel(); !errors.Is(err, ErrBridgeAlreadyStarted) {
		t.Fatalf("second StartTunnel() error = %v, want %v", err, ErrBridgeAlreadyStarted)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Shutdown(ctx, 0); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

// A panic in a session or loop sub-runtime is recovered; it neither crashes
// the process nor wedges the WaitGroups, so Shutdown still completes.
func TestSubRuntimePanicRecoveredAndDoesNotWedgeShutdown(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	release := make(chan struct{})
	started := make(chan struct{}, 2)

	b.sessionGo(func() {
		started <- struct{}{}
		<-release
		panic("boom session")
	})
	b.loopGo(func() {
		started <- struct{}{}
		<-release
		panic("boom loop")
	})
	<-started
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- b.Shutdown(ctx, 100*time.Millisecond) }()

	// Release the panicking runtimes only after the grace window elapsed,
	// while Shutdown is waiting on the groups, proving recovery drains them.
	time.Sleep(250 * time.Millisecond)
	close(release)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown() error = %v, want nil after panic recovery", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown wedged after sub-runtime panic")
	}
}

// Shutdown requested while bootstrap is only half-way through must not
// deadlock: the slow bootstrap unblocks once shutdown begins and StartTunnel
// returns its error; Shutdown still completes cleanly.
func TestShutdownDuringHalfStartedBootstrapDoesNotDeadlock(t *testing.T) {
	resetBridgeConfigTestDB(t)
	tcpListener := &bridgeTestListener{addr: conn.LocalTCPAddr}
	useBridgeTCPListener(t, tcpListener)

	b := NewTunnel(false, &sync.Map{}, 0)
	bridgeGetTCPListener = func() (net.Listener, error) {
		select {
		case <-b.shutdownCh:
			return nil, errors.New("bootstrap aborted by shutdown")
		case <-time.After(5 * time.Second):
			return nil, errors.New("unexpected bootstrap timeout")
		}
	}

	startErr := make(chan error, 1)
	go func() { startErr <- b.StartTunnel() }()
	time.Sleep(100 * time.Millisecond) // let StartTunnel enter the blocked getter

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- b.Shutdown(ctx, 0) }()

	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("StartTunnel() should return the bootstrap error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartTunnel deadlocked during shutdown")
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown deadlocked during half-started bootstrap")
	}
	if got := tcpListener.closeCount.Load(); got != 0 {
		t.Fatalf("never-adopted listener was closed, count=%d", got)
	}
}

// When the caller's context deadline is reached, Shutdown returns within a
// strict upper bound even if some sessions cannot finish.
func TestBridgeShutdownBoundedByContext(t *testing.T) {
	b := NewTunnel(false, &sync.Map{}, 0)
	b.sessionGo(func() { select {} }) // never returns

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := b.Shutdown(ctx, 5*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Shutdown() error = nil, want non-nil after ctx deadline")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v, want strict bound near the ctx deadline", elapsed)
	}
}
