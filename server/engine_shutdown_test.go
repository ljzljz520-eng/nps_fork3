package server

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// resetEngineShutdownState swaps in fresh engine shutdown globals for the
// test and restores the previous state on cleanup.
func resetEngineShutdownState(t *testing.T) {
	t.Helper()
	oldStop := engineStop
	oldRan := engineShutdownRan
	oldErr := engineShutdownErr
	oldEventFlush := eventWriterFlush

	engineStop = newEngineStopSignals()
	engineShutdownRan = false
	engineShutdownErr = nil
	eventWriterFlush = nil

	t.Cleanup(func() {
		engineStop = oldStop
		engineShutdownRan = oldRan
		engineShutdownErr = oldErr
		eventWriterFlush = oldEventFlush
	})
}

// Concurrent ShutdownServerEngine calls must not deadlock; all callers share
// the first orchestration result.
func TestShutdownServerEngineConcurrentIdempotent(t *testing.T) {
	resetServerTestDB(t)
	resetEngineShutdownState(t)

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
			errs[i] = ShutdownServerEngine(ctx)
		}(i)
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("concurrent ShutdownServerEngine calls deadlocked")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("ShutdownServerEngine caller %d error = %v, want nil", i, err)
		}
	}
}

// A bounded writer flush that cannot finish in time must fail the shutdown
// with an explicit error (never exit silently), within the caller's deadline.
func TestShutdownServerEngineReportsFlushFailureAndIsBounded(t *testing.T) {
	resetServerTestDB(t)
	resetEngineShutdownState(t)

	RegisterEventWriterFlush(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := ShutdownServerEngine(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ShutdownServerEngine() error = nil, want explicit flush failure")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("ShutdownServerEngine took %v, want strict bound near ctx deadline", elapsed)
	}
}

// Background loops that only stop on the engine stop channel must be fully
// reclaimed after shutdown.
func TestShutdownServerEngineStopsBackgroundLoops(t *testing.T) {
	resetServerTestDB(t)
	resetEngineShutdownState(t)

	started := make(chan struct{})
	wrapped := wrapBackgroundLoopStart(func() {
		close(started)
		<-engineStop.stop()
	})
	wrapped()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("background loop did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ShutdownServerEngine(ctx); err != nil {
		t.Fatalf("ShutdownServerEngine() error = %v, want nil", err)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := waitEngineWG(waitCtx, &engineBackgroundWG); err != nil {
		t.Fatalf("background loop goroutines not reclaimed after shutdown: %v", err)
	}
}

// A synthetic termination signal triggers the bounded engine shutdown and
// unregisters the signal subscription afterwards.
func TestInstallShutdownSignalHandlerTriggersShutdown(t *testing.T) {
	resetServerTestDB(t)
	resetEngineShutdownState(t)

	sigCh := make(chan os.Signal, 1)
	stopCalled := make(chan struct{})
	oldNotify := notifyEngineSignals
	notifyEngineSignals = func() (<-chan os.Signal, func()) {
		return sigCh, func() { close(stopCalled) }
	}
	t.Cleanup(func() { notifyEngineSignals = oldNotify })

	finished := InstallShutdownSignalHandler(5 * time.Second)
	sigCh <- syscall.SIGTERM

	select {
	case <-finished:
	case <-time.After(6 * time.Second):
		t.Fatal("signal handler did not finish the engine shutdown")
	}
	select {
	case <-stopCalled:
	case <-time.After(time.Second):
		t.Fatal("signal subscription should be stopped after shutdown")
	}
}
