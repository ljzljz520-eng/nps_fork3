package conn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/djylb/nps/lib/logs"
	"github.com/quic-go/quic-go"
	"github.com/xtaci/kcp-go/v5"
)

var ErrVirtualListenerFull = errors.New("virtual listener queue full")
var virtualListenerEnqueueTimeout = 250 * time.Millisecond

func normalizedVirtualListenerEnqueueTimeout() time.Duration {
	if virtualListenerEnqueueTimeout <= 0 {
		return 250 * time.Millisecond
	}
	return virtualListenerEnqueueTimeout
}

func enqueueListenerConn(closed <-chan struct{}, acceptCh chan net.Conn, c net.Conn) error {
	if c == nil {
		return nil
	}
	select {
	case <-closed:
		_ = c.Close()
		return net.ErrClosed
	default:
	}
	select {
	case <-closed:
		_ = c.Close()
		return net.ErrClosed
	case acceptCh <- c:
		return nil
	default:
	}
	timer := time.NewTimer(normalizedVirtualListenerEnqueueTimeout())
	defer timer.Stop()
	select {
	case <-closed:
		_ = c.Close()
		return net.ErrClosed
	case acceptCh <- c:
		return nil
	case <-timer.C:
		_ = c.Close()
		return ErrVirtualListenerFull
	}
}

func NewTcpListenerAndProcess(addr string, f func(c net.Conn), listener *net.Listener) error {
	var err error
	*listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	Accept(*listener, f)
	return nil
}

func NewKcpListenerAndProcess(addr string, f func(c net.Conn)) error {
	listener, err := NewKcpListener(addr)
	if err != nil {
		return err
	}
	return serveKCPListener(listener, f)
}

// NewKcpListener creates a KCP listener without serving it, so the caller can
// hold the returned listener and close it explicitly during shutdown.
func NewKcpListener(addr string) (*kcp.Listener, error) {
	listener, err := kcp.ListenWithOptions(addr, nil, 10, 3)
	if err != nil {
		logs.Error("KCP listen error: %v", err)
		return nil, err
	}
	return listener, nil
}

type kcpSessionAccepter interface {
	AcceptKCP() (*kcp.UDPSession, error)
}

func serveKCPListener(listener kcpSessionAccepter, f func(c net.Conn)) error {
	return ServeKCP(listener, DefaultSpawn, nil, f)
}

// ServeKCP serves an existing KCP listener. Accepted sessions share the
// listener socket, so it is not closed during graceful shutdown. If reject is
// non-nil and returns true, a freshly accepted session is closed immediately
// and f is not invoked, allowing brand-new sessions to be rejected while
// already-established ones keep running.
func ServeKCP(listener kcpSessionAccepter, spawn HandlerSpawn, reject func() bool, f func(c net.Conn)) error {
	if spawn == nil {
		spawn = DefaultSpawn
	}
	for {
		c, err := listener.AcceptKCP()
		if err != nil {
			if shouldStopKCPAcceptLoop(err) {
				return nil
			}
			logs.Trace("KCP accept session error: %v", err)
			continue
		}
		SetUdpSession(c)
		if reject != nil && reject() {
			_ = c.Close()
			continue
		}
		session := c
		spawn(func() { f(session) })
	}
}

func NewQuicListenerAndProcess(addr string, tlsConfig *tls.Config, quicConfig *quic.Config, f func(c net.Conn)) error {
	runtime, err := NewQuicListener(addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}
	return serveQUICListener(runtime.Listener, f)
}

// QUICListenerRuntime groups a QUIC listener with the transport and UDP
// socket backing it. quic-go ties socket release to transport shutdown, so
// callers must explicitly release the runtime once established connections
// have been closed.
type QUICListenerRuntime struct {
	Listener   *quic.Listener
	Transport  *quic.Transport
	PacketConn *net.UDPConn
}

// NewQuicListener creates a QUIC listener without serving it. Closing
// Listener immediately rejects new connections and cancels in-flight
// handshakes, but does not affect already established connections; the UDP
// socket stays open until Release is called.
func NewQuicListener(addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*QUICListenerRuntime, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logs.Error("QUIC listen resolve error: %v", err)
		return nil, err
	}
	packetConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logs.Error("QUIC listen error: %v", err)
		return nil, err
	}
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(tlsConfig, quicConfig)
	if err != nil {
		_ = packetConn.Close()
		logs.Error("QUIC listener error: %v", err)
		return nil, err
	}
	return &QUICListenerRuntime{
		Listener:   listener,
		Transport:  transport,
		PacketConn: packetConn,
	}, nil
}

// Release shuts down the transport and closes the underlying UDP socket. It
// must be called only after established connections have been closed:
// Transport.Close aborts remaining connections without a QUIC close frame.
// Idempotent.
func (r *QUICListenerRuntime) Release() error {
	if r == nil {
		return nil
	}
	var err error
	if r.Transport != nil {
		err = r.Transport.Close()
		r.Transport = nil
	}
	if r.PacketConn != nil {
		if closeErr := r.PacketConn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		r.PacketConn = nil
	}
	return err
}

func serveQUICListener(listener *quic.Listener, f func(c net.Conn)) error {
	return ServeQUIC(listener, DefaultSpawn, f)
}

// ServeQUIC serves an existing QUIC listener, using spawn to schedule the
// per-connection goroutine so the caller can track it.
func ServeQUIC(listener *quic.Listener, spawn HandlerSpawn, f func(c net.Conn)) error {
	if spawn == nil {
		spawn = DefaultSpawn
	}
	pending := newPendingQUICSessions()
	defer pending.closeAll()

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			if isClosedQUICListenerError(err) {
				return nil
			}
			logs.Warn("QUIC accept session error: %v", err)
			continue
		}
		pending.add(sess)
		conn := sess
		spawn(func() { serveAcceptedQUICSession(conn, pending, f) })
	}
}

func serveAcceptedQUICSession(sess *quic.Conn, pending *pendingQUICSessions, f func(c net.Conn)) {
	stream, err := sess.AcceptStream(quicConnContext(sess))
	if pending != nil {
		pending.remove(sess)
	}
	if err != nil {
		logs.Trace("QUIC accept stream error: %v", err)
		_ = sess.CloseWithError(0, "closed")
		return
	}
	f(NewQuicAutoCloseConn(stream, sess))
}

type pendingQUICSessions struct {
	mu       sync.Mutex
	sessions map[*quic.Conn]struct{}
}

func newPendingQUICSessions() *pendingQUICSessions {
	return &pendingQUICSessions{sessions: make(map[*quic.Conn]struct{})}
}

func (p *pendingQUICSessions) add(sess *quic.Conn) {
	if p == nil || sess == nil {
		return
	}
	p.mu.Lock()
	p.sessions[sess] = struct{}{}
	p.mu.Unlock()
}

func (p *pendingQUICSessions) remove(sess *quic.Conn) {
	if p == nil || sess == nil {
		return
	}
	p.mu.Lock()
	delete(p.sessions, sess)
	p.mu.Unlock()
}

func (p *pendingQUICSessions) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	sessions := make([]*quic.Conn, 0, len(p.sessions))
	for sess := range p.sessions {
		sessions = append(sessions, sess)
	}
	clear(p.sessions)
	p.mu.Unlock()

	for _, sess := range sessions {
		_ = sess.CloseWithError(0, "listener closed")
	}
}

func quicConnContext(sess *quic.Conn) context.Context {
	if sess == nil {
		return context.Background()
	}
	if ctx := sess.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func isClosedQUICListenerError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, quic.ErrServerClosed)
}

func shouldStopKCPAcceptLoop(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "the mux has closed")
}

// HandlerSpawn schedules a connection handler to run asynchronously.
// Implementations MUST perform any WaitGroup.Add() synchronously, before the
// goroutine starts (Add-happens-before-Go), so concurrent Wait callers
// cannot observe a zero counter prematurely.
type HandlerSpawn func(fn func())

// DefaultSpawn runs fn on a new, untracked goroutine.
func DefaultSpawn(fn func()) { go fn() }

// Accept accepts connections from l and invokes f in a new goroutine for each
// connection.
func Accept(l net.Listener, f func(c net.Conn)) {
	AcceptTracked(l, DefaultSpawn, f)
}

// AcceptTracked behaves like Accept but uses spawn to schedule each handler,
// allowing the caller to track (e.g. WaitGroup) handler goroutines.
func AcceptTracked(l net.Listener, spawn HandlerSpawn, f func(c net.Conn)) {
	if l == nil {
		return
	}
	if spawn == nil {
		spawn = DefaultSpawn
	}
	for {
		c, err := l.Accept()
		if err != nil {
			if shouldStopAcceptLoop(err) {
				return
			}
			logs.Warn("%v", err)
			continue
		}
		if c == nil {
			logs.Warn("nil connection")
			return
		}
		conn := c
		spawn(func() { f(conn) })
	}
}

func shouldStopAcceptLoop(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "the mux has closed")
}

type OneConnListener struct {
	conn      net.Conn
	accepted  bool
	closed    bool
	mu        sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

func NewOneConnListener(c net.Conn) *OneConnListener {
	return &OneConnListener{
		conn: c,
		done: make(chan struct{}),
	}
}

func (l *OneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.accepted {
		l.mu.Unlock()
		<-l.done
		return nil, io.EOF
	}
	switch {
	case l.closed:
		l.mu.Unlock()
		return nil, net.ErrClosed
	default:
		if l.conn == nil {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		l.accepted = true
		conn := l.conn
		l.mu.Unlock()
		return conn, nil
	}
}

func (l *OneConnListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		conn := l.conn
		l.mu.Unlock()
		if conn != nil {
			err = conn.Close()
		}
		close(l.done)
	})
	return err
}

func (l *OneConnListener) Addr() net.Addr {
	if l == nil || l.conn == nil {
		return nil
	}
	return l.conn.LocalAddr()
}

type VirtualListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	addr      net.Addr
	closeOnce sync.Once
}

func NewVirtualListener(addr net.Addr) *VirtualListener {
	return newVirtualListenerWithBuffer(addr, 1024)
}

func newVirtualListenerWithBuffer(addr net.Addr, buffer int) *VirtualListener {
	if addr == nil {
		addr = LocalTCPAddr
	}
	if buffer <= 0 {
		buffer = 1
	}
	return &VirtualListener{
		conns:  make(chan net.Conn, buffer),
		closed: make(chan struct{}),
		addr:   addr,
	}
}

func (l *VirtualListener) SetAddr(addr net.Addr) {
	if addr != nil {
		l.addr = addr
	}
}

func (l *VirtualListener) Addr() net.Addr {
	return l.addr
}

func (l *VirtualListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *VirtualListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		for {
			select {
			case c := <-l.conns:
				if c != nil {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (l *VirtualListener) ServeVirtual(c net.Conn) {
	_ = l.enqueueVirtual(c)
}

func (l *VirtualListener) enqueueVirtual(c net.Conn) error {
	return enqueueListenerConn(l.closed, l.conns, c)
}

func (l *VirtualListener) DialVirtual(rAddr string) (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	a, b := net.Pipe()
	remoteAddr, err := parseTCPAddrMaybe(rAddr)
	if err != nil || remoteAddr == nil {
		_ = a.Close()
		_ = b.Close()
		return nil, fmt.Errorf("invalid remote addr %q: %w", rAddr, err)
	}
	c := NewAddrOverrideFromAddr(b, remoteAddr, l.addr)
	if err := l.enqueueVirtual(c); err != nil {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}
