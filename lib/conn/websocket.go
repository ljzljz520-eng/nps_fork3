package conn

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/djylb/nps/lib/common"
	"github.com/gorilla/websocket"
)

const (
	maxWebsocketMessageSize = 1 << 20
	websocketMaxHeaderBytes = 32 << 10
)

type WsConn struct {
	*websocket.Conn
	RealIP    string
	readFrame io.Reader
	writeMu   sync.Mutex
}

func NewWsConn(ws *websocket.Conn) *WsConn {
	return &WsConn{Conn: ws}
}

func (c *WsConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}

	for {
		if c.readFrame == nil {
			mt, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if mt == websocket.CloseMessage {
				return 0, io.EOF
			}
			c.readFrame = r
		}

		n, err := c.readFrame.Read(p)
		switch {
		case n > 0 && err == io.EOF:
			c.readFrame = nil
			return n, nil
		case n > 0:
			return n, err
		case err == io.EOF:
			c.readFrame = nil
			continue
		default:
			return 0, err
		}
	}
}

func (c *WsConn) Write(p []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	w, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, err := writeAllCount(w, p)
	if err != nil {
		_ = w.Close()
		return n, err
	}
	if err := w.Close(); err != nil {
		return n, err
	}
	return n, nil
}

func (c *WsConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	// Gorilla's Close closes the TCP connection without a close frame, which
	// peers observe as an abnormal closure (1006). Send a normal close frame
	// under a bounded deadline first; WriteControl is safe on a closed conn.
	_ = c.Conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	return c.Conn.Close()
}

func (c *WsConn) LocalAddr() net.Addr {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.NetConn().LocalAddr()
}

func (c *WsConn) RemoteAddr() net.Addr {
	if c == nil || c.Conn == nil {
		return nil
	}
	if c.RealIP != "" {
		if ip := net.ParseIP(c.RealIP); ip != nil {
			return &net.TCPAddr{
				IP:   ip,
				Port: 0,
			}
		}
	}
	return c.Conn.NetConn().RemoteAddr()
}

func (c *WsConn) GetRawConn() net.Conn {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.NetConn()
}

func (c *WsConn) SetDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	_ = c.Conn.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *WsConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *WsConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.Conn == nil {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(t)
}

type httpListener struct {
	acceptCh  chan net.Conn
	closeCh   chan struct{}
	addr      net.Addr
	closeOnce sync.Once
}

func NewWSListener(base net.Listener, path, trustedIps, realIpHeader string) net.Listener {
	ch := make(chan net.Conn, 16)
	hl := &httpListener{acceptCh: ch, closeCh: make(chan struct{}), addr: base.Addr()}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	if path == "" {
		path = "/"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hl.closeCh:
			return
		default:
		}
		realIP := GetRealIP(r, realIpHeader)
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := NewWsConn(ws)
		if common.IsTrustedProxy(trustedIps, r.RemoteAddr) {
			c.RealIP = realIP
		}
		_ = hl.enqueue(c)
	})
	srv := newWebsocketServer(mux, nil)
	go func() { _ = srv.Serve(base) }()
	go func() {
		<-hl.closeCh
		_ = srv.Close()
	}()
	return hl
}

func NewWSSListener(base net.Listener, path string, cert tls.Certificate, trustedIps, realIpHeader string) net.Listener {
	ch := make(chan net.Conn, 16)
	hl := &httpListener{acceptCh: ch, closeCh: make(chan struct{}), addr: base.Addr()}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	if path == "" {
		path = "/"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hl.closeCh:
			return
		default:
		}
		realIP := GetRealIP(r, realIpHeader)
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := NewWsConn(ws)
		if common.IsTrustedProxy(trustedIps, r.RemoteAddr) {
			c.RealIP = realIP
		}
		_ = hl.enqueue(c)
	})
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv := newWebsocketServer(mux, tlsConfig)
	go func() { _ = srv.Serve(tls.NewListener(base, tlsConfig)) }()
	go func() {
		<-hl.closeCh
		_ = srv.Close()
	}()
	return hl
}

func (hl *httpListener) Accept() (net.Conn, error) {
	select {
	case <-hl.closeCh:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-hl.acceptCh:
		return c, nil
	case <-hl.closeCh:
		return nil, net.ErrClosed
	}
}

func (hl *httpListener) Close() error {
	hl.closeOnce.Do(func() {
		close(hl.closeCh)
		for {
			select {
			case c := <-hl.acceptCh:
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

func (hl *httpListener) Addr() net.Addr {
	return hl.addr
}

func (hl *httpListener) enqueue(c net.Conn) error {
	if hl == nil {
		if c != nil {
			_ = c.Close()
		}
		return net.ErrClosed
	}
	return enqueueListenerConn(hl.closeCh, hl.acceptCh, c)
}

func DialWS(rawConn net.Conn, urlStr, host string, timeout time.Duration) (*websocket.Conn, *http.Response, error) {
	return DialWSContext(context.Background(), rawConn, urlStr, host, timeout)
}

func DialWSContext(parent context.Context, rawConn net.Conn, urlStr, host string, timeout time.Duration) (*websocket.Conn, *http.Response, error) {
	return dialWebsocketContext(parent, rawConn, urlStr, host, timeout, nil)
}

func DialWSS(rawConn net.Conn, urlStr, host, sni string, timeout time.Duration, verifyCertificate bool) (*websocket.Conn, *http.Response, error) {
	return DialWSSContext(context.Background(), rawConn, urlStr, host, sni, timeout, verifyCertificate)
}

func DialWSSContext(parent context.Context, rawConn net.Conn, urlStr, host, sni string, timeout time.Duration, verifyCertificate bool) (*websocket.Conn, *http.Response, error) {
	tlsConfig := newTLSClientConfig(websocketTLSServerName(urlStr, host, sni), verifyCertificate)
	return dialWebsocketContext(parent, rawConn, urlStr, host, timeout, tlsConfig)
}

func dialWebsocketContext(parent context.Context, rawConn net.Conn, urlStr, host string, timeout time.Duration, tlsConfig *tls.Config) (*websocket.Conn, *http.Response, error) {
	if rawConn == nil {
		return nil, nil, net.ErrClosed
	}
	if parent == nil {
		parent = context.Background()
	}
	timeout = normalizeLinkTimeout(timeout)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = rawConn.Close()
		}
	}()
	h := http.Header{}
	if host != "" {
		h.Set("Host", host)
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		TLSClientConfig:  tlsConfig,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rawConn, nil
		},
	}
	wsConn, resp, err := dialer.DialContext(ctx, urlStr, h)
	if err != nil {
		return nil, resp, err
	}
	closeOnError = false
	return wsConn, resp, nil
}

func newWebsocketServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	timeout := normalizeLinkTimeout(0)
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: timeout,
		IdleTimeout:       2 * timeout,
		MaxHeaderBytes:    websocketMaxHeaderBytes,
	}
}

func websocketTLSServerName(urlStr, host, sni string) string {
	for _, candidate := range []string{sni, host, websocketURLHost(urlStr)} {
		if candidate == "" {
			continue
		}
		return common.RemovePortFromHost(candidate)
	}
	return ""
}

func websocketURLHost(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}
	host := parsed.Hostname()
	if host != "" {
		return host
	}
	return parsed.Host
}

func (c *WsConn) String() string {
	if c == nil || c.Conn == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ws(%s->%s)", c.LocalAddr(), c.RemoteAddr())
}
