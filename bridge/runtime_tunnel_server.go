package bridge

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/nps/lib/conn"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/mux"
	"github.com/quic-go/quic-go"
)

var bridgeVisitorRuntimeIdleTimeout = 30 * time.Second

func normalizeBridgeRuntimeTunnel(tunnel any) any {
	switch t := tunnel.(type) {
	case *mux.Mux:
		if t == nil {
			return nil
		}
	case *quic.Conn:
		if t == nil {
			return nil
		}
	}
	return tunnel
}

func bridgeRuntimeTunnelClosed(tunnel any) bool {
	tunnel = normalizeBridgeRuntimeTunnel(tunnel)
	if tunnel == nil {
		return true
	}
	switch t := tunnel.(type) {
	case *mux.Mux:
		return t.IsClosed()
	case *quic.Conn:
		return t.Context().Err() != nil
	default:
		return true
	}
}

func closeBridgeRuntimeTunnel(tunnel any, err string) error {
	tunnel = normalizeBridgeRuntimeTunnel(tunnel)
	switch t := tunnel.(type) {
	case *mux.Mux:
		return t.Close()
	case *quic.Conn:
		return t.CloseWithError(0, err)
	default:
		return nil
	}
}

func tunnelCloseReason(v any) string {
	switch t := normalizeBridgeRuntimeTunnel(v).(type) {
	case *mux.Mux:
		return t.CloseReason()
	case *quic.Conn:
		if err := t.Context().Err(); err != nil {
			return err.Error()
		}
	}
	return ""
}

func (s *Bridge) handleTunnelWork(c *conn.Conn, id, ver int, vs, tunnelType string, authKind bridgeAuthKind, uuid string, addr net.Addr, first bool) {
	anyConn, ok := s.openRuntimeTunnelWork(c, ver, tunnelType, addr, first)
	if !ok {
		return
	}
	node, client := s.attachTunnelNode(id, ver, vs, uuid, anyConn)
	if ver > 4 {
		s.sessionGo(func() {
			s.serveTunnelRuntime(anyConn, c, id, ver, vs, tunnelType, authKind, uuid, addr, client, node)
		})
	}
}

func (s *Bridge) handleVisitorWork(c *conn.Conn, id, ver int, vs, tunnelType string, authKind bridgeAuthKind, addr net.Addr, first bool) {
	anyConn, ok := s.openRuntimeTunnelWork(c, ver, tunnelType, addr, first)
	if !ok {
		return
	}
	s.sessionGo(func() {
		s.serveVisitorRuntime(anyConn, c, id, ver, vs, tunnelType, authKind, addr)
	})
}

func (s *Bridge) buildRuntimeTunnelConn(c *conn.Conn, ver int, tunnelType string) (any, bool) {
	if c == nil || c.Conn == nil {
		return nil, false
	}
	if qc, ok := c.Conn.(*conn.QuicAutoCloseConn); ok && ver > 4 {
		sess := normalizeBridgeRuntimeTunnel(qc.GetSession())
		if sess == nil {
			return nil, false
		}
		return sess, true
	}
	mx := normalizeBridgeRuntimeTunnel(mux.NewMux(c.Conn, tunnelType, s.DisconnectTimeout(), false))
	if mx == nil {
		return nil, false
	}
	return mx, true
}

func (s *Bridge) openRuntimeTunnelWork(c *conn.Conn, ver int, tunnelType string, addr net.Addr, first bool) (any, bool) {
	if !first {
		logs.Error("Can not create mux more than once")
		if c != nil {
			_ = c.Close()
		}
		return nil, false
	}
	if s == nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, false
	}
	anyConn, ok := s.buildRuntimeTunnelConn(c, ver, tunnelType)
	anyConn = normalizeBridgeRuntimeTunnel(anyConn)
	if !ok || anyConn == nil {
		logs.Warn("Failed to create runtime tunnel for client %v", addr)
		if c != nil {
			_ = c.Close()
		}
		return nil, false
	}
	return anyConn, true
}

func quicRuntimeContext(t *quic.Conn) context.Context {
	if t == nil {
		return context.Background()
	}
	if ctx := t.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func closeVisitorRuntimeOnIdle(anyConn any, c *conn.Conn) {
	if t, ok := normalizeBridgeRuntimeTunnel(anyConn).(*quic.Conn); ok {
		_ = t.CloseWithError(0, "visitor idle timeout")
	}
	if c != nil {
		_ = c.Close()
	}
}

func (s *Bridge) attachTunnelNode(id, ver int, vs, uuid string, anyConn any) (*Node, *Client) {
	node := NewNode(uuid, vs, ver)
	node.AddTunnel(anyConn)
	client := NewClient(id, node)
	client.SetCloseNodeHook(s.notifyCloseNode)
	if existing, loaded := s.loadOrStoreRuntimeClient(id, client); loaded {
		client = existing
		client.SetCloseNodeHook(s.notifyCloseNode)
		client.MarkConnectedNow()
		client.RemoveOfflineNodesExcept(uuid, true)
		if existingNode, ok := client.GetNodeByUUID(uuid); ok {
			node = existingNode
			node.AddTunnel(anyConn)
		} else {
			client.AddNode(node)
		}
	}
	client.MarkConnectedNow()
	return node, client
}

func (s *Bridge) cleanupTunnelRuntimeNode(node *Node, client *Client, anyConn any) int {
	anyConn = normalizeBridgeRuntimeTunnel(anyConn)
	if node == nil || client == nil || anyConn == nil {
		return 0
	}
	if !node.CloseIfTunnelCurrent(anyConn) {
		return 0
	}
	if client.closeAndRemoveNodeIfCurrent(strings.TrimSpace(node.UUID), node) {
		s.removeEmptyRuntimeClient(client.Id, client)
		return 1
	}
	return 0
}

func (s *Bridge) serveTunnelRuntime(anyConn any, c *conn.Conn, id, ver int, vs, tunnelType string, authKind bridgeAuthKind, uuid string, addr net.Addr, client *Client, node *Node) {
	anyConn = normalizeBridgeRuntimeTunnel(anyConn)
	if anyConn == nil {
		if c != nil {
			_ = c.Close()
		}
		return
	}
	defer func() {
		reason := tunnelCloseReason(anyConn)
		if reason != "" {
			logs.Trace("Tunnel connection closed, client %d, remote %v, reason: %s", id, addr, reason)
		} else {
			logs.Trace("Tunnel connection closed, client %d, remote %v", id, addr)
		}
		if c != nil {
			_ = c.Close()
		}
		removed := s.cleanupTunnelRuntimeNode(node, client, anyConn)
		remaining := 0
		if client != nil {
			remaining = client.NodeCount()
		}
		logs.Warn(
			"Disconnect summary event=disconnect_summary role=server client=%d uuid=%s remote=%v removed=%d remaining=%d reason=%q",
			id,
			uuid,
			addr,
			removed,
			remaining,
			reason,
		)
	}()
	switch t := anyConn.(type) {
	case *mux.Mux:
		conn.Accept(t, func(nc net.Conn) {
			if mc, ok := nc.(*mux.Conn); ok {
				mc.SetPriority()
			}

			s.sessionGo(func() {
				s.typeDeal(conn.NewConn(nc), id, ver, vs, tunnelType, authKind, false)
			})
		})
	case *quic.Conn:
		for {
			stream, err := t.AcceptStream(quicRuntimeContext(t))
			if err != nil {
				logs.Trace("QUIC accept stream error: %v", err)
				return
			}
			sc := conn.NewQuicStreamConn(stream, t)
			s.sessionGo(func() {
				s.typeDeal(conn.NewConn(sc), id, ver, vs, tunnelType, authKind, false)
			})
		}
	default:
		logs.Error("Unknown tunnel type")
	}
}

func (s *Bridge) serveVisitorRuntime(anyConn any, c *conn.Conn, id, ver int, vs, tunnelType string, authKind bridgeAuthKind, addr net.Addr) {
	anyConn = normalizeBridgeRuntimeTunnel(anyConn)
	if anyConn == nil {
		if c != nil {
			_ = c.Close()
		}
		return
	}
	idle := NewIdleTimer(bridgeVisitorRuntimeIdleTimeout, func() {
		closeVisitorRuntimeOnIdle(anyConn, c)
	})
	defer func() {
		logs.Trace("Visitor connection closed, client %d, remote %v", id, addr)
		idle.Stop()
		if c != nil {
			_ = c.Close()
		}
	}()
	switch t := anyConn.(type) {
	case *mux.Mux:
		conn.Accept(t, func(nc net.Conn) {
			idle.Inc()
			s.sessionGo(func() {
				s.typeDeal(conn.NewConn(nc).OnClose(func(*conn.Conn) {
					idle.Dec()
				}), id, ver, vs, tunnelType, authKind, false)
			})
		})
	case *quic.Conn:
		for {
			stream, err := t.AcceptStream(quicRuntimeContext(t))
			if err != nil {
				logs.Trace("QUIC accept stream error: %v", err)
				return
			}
			sc := conn.NewQuicStreamConn(stream, t)
			idle.Inc()
			s.sessionGo(func() {
				s.typeDeal(conn.NewConn(sc).OnClose(func(*conn.Conn) {
					idle.Dec()
				}), id, ver, vs, tunnelType, authKind, false)
			})
		}
	default:
		logs.Error("Unknown tunnel type")
	}
}

type IdleTimer struct {
	idle    time.Duration
	closeFn func()
	mu      sync.Mutex
	active  int
	t       *time.Timer
	closed  atomic.Uint32
}

func NewIdleTimer(idle time.Duration, closeFn func()) *IdleTimer {
	it := &IdleTimer{idle: idle, closeFn: closeFn}
	it.t = time.AfterFunc(idle, func() {
		shouldClose := false
		it.mu.Lock()
		if it.active == 0 && it.closed.CompareAndSwap(0, 1) {
			shouldClose = true
		}
		it.mu.Unlock()
		if shouldClose {
			closeFn()
		}
	})
	return it
}

func (it *IdleTimer) Inc() {
	if it.closed.Load() == 1 {
		return
	}
	it.mu.Lock()
	it.active++
	if it.active == 1 {
		_ = it.t.Stop()
	}
	it.mu.Unlock()
}

func (it *IdleTimer) Dec() {
	if it.closed.Load() == 1 {
		return
	}
	it.mu.Lock()
	if it.active > 0 {
		it.active--
		if it.active == 0 && it.closed.Load() == 0 {
			it.t.Reset(it.idle)
		}
	}
	it.mu.Unlock()
}

func (it *IdleTimer) Stop() {
	if it.closed.CompareAndSwap(0, 1) {
		_ = it.t.Stop()
	}
}
