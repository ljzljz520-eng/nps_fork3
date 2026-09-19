package goroutine

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/logs"
	"github.com/panjf2000/ants/v2"
)

const httpProbePrefixLimit = 8

var (
	httpResponsePrefix  = []byte("HTTP/")
	httpRequestPrefixes = [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("PATCH "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
	}
)

type connGroup struct {
	src    io.ReadWriteCloser
	dst    io.ReadWriteCloser
	wg     *sync.WaitGroup
	n      *int64
	flows  []*file.Flow
	task   *file.Tunnel
	remote string
	close  func()
}

func newConnGroup(dst, src io.ReadWriteCloser, wg *sync.WaitGroup, n *int64, flows []*file.Flow, task *file.Tunnel, remote string) connGroup {
	return connGroup{
		src:    src,
		dst:    dst,
		wg:     wg,
		n:      n,
		flows:  flows,
		task:   task,
		remote: remote,
	}
}

func CopyBuffer(dst io.Writer, src io.Reader, flows []*file.Flow, task *file.Tunnel, remote string) (written int64, err error) {
	buf := common.BufPoolCopy.Get()
	defer common.BufPoolCopy.Put(buf)

	checkedHTTP := task == nil
	var httpProbe [httpProbePrefixLimit]byte
	httpProbeUsed := 0

	for {
		nr, er := src.Read(buf)

		if nr > 0 && !checkedHTTP {
			httpProbeUsed += copy(httpProbe[httpProbeUsed:], buf[:nr])
			checkedHTTP = resolveHTTPProbe(task, httpProbe[:httpProbeUsed], buf[:nr], remote)
		}

		if er == nil || nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if len(flows) > 0 {
					nw64 := int64(nw)
					for _, f := range flows {
						if f == nil {
							continue
						}
						f.Add(nw64, nw64)
					}
				}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			err = er
			break
		}
	}

	return written, err
}

func resolveHTTPProbe(task *file.Tunnel, prefix, sample []byte, remote string) bool {
	if task == nil {
		return true
	}
	switch {
	case prefixHasToken(prefix, httpResponsePrefix):
		task.IsHttp = true
		return true
	case prefixHasAnyToken(prefix, httpRequestPrefixes):
		task.IsHttp = true
		logHTTPRequestSample(sample, task, remote)
		return true
	case len(prefix) >= httpProbePrefixLimit, !prefixCouldMatchHTTP(prefix):
		return true
	default:
		return false
	}
}

func prefixHasToken(prefix, token []byte) bool {
	return len(prefix) >= len(token) && bytes.Equal(prefix[:len(token)], token)
}

func prefixHasAnyToken(prefix []byte, tokens [][]byte) bool {
	for _, token := range tokens {
		if prefixHasToken(prefix, token) {
			return true
		}
	}
	return false
}

func prefixCouldMatchHTTP(prefix []byte) bool {
	if len(prefix) == 0 {
		return true
	}
	if len(prefix) < len(httpResponsePrefix) && bytes.Equal(httpResponsePrefix[:len(prefix)], prefix) {
		return true
	}
	for _, token := range httpRequestPrefixes {
		if len(prefix) < len(token) && bytes.Equal(token[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func logHTTPRequestSample(sample []byte, task *file.Tunnel, remote string) {
	first, rest, ok := cutHTTPLine(sample)
	if !ok {
		return
	}
	second, _, ok := cutHTTPLine(rest)
	if !ok {
		return
	}
	target := ""
	if task.Target != nil {
		target = task.Target.TargetStr
	}
	logs.Info("HTTP Request method %s, %s, remote address %s, target %s", string(first), string(second), remote, target)
}

func cutHTTPLine(sample []byte) (line []byte, rest []byte, ok bool) {
	i := bytes.IndexByte(sample, '\n')
	if i < 0 {
		return nil, nil, false
	}
	line = bytes.TrimRight(sample[:i], "\r")
	return line, sample[i+1:], len(line) > 0
}

func copyConnGroup(group interface{}) {
	cg, ok := group.(connGroup)
	if !ok {
		return
	}

	if cg.wg != nil {
		defer cg.wg.Done()
	}
	defer func() {
		if cg.close != nil {
			cg.close()
			return
		}
		_ = cg.src.Close()
		_ = cg.dst.Close()
	}()

	written, _ := CopyBuffer(cg.dst, cg.src, cg.flows, cg.task, cg.remote)
	if cg.n != nil {
		*cg.n = written
	}
}

type Conns struct {
	conn1 io.ReadWriteCloser // mux connection
	conn2 net.Conn           // outside connection
	flows []*file.Flow       // support multiple flows
	wg    *sync.WaitGroup
	task  *file.Tunnel
}

func NewConns(c1 io.ReadWriteCloser, c2 net.Conn, flows []*file.Flow, wg *sync.WaitGroup, task *file.Tunnel) Conns {
	return Conns{
		conn1: c1,
		conn2: c2,
		flows: flows,
		wg:    wg,
		task:  task,
	}
}

func copyConns(group interface{}) {
	conns := group.(Conns)
	defer func() {
		if conns.wg != nil {
			conns.wg.Done()
		}
	}()

	wg := new(sync.WaitGroup)
	wg.Add(2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = conns.conn1.Close()
			_ = conns.conn2.Close()
		})
	}

	var in, out int64
	remoteAddr := ""
	if ra := conns.conn2.RemoteAddr(); ra != nil {
		remoteAddr = ra.String()
	}

	groupIn := newConnGroup(conns.conn1, conns.conn2, wg, &in, conns.flows, conns.task, remoteAddr)
	groupIn.close = closeBoth
	if err := connCopyPool.Invoke(groupIn); err != nil {
		logs.Error("connCopyPool.Invoke failed: %v", err)
		closeBoth()
		wg.Done()
	}
	groupOut := newConnGroup(conns.conn2, conns.conn1, wg, &out, conns.flows, nil, remoteAddr)
	groupOut.close = closeBoth
	if err := connCopyPool.Invoke(groupOut); err != nil {
		logs.Error("connCopyPool.Invoke failed: %v", err)
		closeBoth()
		wg.Done()
	}

	wg.Wait()
	if conns.task != nil && conns.task.Flow != nil {
		conns.task.Flow.Sub(out, in)
	}
}

var connCopyPool, _ = ants.NewPoolWithFunc(200000, copyConnGroup, ants.WithNonblocking(false))
var CopyConnsPool, _ = ants.NewPoolWithFunc(100000, copyConns, ants.WithNonblocking(false))

func Join(c1, c2 net.Conn, flows []*file.Flow, task *file.Tunnel, remote string) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = c1.Close()
			_ = c2.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// c2 -> c1
	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = CopyBuffer(c1, c2, flows, nil, remote)
	}()

	// c1 -> c2
	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = CopyBuffer(c2, c1, flows, task, remote)
	}()

	wg.Wait()
}
