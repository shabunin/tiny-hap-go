//go:build tinygo

package accessory

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// TinyGo has no sockets on Linux: tests connect through pipes, buffered as TCP,
// since server writes events without waiting for controller to read them.

var pipes = struct {
	sync.Mutex
	m map[string]*pipeListener
}{m: map[string]*pipeListener{}}

type pipeListener struct {
	addr  pipeAddr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func listen() (net.Listener, error) {
	pipes.Lock()
	defer pipes.Unlock()
	l := &pipeListener{addr: pipeAddr("pipe" + strconv.Itoa(len(pipes.m))),
		conns: make(chan net.Conn), done: make(chan struct{})}
	pipes.m[string(l.addr)] = l
	return l, nil
}

func dial(addr string) (net.Conn, error) {
	pipes.Lock()
	l := pipes.m[addr]
	pipes.Unlock()
	if l == nil {
		return nil, errors.New("no listener at " + addr)
	}
	a, b := newStream(), newStream()
	c, s := &pipeConn{in: a, out: b, addr: l.addr}, &pipeConn{in: b, out: a, addr: l.addr}
	select {
	case l.conns <- s:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

// stream is one direction of pipe connection.
type stream struct {
	mu     sync.Mutex
	cond   sync.Cond
	data   []byte
	closed bool
}

func newStream() *stream {
	s := &stream{}
	s.cond.L = &s.mu
	return s
}

func (s *stream) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

type pipeConn struct {
	in, out *stream
	addr    pipeAddr

	mu       sync.Mutex
	deadline time.Time // of reads
}

func (c *pipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	s := c.in
	if !d.IsZero() {
		t := time.AfterFunc(time.Until(d), func() {
			s.mu.Lock()
			s.mu.Unlock()
			s.cond.Broadcast()
		})
		defer t.Stop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.data) == 0 {
		if s.closed {
			return 0, io.EOF
		}
		if !d.IsZero() && !time.Now().Before(d) {
			return 0, os.ErrDeadlineExceeded
		}
		s.cond.Wait()
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

func (c *pipeConn) Write(p []byte) (int, error) {
	s := c.out
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, net.ErrClosed
	}
	s.data = append(s.data, p...)
	s.cond.Broadcast()
	return len(p), nil
}

func (c *pipeConn) Close() error {
	c.in.close()
	c.out.close()
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.addr }
func (c *pipeConn) RemoteAddr() net.Addr { return c.addr }

func (c *pipeConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline does nothing: writes never block.
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }
