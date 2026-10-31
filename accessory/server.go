// Package accessory implements HomeKit accessory protocol (HAP) over IP:
// pairing with controllers, serving accessories and characteristics, events.
// It avoids net/http, reflection and big buffers, so it fits microcontrollers.
package accessory

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shabunin/tiny-hap-go/internal/session"
)

// Config of accessory server.
type Config struct {
	// Name is advertised name, defaults to name of first accessory.
	Name string
	// Pin is setup code entered on controller, e.g. "031-45-154".
	Pin      string
	Category Category
	// Model is advertised model, defaults to Name.
	Model string
	// Store keeps keys and pairings, in memory if nil.
	Store Store
	// Advertiser announces accessory with mDNS, nothing is announced if nil.
	Advertiser Advertiser
	// MaxConns limits connections, 8 if zero. A goroutine for each is started by Serve.
	MaxConns int
	// MinFreeHeap refuses new connections while less heap is free after
	// garbage collection, so that a board with fixed heap, e.g. with TinyGo,
	// does not run out of memory. Zero disables the check.
	MinFreeHeap int
	// OnIdentify is called when controller asks accessory to identify itself,
	// e.g. to blink.
	OnIdentify func()
}

// Advertiser announces accessory, e.g. with mDNS. Advertise is called
// when server starts and again when TXT record changes, e.g. after pairing.
type Advertiser interface {
	Advertise(name string, port int, txt map[string]string) error
}

// Server serves accessories to controllers.
type Server struct {
	cfg  Config
	accs []*Accessory
	id   string // accessory pairing id, e.g. "4A:B2:..."
	ltsk ed25519.PrivateKey
	ltpk ed25519.PublicKey

	handling sync.Mutex // held while request is handled

	mu         sync.Mutex
	pairings   []pairing
	conns      map[*conn]struct{}
	configNum  int
	setup      *pairSetup // pair-setup in progress
	failed     int        // failed pair-setup attempts
	ln         net.Listener
	port       int
	closed     bool
	advertised map[string]string
}

const (
	maxPairings = 16
	maxFailed   = 100
)

// NewServer loads or creates accessory identity in store.
func NewServer(cfg Config, accs ...*Accessory) (*Server, error) {
	if len(accs) == 0 {
		return nil, errors.New("accessory: no accessories")
	}
	if err := checkPin(cfg.Pin); err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		cfg.Store = NewMemStore()
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 8
	}
	if cfg.Category == 0 {
		cfg.Category = CategoryOther
	}
	s := &Server{cfg: cfg, accs: accs, conns: make(map[*conn]struct{})}
	if err := s.assignIDs(); err != nil {
		return nil, err
	}
	if s.cfg.Name == "" {
		s.cfg.Name = s.firstName()
	}
	if s.cfg.Model == "" {
		s.cfg.Model = s.cfg.Name
	}
	if err := s.loadIdentity(); err != nil {
		return nil, err
	}
	if err := s.loadPairings(); err != nil {
		return nil, err
	}
	if err := s.loadConfigNumber(); err != nil {
		return nil, err
	}
	return s, nil
}

// checkPin accepts XXX-XX-XXX digits, without codes the spec forbids.
func checkPin(pin string) error {
	if len(pin) != 10 || pin[3] != '-' || pin[6] != '-' {
		return errors.New("accessory: pin must look like 031-45-154")
	}
	digits := pin[:3] + pin[4:6] + pin[7:]
	for _, ch := range digits {
		if ch < '0' || ch > '9' {
			return errors.New("accessory: pin must have digits only")
		}
	}
	if strings.Count(digits, digits[:1]) == len(digits) || digits == "12345678" || digits == "87654321" {
		return errors.New("accessory: pin is too simple")
	}
	return nil
}

// assignIDs numbers accessories from 1, services and characteristics
// of each accessory from 1 in order, keeping ids that are set.
func (s *Server) assignIDs() error {
	used := make(map[uint64]bool)
	for _, a := range s.accs {
		if a.ID != 0 && used[a.ID] {
			return fmt.Errorf("accessory: duplicate accessory id %d", a.ID)
		}
		used[a.ID] = true
	}
	next := uint64(1)
	for _, a := range s.accs {
		if a.ID == 0 {
			for used[next] {
				next++
			}
			a.ID = next
			used[next] = true
		}
		iids := make(map[uint64]bool)
		for _, sv := range a.Services {
			if sv.ID != 0 {
				iids[sv.ID] = true
			}
			for _, c := range sv.Characteristics {
				if c.ID != 0 {
					iids[c.ID] = true
				}
			}
		}
		iid := uint64(1)
		take := func() uint64 {
			for iids[iid] {
				iid++
			}
			iids[iid] = true
			return iid
		}
		for _, sv := range a.Services {
			if sv.ID == 0 {
				sv.ID = take()
			}
			for _, c := range sv.Characteristics {
				if c.ID == 0 {
					c.ID = take()
				}
				c.aid = a.ID
				c.srv = s
			}
		}
	}
	return nil
}

func (s *Server) firstName() string {
	for _, sv := range s.accs[0].Services {
		for _, c := range sv.Characteristics {
			if c.Type == "23" {
				if name, ok := c.Value().(string); ok && name != "" {
					return name
				}
			}
		}
	}
	return "Accessory"
}

func (s *Server) loadIdentity() error {
	id, err := s.cfg.Store.Get("id")
	seed, err2 := s.cfg.Store.Get("key")
	if errors.Is(err, ErrNotFound) || errors.Is(err2, ErrNotFound) {
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		id = fmt.Appendf(nil, "%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		if err := s.cfg.Store.Set("key", seed); err != nil {
			return err
		}
		if err := s.cfg.Store.Set("id", id); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if err2 != nil {
		return err2
	}
	if len(seed) != ed25519.SeedSize {
		return errors.New("accessory: stored key is broken")
	}
	s.id = string(id)
	s.ltsk = ed25519.NewKeyFromSeed(seed)
	s.ltpk = s.ltsk.Public().(ed25519.PublicKey)
	return nil
}

// loadConfigNumber increments configuration number when accessories changed
// since last start, so controllers load them again.
func (s *Server) loadConfigNumber() error {
	var w jsonWriter
	w.accessories(s.accs, false)
	h := fnv.New64a()
	h.Write(w.b)
	hash := h.Sum64()

	b, err := s.cfg.Store.Get("config")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if len(b) == 10 && binary.BigEndian.Uint64(b[2:]) == hash {
		s.configNum = int(binary.BigEndian.Uint16(b))
		return nil
	}
	if len(b) == 10 {
		s.configNum = int(binary.BigEndian.Uint16(b))
	}
	s.configNum++
	if s.configNum > 65535 {
		s.configNum = 1
	}
	b = binary.BigEndian.AppendUint16(nil, uint16(s.configNum))
	b = binary.BigEndian.AppendUint64(b, hash)
	return s.cfg.Store.Set("config", b)
}

// ID returns accessory pairing id.
func (s *Server) ID() string {
	return s.id
}

// IsPaired reports if any controller is paired.
func (s *Server) IsPaired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pairings) > 0
}

// TXT returns TXT record to advertise, for own Advertiser implementations.
func (s *Server) TXT() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txtLocked()
}

func (s *Server) txtLocked() map[string]string {
	sf := "1"
	if len(s.pairings) > 0 {
		sf = "0"
	}
	return map[string]string{
		"c#": strconv.Itoa(s.configNum),
		"ff": "0",
		"id": s.id,
		"md": s.cfg.Model,
		"pv": "1.1",
		"s#": "1",
		"sf": sf,
		"ci": strconv.Itoa(int(s.cfg.Category)),
	}
}

// advertise announces TXT record if it changed since last time.
func (s *Server) advertise() {
	if s.cfg.Advertiser == nil {
		return
	}
	s.mu.Lock()
	txt := s.txtLocked()
	same := s.port != 0 && len(txt) == len(s.advertised)
	for k, v := range txt {
		same = same && s.advertised[k] == v
	}
	port := s.port
	if !same {
		s.advertised = txt
	}
	s.mu.Unlock()
	if same || port == 0 {
		return
	}
	if err := s.cfg.Advertiser.Advertise(s.cfg.Name, port, txt); err != nil {
		logf("advertise: %v", err)
	}
}

// Serve accepts controller connections until listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ln = ln
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = a.Port
	}
	s.mu.Unlock()
	s.advertise()

	// Connections are served by MaxConns goroutines started here: on a board
	// their stacks and buffers are allocated before the heap gets fragmented,
	// and reused.
	var w jsonWriter
	w.accessories(s.accs, true)
	bodySize := len(w.b) + len(w.b)/4 // room for longer values
	idle := make(chan chan net.Conn, s.cfg.MaxConns)
	for range s.cfg.MaxConns {
		ch := make(chan net.Conn)
		idle <- ch
		go s.work(ch, idle, newBuffers(bodySize))
		defer close(ch)
	}

	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return net.ErrClosed
			}
			return err
		}
		if s.cfg.MinFreeHeap > 0 {
			if free := freeHeap(); free < s.cfg.MinFreeHeap {
				logf("%s: refused, %d bytes of heap free", nc.RemoteAddr(), free)
				nc.Close()
				continue
			}
		}
		select {
		case ch := <-idle:
			ch <- nc
		default:
			logf("%s: refused, %d connections", nc.RemoteAddr(), s.cfg.MaxConns)
			nc.Close()
		}
	}
}

// work serves connections received on ch, then waits on idle for the next one.
func (s *Server) work(ch chan net.Conn, idle chan<- chan net.Conn, b *buffers) {
	for nc := range ch {
		s.serveConn(nc, b)
		idle <- ch
	}
}

// buffers of a worker goroutine, used by one connection at a time.
type buffers struct {
	rd    *bufio.Reader
	frame []byte // sealed frame read
	out   []byte // sealed frame written, guarded by wmu of connection
	body  []byte // JSON of response
}

func newBuffers(bodySize int) *buffers {
	return &buffers{
		rd:    bufio.NewReaderSize(nil, 512),
		frame: make([]byte, session.FrameSize),
		out:   make([]byte, session.FrameSize),
		body:  make([]byte, 0, bodySize),
	}
}

// serveConn serves connection until it is closed. It is a function of its own, so
// that nothing of the connection stays on stack of waiting goroutine for
// conservative garbage collector of TinyGo.
func (s *Server) serveConn(nc net.Conn, b *buffers) {
	c := newConn(s, nc, b)
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.conns[c] = struct{}{}
	}
	s.mu.Unlock()
	if closed {
		nc.Close()
		return
	}
	c.serve()
	// Events may still be written to c, they must not use buffers of the next connection.
	c.wmu.Lock()
	c.done = true
	c.wmu.Unlock()
}

// Close stops listener and closes connections.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		c.close()
	}
	return err
}

// freeHeap returns bytes of heap free after garbage collection.
func freeHeap() int {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int(m.HeapSys - m.HeapInuse)
}

func (s *Server) removeConn(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	if s.setup != nil && s.setup.c == c {
		s.setup = nil
	}
	s.mu.Unlock()
}

// connsOf returns verified connections of controller, all if id is empty.
func (s *Server) connsOf(id string) []*conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res []*conn
	for c := range s.conns {
		if ctrl, _ := c.controller(); ctrl != "" && (id == "" || ctrl == id) {
			res = append(res, c)
		}
	}
	return res
}

// logf prints debug messages, replaced in tests or by applications.
var logf = func(format string, args ...any) {}

// SetLogger sets function printing debug messages, e.g. log.Printf.
func SetLogger(f func(format string, args ...any)) {
	logf = f
}

const (
	maxLine      = 1024
	maxBody      = 8 * 1024
	maxHeaders   = 32
	writeTimeout = 10 * time.Second
	eventTimeout = time.Second
)

type conn struct {
	srv *Server
	nc  net.Conn
	buf *buffers
	rd  *bufio.Reader

	dec *session.Reader // set after pair-verify, used by serve goroutine only

	wmu  sync.Mutex
	sess *session.Session // guarded by wmu
	done bool             // guarded by wmu, buffers are not of c anymore

	vmu    sync.Mutex
	ctrlID string // verified controller
	admin  bool
	events map[*Characteristic]bool

	verify *pairVerify // pair-verify in progress

	changed []*Characteristic // written by request, notified after response
}

func newConn(s *Server, nc net.Conn, b *buffers) *conn {
	c := &conn{srv: s, nc: nc, buf: b, rd: b.rd}
	c.rd.Reset(connReader{c})
	return c
}

// json returns writer of response body in buffer of connection.
func (c *conn) json() jsonWriter { return jsonWriter{b: c.buf.body[:0]} }

// jsonResponse returns response with body of w, keeping its buffer if it grew.
func (c *conn) jsonResponse(status int, w jsonWriter) *response {
	c.buf.body = w.b
	return &response{status: status, contentType: contentJSON, body: w.b}
}

// connReader reads plain data before pair-verify, decrypted after.
type connReader struct{ c *conn }

func (r connReader) Read(p []byte) (int, error) {
	if r.c.dec != nil {
		return r.c.dec.Read(p)
	}
	return r.c.nc.Read(p)
}

func (c *conn) close() { c.nc.Close() }

// controller returns verified controller id, empty before pair-verify.
func (c *conn) controller() (id string, admin bool) {
	c.vmu.Lock()
	defer c.vmu.Unlock()
	return c.ctrlID, c.admin
}

func (c *conn) subscribed(ch *Characteristic) bool {
	c.vmu.Lock()
	defer c.vmu.Unlock()
	return c.events[ch]
}

func (c *conn) subscribe(ch *Characteristic, on bool) {
	c.vmu.Lock()
	defer c.vmu.Unlock()
	if on {
		if c.events == nil {
			c.events = make(map[*Characteristic]bool)
		}
		c.events[ch] = true
	} else {
		delete(c.events, ch)
	}
}

func (c *conn) serve() {
	defer func() {
		c.close()
		c.srv.removeConn(c)
	}()
	for {
		req, err := readRequest(c.rd)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logf("%s: read: %v", c.nc.RemoteAddr(), err)
			}
			return
		}
		// One request at a time: on a board the heap fits only one pair-verify
		// or accessory database, and a single core gains nothing from more.
		c.srv.handling.Lock()
		res := c.handle(req)
		c.srv.handling.Unlock()
		if err := c.write(res.header(), res.body); err != nil {
			logf("%s: write: %v", c.nc.RemoteAddr(), err)
			return
		}
		// Events go after response and out of handling: a controller that does
		// not read them holds up only this connection, for eventTimeout at most.
		for i, ch := range c.changed {
			c.srv.notify(ch, c)
			c.changed[i] = nil
		}
		c.changed = c.changed[:0]
		if res.after != nil && !res.after() {
			return
		}
	}
}

type request struct {
	method string
	path   string
	query  string
	body   []byte
}

var errBadRequest = errors.New("bad request")

func readLine(rd *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, more, err := rd.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, part...)
		if len(line) > maxLine {
			return "", errBadRequest
		}
		if !more {
			return string(line), nil
		}
	}
}

// readRequest reads HTTP/1.1 request with Content-Length body.
func readRequest(rd *bufio.Reader) (*request, error) {
	line, err := readLine(rd)
	if err != nil {
		return nil, err
	}
	method, rest, ok1 := strings.Cut(line, " ")
	target, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 || !strings.HasPrefix(proto, "HTTP/1.") {
		return nil, errBadRequest
	}
	req := &request{method: method}
	req.path, req.query, _ = strings.Cut(target, "?")

	length := 0
	for i := 0; ; i++ {
		if i > maxHeaders {
			return nil, errBadRequest
		}
		h, err := readLine(rd)
		if err != nil {
			return nil, err
		}
		if h == "" {
			break
		}
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, errBadRequest
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(name) {
		case "content-length":
			length, err = strconv.Atoi(value)
			if err != nil || length < 0 || length > maxBody {
				return nil, errBadRequest
			}
		case "transfer-encoding":
			// controllers send length, chunked bodies are not supported
			return nil, errBadRequest
		}
	}
	if length > 0 {
		req.body = make([]byte, length)
		if _, err := io.ReadFull(rd, req.body); err != nil {
			return nil, err
		}
	}
	return req, nil
}

const (
	contentTLV  = "application/pairing+tlv8"
	contentJSON = "application/hap+json"
)

type response struct {
	status      int
	contentType string
	body        []byte
	// after runs once response is written, false closes connection
	after func() bool
}

var statusText = map[int]string{
	200: "OK",
	204: "No Content",
	207: "Multi-Status",
	400: "Bad Request",
	404: "Not Found",
	405: "Method Not Allowed",
	422: "Unprocessable Entity",
	470: "Connection Authorization Required",
	500: "Internal Server Error",
	503: "Service Unavailable",
}

// header returns status line and headers, body is written after them.
func (r *response) header() []byte {
	b := make([]byte, 0, 96)
	b = fmt.Appendf(b, "HTTP/1.1 %d %s\r\n", r.status, statusText[r.status])
	if r.contentType != "" {
		b = append(b, "Content-Type: "...)
		b = append(b, r.contentType...)
		b = append(b, "\r\n"...)
	}
	return fmt.Appendf(b, "Content-Length: %d\r\n\r\n", len(r.body))
}

func tlvResponse(b []byte) *response {
	return &response{status: 200, contentType: contentTLV, body: b}
}

func statusResponse(status, hapStatus int) *response {
	return &response{status: status, contentType: contentJSON,
		body: fmt.Appendf(nil, `{"status":%d}`, hapStatus)}
}

// write sends parts of message, encrypted once connection is verified.
// Encrypted message is sealed and written frame by frame, without copy of it.
func (c *conn) write(parts ...[]byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeLocked(writeTimeout, parts...)
}

// writeLocked is write with c.wmu held, closing connection if it takes longer than timeout.
func (c *conn) writeLocked(timeout time.Duration, parts ...[]byte) error {
	if c.done {
		return net.ErrClosed
	}
	c.nc.SetWriteDeadline(time.Now().Add(timeout))
	var err error
	if c.sess != nil {
		err = c.sess.Write(c.nc, c.buf.out, parts...)
	} else {
		for _, p := range parts {
			if _, err = c.nc.Write(p); err != nil {
				break
			}
		}
	}
	if err != nil {
		c.close()
	}
	return err
}

// HAP status codes.
const (
	statusSuccess          = 0
	statusInsufficientPriv = -70401
	statusCommunication    = -70402
	statusBusy             = -70403
	statusReadOnly         = -70404
	statusWriteOnly        = -70405
	statusNoNotification   = -70406
	statusNoResource       = -70409
	statusInvalidValue     = -70410
)

func (c *conn) handle(req *request) *response {
	switch req.path {
	case "/pair-setup":
		if req.method != "POST" {
			return &response{status: 405}
		}
		return c.pairSetup(req.body)
	case "/pair-verify":
		if req.method != "POST" {
			return &response{status: 405}
		}
		return c.pairVerify(req.body)
	case "/identify":
		if req.method != "POST" {
			return &response{status: 405}
		}
		if c.srv.IsPaired() {
			return statusResponse(400, statusInsufficientPriv)
		}
		c.srv.identify()
		return &response{status: 204}
	}

	if ctrl, _ := c.controller(); ctrl == "" {
		return statusResponse(470, statusInsufficientPriv)
	}
	switch req.path {
	case "/pairings":
		if req.method != "POST" {
			return &response{status: 405}
		}
		return c.pairings(req.body)
	case "/accessories":
		if req.method != "GET" {
			return &response{status: 405}
		}
		w := c.json()
		w.accessories(c.srv.accs, true)
		return c.jsonResponse(200, w)
	case "/characteristics":
		switch req.method {
		case "GET":
			return c.getCharacteristics(req.query)
		case "PUT":
			return c.putCharacteristics(req.body)
		}
		return &response{status: 405}
	}
	return &response{status: 404}
}

func (s *Server) identify() {
	if s.cfg.OnIdentify != nil {
		s.cfg.OnIdentify()
	}
}
