package accessory

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/tiny-hap-go/internal/hapcrypto"
	"github.com/shabunin/tiny-hap-go/internal/session"
	"github.com/shabunin/tiny-hap-go/tlv"
)

// testClient is a minimal controller talking to accessory server in tests.
type testClient struct {
	t    *testing.T
	nc   net.Conn
	rd   *bufio.Reader
	dec  *session.Reader
	sess *session.Session

	id   string
	ltsk ed25519.PrivateKey
	ltpk ed25519.PublicKey

	events []string // bodies of events received while waiting for responses

	// tamper, if set, changes each request as it goes on the wire.
	tamper func(req []byte) []byte
}

func newTestController(t *testing.T, id string) *testClient {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{t: t, id: id, ltsk: priv, ltpk: pub}
}

// connect opens new connection, without session.
func (c *testClient) connect(addr string) {
	c.t.Helper()
	if c.nc != nil {
		c.nc.Close()
	}
	nc, err := dial(addr)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { nc.Close() })
	c.nc, c.dec, c.sess, c.events = nc, nil, nil, nil
	c.rd = bufio.NewReader(clientReader{c})
}

type clientReader struct{ c *testClient }

func (r clientReader) Read(p []byte) (int, error) {
	if r.c.dec != nil {
		return r.c.dec.Read(p)
	}
	return r.c.nc.Read(p)
}

type testResponse struct {
	status int
	body   []byte
}

// readMessage reads response or event.
func (c *testClient) readMessage() (proto string, res testResponse, err error) {
	c.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.rd.ReadString('\n')
	if err != nil {
		return "", res, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", res, fmt.Errorf("bad status line %q", line)
	}
	proto = fields[0]
	res.status, _ = strconv.Atoi(fields[1])
	length := 0
	for {
		h, err := c.rd.ReadString('\n')
		if err != nil {
			return "", res, err
		}
		h = strings.TrimSpace(h)
		if h == "" {
			break
		}
		if name, value, _ := strings.Cut(h, ":"); strings.EqualFold(name, "content-length") {
			length, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	res.body = make([]byte, length)
	_, err = io.ReadFull(c.rd, res.body)
	return proto, res, err
}

// do sends request and returns response, events coming before it are kept.
func (c *testClient) do(method, path, contentType string, body []byte) (testResponse, error) {
	req := fmt.Appendf(nil, "%s %s HTTP/1.1\r\nHost: test\r\n", method, path)
	if contentType != "" {
		req = fmt.Appendf(req, "Content-Type: %s\r\n", contentType)
	}
	req = fmt.Appendf(req, "Content-Length: %d\r\n\r\n", len(body))
	req = append(req, body...)
	if c.sess != nil {
		req = c.sess.Seal(nil, req)
	}
	if c.tamper != nil {
		req = c.tamper(req)
	}
	if _, err := c.nc.Write(req); err != nil {
		return testResponse{}, err
	}
	for {
		proto, res, err := c.readMessage()
		if err != nil {
			return res, err
		}
		if proto == "EVENT/1.0" {
			c.events = append(c.events, string(res.body))
			continue
		}
		return res, nil
	}
}

func (c *testClient) mustDo(method, path, contentType string, body []byte) testResponse {
	c.t.Helper()
	res, err := c.do(method, path, contentType, body)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

// postTLV sends pairing message and parses response items.
func (c *testClient) postTLV(path string, w *tlv.Writer) (tlv.Items, error) {
	res, err := c.do("POST", path, contentTLV, w.Data())
	if err != nil {
		return nil, err
	}
	if res.status != 200 {
		return nil, fmt.Errorf("%s: status %d", path, res.status)
	}
	return tlv.Parse(res.body)
}

type tlvErr byte

func (e tlvErr) Error() string { return fmt.Sprintf("tlv error %d", byte(e)) }

func itemsError(items tlv.Items) error {
	if code, ok := items.Byte(tlv.Error); ok {
		return tlvErr(code)
	}
	return nil
}

// pairSetup pairs with setup code, returns accessory id and long term public key.
func (c *testClient) pairSetup(pin string) (string, []byte, error) {
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Byte(tlv.Method, 0)
	m2, err := c.postTLV("/pair-setup", &w)
	if err != nil {
		return "", nil, err
	}
	if err := itemsError(m2); err != nil {
		return "", nil, err
	}
	salt, _ := m2.Get(tlv.Salt)
	b, _ := m2.Get(tlv.PublicKey)

	sr, err := newSRP()
	if err != nil {
		return "", nil, err
	}
	cs := sr.NewClientSession([]byte("Pair-Setup"), []byte(pin))
	key, err := cs.ComputeKey(salt, b)
	if err != nil {
		return "", nil, err
	}
	w = tlv.Writer{}
	w.Byte(tlv.State, 3)
	w.Bytes(tlv.PublicKey, cs.GetA())
	w.Bytes(tlv.Proof, cs.ComputeAuthenticator())
	m4, err := c.postTLV("/pair-setup", &w)
	if err != nil {
		return "", nil, err
	}
	if err := itemsError(m4); err != nil {
		return "", nil, err
	}
	proof, _ := m4.Get(tlv.Proof)
	if !cs.VerifyServerAuthenticator(proof) {
		return "", nil, errors.New("server proof invalid")
	}

	encKey := hapcrypto.HKDF(key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	ctrlX := hapcrypto.HKDF(key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	var sw tlv.Writer
	sw.String(tlv.Identifier, c.id)
	sw.Bytes(tlv.PublicKey, c.ltpk)
	sw.Bytes(tlv.Signature, ed25519.Sign(c.ltsk, append(append(ctrlX[:], c.id...), c.ltpk...)))
	w = tlv.Writer{}
	w.Byte(tlv.State, 5)
	w.Bytes(tlv.EncryptedData, hapcrypto.Seal(nil, encKey, []byte("PS-Msg05"), sw.Data(), nil))
	m6, err := c.postTLV("/pair-setup", &w)
	if err != nil {
		return "", nil, err
	}
	if err := itemsError(m6); err != nil {
		return "", nil, err
	}
	enc, _ := m6.Get(tlv.EncryptedData)
	plain, err := hapcrypto.Open(encKey, []byte("PS-Msg06"), enc, nil)
	if err != nil {
		return "", nil, err
	}
	sub, err := tlv.Parse(plain)
	if err != nil {
		return "", nil, err
	}
	accID, _ := sub.Get(tlv.Identifier)
	accLTPK, _ := sub.Get(tlv.PublicKey)
	sig, _ := sub.Get(tlv.Signature)
	accX := hapcrypto.HKDF(key, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	if !ed25519.Verify(accLTPK, append(append(accX[:], accID...), accLTPK...), sig) {
		return "", nil, errors.New("accessory signature invalid")
	}
	return string(accID), accLTPK, nil
}

// pairVerify establishes session with accessory of long term public key.
func (c *testClient) pairVerify(accLTPK []byte) error {
	pub, priv, err := hapcrypto.X25519KeyPair()
	if err != nil {
		return err
	}
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Bytes(tlv.PublicKey, pub[:])
	m2, err := c.postTLV("/pair-verify", &w)
	if err != nil {
		return err
	}
	if err := itemsError(m2); err != nil {
		return err
	}
	accPubB, _ := m2.Get(tlv.PublicKey)
	var accPub [32]byte
	copy(accPub[:], accPubB)
	shared, err := hapcrypto.X25519(priv, accPub)
	if err != nil {
		return err
	}
	encKey := hapcrypto.HKDF(shared[:], "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	enc, _ := m2.Get(tlv.EncryptedData)
	plain, err := hapcrypto.Open(encKey, []byte("PV-Msg02"), enc, nil)
	if err != nil {
		return err
	}
	sub, err := tlv.Parse(plain)
	if err != nil {
		return err
	}
	accID, _ := sub.Get(tlv.Identifier)
	sig, _ := sub.Get(tlv.Signature)
	if !ed25519.Verify(accLTPK, append(append(accPub[:], accID...), pub[:]...), sig) {
		return errors.New("accessory signature invalid")
	}

	var sw tlv.Writer
	sw.String(tlv.Identifier, c.id)
	sw.Bytes(tlv.Signature, ed25519.Sign(c.ltsk, append(append(pub[:], c.id...), accPub[:]...)))
	w = tlv.Writer{}
	w.Byte(tlv.State, 3)
	w.Bytes(tlv.EncryptedData, hapcrypto.Seal(nil, encKey, []byte("PV-Msg03"), sw.Data(), nil))
	m4, err := c.postTLV("/pair-verify", &w)
	if err != nil {
		return err
	}
	if err := itemsError(m4); err != nil {
		return err
	}
	c.sess = session.NewController(shared)
	c.dec = session.NewReader(c.sess, c.nc, nil)
	return nil
}

// waitEvent returns next event, reading it if none arrived with responses.
func (c *testClient) waitEvent() string {
	c.t.Helper()
	if len(c.events) > 0 {
		ev := c.events[0]
		c.events = c.events[1:]
		return ev
	}
	proto, res, err := c.readMessage()
	if err != nil {
		c.t.Fatalf("waiting for event: %v", err)
	}
	if proto != "EVENT/1.0" {
		c.t.Fatalf("expected event, got %s %d %s", proto, res.status, res.body)
	}
	return string(res.body)
}

// expectNoEvent fails if event arrives shortly.
func (c *testClient) expectNoEvent() {
	c.t.Helper()
	if len(c.events) > 0 {
		c.t.Fatalf("unexpected event %s", c.events[0])
	}
	c.nc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := c.rd.Peek(1); err == nil {
		c.t.Fatal("unexpected data from accessory")
	}
}

func (c *testClient) expectClosed() {
	c.t.Helper()
	c.nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.rd.Peek(1); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) &&
		!strings.Contains(fmt.Sprint(err), "reset") {
		c.t.Fatalf("connection should be closed, got %v", err)
	}
}

// testServer starts server with lamp accessory.
func testServer(t *testing.T, store Store) (*Server, string, *testLamp) {
	t.Helper()
	l := newTestLamp()
	if store == nil {
		store = NewMemStore()
	}
	srv, err := NewServer(Config{Pin: "031-45-154", Category: CategoryLightbulb, Store: store,
		OnIdentify: func() {
			l.mu.Lock()
			l.identified++
			l.mu.Unlock()
		}}, l.acc)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return srv, ln.Addr().String(), l
}

type testLamp struct {
	acc        *Accessory
	on, bright *Characteristic

	mu         sync.Mutex // written by server goroutines
	writes     []any
	identified int
}

func (l *testLamp) counts() (writes []any, identified int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]any(nil), l.writes...), l.identified
}

func newTestLamp() *testLamp {
	l := &testLamp{on: NewOn(), bright: NewBrightness()}
	l.on.OnWrite = func(v any) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.writes = append(l.writes, v)
		return nil
	}
	l.acc = &Accessory{Services: []*Service{
		NewInfoService(Info{Name: "Lamp", Manufacturer: "test", Model: "L1", SerialNumber: "1", Firmware: "1.0"}),
		NewService(ServiceLightbulb, NewName("Lamp"), l.on, l.bright),
	}}
	return l
}

// pairedClient pairs new controller and verifies connection.
func pairedClient(t *testing.T, srv *Server, addr, id string) *testClient {
	t.Helper()
	c := newTestController(t, id)
	c.connect(addr)
	accID, ltpk, err := c.pairSetup("031-45-154")
	if err != nil {
		t.Fatal(err)
	}
	if accID != srv.ID() || !bytes.Equal(ltpk, srv.ltpk) {
		t.Fatalf("accessory id %s and key differ from server's", accID)
	}
	if err := c.pairVerify(ltpk); err != nil {
		t.Fatal(err)
	}
	return c
}

// serve starts server on local port, returns its address.
func serve(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}
