package accessory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shabunin/tiny-hap-go/tlv"
)

func TestPairSetupAndVerify(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	if srv.IsPaired() || srv.TXT()["sf"] != "1" {
		t.Fatal("new server should be unpaired")
	}
	c := pairedClient(t, srv, addr, "ctrl")
	if !srv.IsPaired() || srv.TXT()["sf"] != "0" {
		t.Fatal("server should be paired")
	}

	res := c.mustDo("GET", "/accessories", "", nil)
	var db struct {
		Accessories []struct {
			Aid      uint64 `json:"aid"`
			Services []struct {
				Iid             uint64 `json:"iid"`
				Type            string `json:"type"`
				Characteristics []struct {
					Iid    uint64   `json:"iid"`
					Type   string   `json:"type"`
					Perms  []string `json:"perms"`
					Format string   `json:"format"`
					Value  any      `json:"value"`
				} `json:"characteristics"`
			} `json:"services"`
		} `json:"accessories"`
	}
	if err := json.Unmarshal(res.body, &db); err != nil {
		t.Fatalf("%v: %s", err, res.body)
	}
	if len(db.Accessories) != 1 || db.Accessories[0].Aid != 1 || len(db.Accessories[0].Services) != 2 {
		t.Fatalf("unexpected accessories %s", res.body)
	}
	bulb := db.Accessories[0].Services[1]
	on := bulb.Characteristics[1]
	if bulb.Type != ServiceLightbulb || bulb.Iid != 8 || on.Iid != 10 || on.Type != "25" ||
		on.Format != "bool" || on.Value != false || strings.Join(on.Perms, ",") != "pr,pw,ev" {
		t.Fatalf("unexpected lightbulb %+v", bulb)
	}
	// Identify is write only, without value
	if id := db.Accessories[0].Services[0].Characteristics[0]; id.Type != "14" || id.Value != nil {
		t.Fatalf("unexpected identify %+v", id)
	}
}

func TestWrongPin(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := newTestController(t, "ctrl")
	c.connect(addr)
	var terr tlvErr
	if _, _, err := c.pairSetup("111-22-333"); !errors.As(err, &terr) || byte(terr) != tlv.ErrAuthentication {
		t.Fatalf("expected authentication error, got %v", err)
	}
	if srv.IsPaired() {
		t.Fatal("paired with wrong pin")
	}
	// next attempt with right pin works
	if _, _, err := c.pairSetup("031-45-154"); err != nil {
		t.Fatal(err)
	}
}

func TestPairSetupWhenPaired(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	pairedClient(t, srv, addr, "ctrl")
	c := newTestController(t, "other")
	c.connect(addr)
	var terr tlvErr
	if _, _, err := c.pairSetup("031-45-154"); !errors.As(err, &terr) || byte(terr) != tlv.ErrUnavailable {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func TestPairSetupBusy(t *testing.T) {
	_, addr, _ := testServer(t, nil)
	a := newTestController(t, "a")
	a.connect(addr)
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Byte(tlv.Method, 0)
	if _, err := a.postTLV("/pair-setup", &w); err != nil {
		t.Fatal(err)
	}

	b := newTestController(t, "b")
	b.connect(addr)
	var terr tlvErr
	if _, _, err := b.pairSetup("031-45-154"); !errors.As(err, &terr) || byte(terr) != tlv.ErrBusy {
		t.Fatalf("expected busy error, got %v", err)
	}
	// closed connection frees pair-setup
	a.nc.Close()
	for i := 0; ; i++ {
		_, _, err := b.pairSetup("031-45-154")
		if err == nil {
			break
		}
		if i == 50 {
			t.Fatalf("pair-setup still busy: %v", err)
		}
		b.connect(addr)
	}
}

func TestVerifyUnknownController(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	pairedClient(t, srv, addr, "ctrl")
	c := newTestController(t, "stranger")
	c.connect(addr)
	var terr tlvErr
	if err := c.pairVerify(srv.ltpk); !errors.As(err, &terr) || byte(terr) != tlv.ErrAuthentication {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestRequestsNeedVerifiedConnection(t *testing.T) {
	_, addr, _ := testServer(t, nil)
	c := newTestController(t, "ctrl")
	c.connect(addr)
	for _, path := range []string{"/accessories", "/characteristics?id=1.10"} {
		if res := c.mustDo("GET", path, "", nil); res.status != 470 {
			t.Fatalf("%s: status %d, want 470", path, res.status)
		}
	}
}

func TestGetCharacteristics(t *testing.T) {
	srv, addr, l := testServer(t, nil)
	c := pairedClient(t, srv, addr, "ctrl")
	l.bright.SetValue(42)

	res := c.mustDo("GET", "/characteristics?id=1.10,1.11", "", nil)
	if res.status != 200 || string(res.body) != `{"characteristics":[{"aid":1,"iid":10,"value":false},{"aid":1,"iid":11,"value":42}]}` {
		t.Fatalf("%d %s", res.status, res.body)
	}
	res = c.mustDo("GET", "/characteristics?id=1.11&meta=1&perms=1&type=1&ev=1", "", nil)
	want := `{"characteristics":[{"aid":1,"iid":11,"type":"8","perms":["pr","pw","ev"],"format":"int",` +
		`"unit":"percentage","minValue":0,"maxValue":100,"minStep":1,"value":42,"ev":false}]}`
	if string(res.body) != want {
		t.Fatalf("got  %s\nwant %s", res.body, want)
	}
	// unknown and write only characteristics: every entry gets status
	res = c.mustDo("GET", "/characteristics?id=1.10,1.99,1.2", "", nil)
	want = `{"characteristics":[{"aid":1,"iid":10,"value":false,"status":0},` +
		`{"aid":1,"iid":99,"status":-70409},{"aid":1,"iid":2,"status":-70405}]}`
	if res.status != 207 || string(res.body) != want {
		t.Fatalf("got %d %s\nwant %s", res.status, res.body, want)
	}
	if res := c.mustDo("GET", "/characteristics?id=x", "", nil); res.status != 400 {
		t.Fatalf("bad id: status %d", res.status)
	}
}

func put(c *testClient, body string) testResponse {
	c.t.Helper()
	return c.mustDo("PUT", "/characteristics", contentJSON, []byte(body))
}

func TestPutCharacteristics(t *testing.T) {
	srv, addr, l := testServer(t, nil)
	c := pairedClient(t, srv, addr, "ctrl")

	if res := put(c, `{"characteristics":[{"aid":1,"iid":10,"value":true},{"aid":1,"iid":11,"value":37}]}`); res.status != 204 {
		t.Fatalf("status %d %s", res.status, res.body)
	}
	if l.on.Value() != true || l.bright.Value() != int64(37) {
		t.Fatalf("values %v %v", l.on.Value(), l.bright.Value())
	}
	// controllers send 0 and 1 for bool
	if res := put(c, `{"characteristics":[{"aid":1,"iid":10,"value":0}]}`); res.status != 204 {
		t.Fatalf("status %d %s", res.status, res.body)
	}
	if writes, _ := l.counts(); fmt.Sprint(writes) != "[true false]" {
		t.Fatalf("OnWrite got %v", writes)
	}

	res := put(c, `{"characteristics":[{"aid":1,"iid":11,"value":150},{"aid":1,"iid":9,"value":"x"},`+
		`{"aid":1,"iid":10,"value":"on"},{"aid":2,"iid":10,"value":true},{"aid":1,"iid":11,"value":50}]}`)
	want := `{"characteristics":[{"aid":1,"iid":11,"status":-70410},{"aid":1,"iid":9,"status":-70404},` +
		`{"aid":1,"iid":10,"status":-70410},{"aid":2,"iid":10,"status":-70409},{"aid":1,"iid":11,"status":0}]}`
	if res.status != 207 || string(res.body) != want {
		t.Fatalf("got %d %s\nwant %s", res.status, res.body, want)
	}
	if l.bright.Value() != int64(50) {
		t.Fatal("valid write in failed request should be applied")
	}

	l.on.OnWrite = func(any) error { return errors.New("relay stuck") }
	if res := put(c, `{"characteristics":[{"aid":1,"iid":10,"value":true}]}`); !strings.Contains(string(res.body), "-70402") {
		t.Fatalf("rejected write: %d %s", res.status, res.body)
	}
	if l.on.Value() != false {
		t.Fatal("rejected value stored")
	}
	if res := put(c, `{"characteristics":[`); res.status != 400 {
		t.Fatalf("bad json: status %d", res.status)
	}
}

func TestWriteResponse(t *testing.T) {
	ch := NewCharacteristic("FF", FormatString, PermRead|PermWrite|PermWriteResponse, "")
	ch.OnWrite = func(v any) error { return nil }
	acc := &Accessory{Services: []*Service{NewInfoService(Info{Name: "x"}), NewService("FE", ch)}}
	srv, err := NewServer(Config{Pin: "031-45-154"}, acc)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	c := pairedClient(t, srv, addr, "ctrl")
	body := fmt.Sprintf(`{"characteristics":[{"aid":1,"iid":%d,"value":"ping","r":true}]}`, ch.ID)
	res := put(c, body)
	want := fmt.Sprintf(`{"characteristics":[{"aid":1,"iid":%d,"status":0,"value":"ping"}]}`, ch.ID)
	if res.status != 207 || string(res.body) != want {
		t.Fatalf("got %d %s", res.status, res.body)
	}
}

func TestIdentify(t *testing.T) {
	srv, addr, l := testServer(t, nil)
	c := newTestController(t, "ctrl")
	c.connect(addr)
	if res := c.mustDo("POST", "/identify", "", nil); res.status != 204 {
		t.Fatalf("unpaired identify: status %d", res.status)
	}
	c = pairedClient(t, srv, addr, "ctrl")
	if res := c.mustDo("POST", "/identify", "", nil); res.status != 400 {
		t.Fatalf("paired identify: status %d", res.status)
	}
	// paired controllers write Identify characteristic
	if res := put(c, `{"characteristics":[{"aid":1,"iid":2,"value":true}]}`); res.status != 204 {
		t.Fatalf("status %d", res.status)
	}
	if _, n := l.counts(); n != 2 {
		t.Fatalf("identified %d times", n)
	}
}

// addPairing adds controller by admin c, returns verified client of it.
func addPairing(t *testing.T, srv *Server, addr string, c *testClient, id string, admin bool) *testClient {
	t.Helper()
	other := newTestController(t, id)
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Byte(tlv.Method, 3)
	w.String(tlv.Identifier, id)
	w.Bytes(tlv.PublicKey, other.ltpk)
	if admin {
		w.Byte(tlv.Permissions, 1)
	} else {
		w.Byte(tlv.Permissions, 0)
	}
	items, err := c.postTLV("/pairings", &w)
	if err != nil || itemsError(items) != nil {
		t.Fatalf("add pairing: %v %v", err, itemsError(items))
	}
	other.connect(addr)
	if err := other.pairVerify(srv.ltpk); err != nil {
		t.Fatal(err)
	}
	return other
}

func TestEvents(t *testing.T) {
	srv, addr, l := testServer(t, nil)
	a := pairedClient(t, srv, addr, "a")
	b := addPairing(t, srv, addr, a, "b", false)

	if res := put(a, `{"characteristics":[{"aid":1,"iid":10,"ev":true},{"aid":1,"iid":9,"ev":true}]}`); !strings.Contains(string(res.body), `"iid":9,"status":-70406`) {
		t.Fatalf("subscribing: %d %s", res.status, res.body)
	}
	if res := c2get(a, "1.10"); !strings.Contains(res, `"ev":true`) {
		t.Fatalf("ev not reported: %s", res)
	}

	// write of other controller comes as event
	put(b, `{"characteristics":[{"aid":1,"iid":10,"value":true}]}`)
	if ev := a.waitEvent(); ev != `{"characteristics":[{"aid":1,"iid":10,"value":true}]}` {
		t.Fatalf("event %s", ev)
	}
	b.expectNoEvent()

	// own writes and unchanged values send nothing
	put(a, `{"characteristics":[{"aid":1,"iid":10,"value":false}]}`)
	put(b, `{"characteristics":[{"aid":1,"iid":11,"value":100}]}`)
	a.expectNoEvent()

	// value changed by accessory itself
	l.on.SetValue(true)
	if ev := a.waitEvent(); !strings.Contains(ev, `"value":true`) {
		t.Fatalf("event %s", ev)
	}

	put(a, `{"characteristics":[{"aid":1,"iid":10,"ev":false}]}`)
	l.on.SetValue(false)
	a.expectNoEvent()
}

func c2get(c *testClient, ids string) string {
	return string(c.mustDo("GET", "/characteristics?ev=1&id="+ids, "", nil).body)
}

func listPairings(t *testing.T, c *testClient) ([]pairing, error) {
	t.Helper()
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Byte(tlv.Method, 5)
	res, err := c.do("POST", "/pairings", contentTLV, w.Data())
	if err != nil {
		t.Fatal(err)
	}
	items, err := tlv.Parse(res.body)
	if err != nil {
		t.Fatal(err)
	}
	if err := itemsError(items); err != nil {
		return nil, err
	}
	return decodePairings(res.body)
}

func removePairing(t *testing.T, c *testClient, id string) error {
	t.Helper()
	var w tlv.Writer
	w.Byte(tlv.State, 1)
	w.Byte(tlv.Method, 4)
	w.String(tlv.Identifier, id)
	items, err := c.postTLV("/pairings", &w)
	if err != nil {
		t.Fatal(err)
	}
	return itemsError(items)
}

func TestPairings(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	a := pairedClient(t, srv, addr, "a")
	b := addPairing(t, srv, addr, a, "b", false)

	pp, err := listPairings(t, a)
	if err != nil || len(pp) != 2 || pp[0].id != "a" || !pp[0].admin || pp[1].id != "b" || pp[1].admin {
		t.Fatalf("pairings %+v %v", pp, err)
	}
	// only admins manage pairings
	var terr tlvErr
	if _, err := listPairings(t, b); !errors.As(err, &terr) || byte(terr) != tlv.ErrAuthentication {
		t.Fatalf("user listed pairings: %v", err)
	}
	if err := removePairing(t, b, "a"); !errors.As(err, &terr) {
		t.Fatalf("user removed admin: %v", err)
	}

	// removed controller is disconnected
	if err := removePairing(t, a, "b"); err != nil {
		t.Fatal(err)
	}
	b.expectClosed()
	if pp, _ := listPairings(t, a); len(pp) != 1 {
		t.Fatalf("pairings %+v", pp)
	}

	// removing itself, the last admin, unpairs accessory
	if err := removePairing(t, a, "a"); err != nil {
		t.Fatal(err)
	}
	a.expectClosed()
	if srv.IsPaired() || srv.TXT()["sf"] != "1" {
		t.Fatal("accessory should be unpaired")
	}
}

func TestLastAdminRemovesAll(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	a := pairedClient(t, srv, addr, "a")
	b := addPairing(t, srv, addr, a, "b", false)
	if err := removePairing(t, a, "a"); err != nil {
		t.Fatal(err)
	}
	a.expectClosed()
	b.expectClosed()
	if srv.IsPaired() {
		t.Fatal("user without admin should be removed too")
	}
}

func TestRestartKeepsPairing(t *testing.T) {
	store := NewMemStore()
	srv, addr, _ := testServer(t, store)
	c := pairedClient(t, srv, addr, "ctrl")
	id, cn := srv.ID(), srv.TXT()["c#"]
	srv.Close()

	srv2, addr2, _ := testServer(t, store)
	if srv2.ID() != id || !srv2.IsPaired() || srv2.TXT()["c#"] != cn {
		t.Fatalf("restarted server: id %s paired %v c# %s", srv2.ID(), srv2.IsPaired(), srv2.TXT()["c#"])
	}
	c.connect(addr2)
	if err := c.pairVerify(srv2.ltpk); err != nil {
		t.Fatal(err)
	}
}

func TestConfigNumberChangesWithAccessories(t *testing.T) {
	store := NewMemStore()
	srv, _, l := testServer(t, store)
	if srv.TXT()["c#"] != "1" {
		t.Fatalf("c# %s", srv.TXT()["c#"])
	}
	// values don't change configuration
	l.on.SetValue(true)
	srv2, _, _ := testServer(t, store)
	if srv2.TXT()["c#"] != "1" {
		t.Fatalf("c# %s after value change", srv2.TXT()["c#"])
	}

	l3 := newTestLamp()
	l3.acc.Services = append(l3.acc.Services, NewService(ServiceSwitch, NewOn()))
	srv3, err := NewServer(Config{Pin: "031-45-154", Store: store}, l3.acc)
	if err != nil {
		t.Fatal(err)
	}
	if srv3.TXT()["c#"] != "2" {
		t.Fatalf("c# %s after new service", srv3.TXT()["c#"])
	}
}

func TestMaxConns(t *testing.T) {
	l := newTestLamp()
	srv, err := NewServer(Config{Pin: "031-45-154", MaxConns: 2}, l.acc)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	var cs []*testClient
	for i := 0; i < 3; i++ {
		c := newTestController(t, "c")
		c.connect(addr)
		cs = append(cs, c)
	}
	for _, c := range cs[:2] {
		if res := c.mustDo("POST", "/identify", "", nil); res.status != 204 {
			t.Fatalf("status %d", res.status)
		}
	}
	cs[2].expectClosed()
}

// Connections served one after another by the same worker reuse its buffers,
// while the other worker sends events.
func TestReusedBuffers(t *testing.T) {
	l := newTestLamp()
	srv, err := NewServer(Config{Pin: "031-45-154", MaxConns: 2}, l.acc)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	a := pairedClient(t, srv, addr, "a")
	b := addPairing(t, srv, addr, a, "b", false)
	put(a, `{"characteristics":[{"aid":1,"iid":11,"ev":true}]}`)
	want := string(b.mustDo("GET", "/accessories", "", nil).body)
	for i := range 5 {
		b.nc.Close()
		waitConns(t, srv, 1)
		b.connect(addr)
		if err := b.pairVerify(srv.ltpk); err != nil {
			t.Fatal(err)
		}
		v := strconv.Itoa(10 + i)
		put(b, `{"characteristics":[{"aid":1,"iid":11,"value":`+v+`}]}`)
		if ev := a.waitEvent(); ev != `{"characteristics":[{"aid":1,"iid":11,"value":`+v+`}]}` {
			t.Fatalf("event %s", ev)
		}
		got := string(b.mustDo("GET", "/accessories", "", nil).body)
		if got != strings.Replace(want, `"value":100`, `"value":`+v, 1) {
			t.Fatalf("accessories %s", got)
		}
	}
}

// waitConns waits until server has n connections.
func waitConns(t *testing.T, srv *Server, n int) {
	t.Helper()
	for range 100 {
		srv.mu.Lock()
		k := len(srv.conns)
		srv.mu.Unlock()
		if k == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server still has other than %d connections", n)
}

// A controller that stopped reading holds up neither the one writing a value,
// nor others, and is disconnected.
func TestStalledSubscriber(t *testing.T) {
	l := newTestLamp()
	srv, err := NewServer(Config{Pin: "031-45-154"}, l.acc)
	if err != nil {
		t.Fatal(err)
	}
	ln0, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	ln := &stallListener{Listener: ln0}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	a := pairedClient(t, srv, addr, "a")
	b := addPairing(t, srv, addr, a, "b", false)
	c := addPairing(t, srv, addr, a, "c", false)
	put(a, `{"characteristics":[{"aid":1,"iid":10,"ev":true}]}`)
	ln.stall()

	start := time.Now()
	put(b, `{"characteristics":[{"aid":1,"iid":10,"value":true}]}`)
	if d := time.Since(start); d > eventTimeout/2 {
		t.Fatalf("write took %v", d)
	}
	start = time.Now()
	if res := c2get(c, "1.10"); !strings.Contains(res, `"value":true`) {
		t.Fatalf("read %s", res)
	}
	if d := time.Since(start); d > eventTimeout/2 {
		t.Fatalf("read of other controller took %v", d)
	}
	a.expectClosed()
	put(b, `{"characteristics":[{"aid":1,"iid":10,"value":false}]}`)
}

// Events of concurrent writes may come in any order, the last one has the value
// characteristic ended with.
func TestLastEventHasLastValue(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	sub := pairedClient(t, srv, addr, "sub")
	put(sub, `{"characteristics":[{"aid":1,"iid":11,"ev":true}]}`)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for k := range 2 {
		w := addPairing(t, srv, addr, sub, "w"+strconv.Itoa(k), false)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 40 {
				v := strconv.Itoa(2*i + k)
				if _, err := w.do("PUT", "/characteristics", contentJSON,
					[]byte(`{"characteristics":[{"aid":1,"iid":11,"value":`+v+`}]}`)); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var last string
	for {
		sub.nc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := sub.rd.Peek(1); err != nil {
			break
		}
		last = sub.waitEvent()
	}
	want := c2get(sub, "1.11")
	v := want[strings.Index(want, `"value":`):]
	if !strings.Contains(last, v[:strings.IndexAny(v, ",}")]) {
		t.Fatalf("last event %s, value %s", last, want)
	}
}

// stallListener holds writes to its first connection once stalled, until their
// deadline, as to a controller that stopped reading.
type stallListener struct {
	net.Listener
	mu    sync.Mutex
	first *stallConn
}

func (l *stallListener) Accept() (net.Conn, error) {
	nc, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &stallConn{Conn: nc}
	l.mu.Lock()
	if l.first == nil {
		l.first = c
	}
	l.mu.Unlock()
	return c, nil
}

func (l *stallListener) stall() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.first.stalled.Store(true)
}

type stallConn struct {
	net.Conn
	stalled  atomic.Bool
	mu       sync.Mutex
	deadline time.Time
}

func (c *stallConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *stallConn) Write(p []byte) (int, error) {
	if c.stalled.Load() {
		c.mu.Lock()
		d := c.deadline
		c.mu.Unlock()
		time.Sleep(time.Until(d))
		return 0, os.ErrDeadlineExceeded
	}
	return c.Conn.Write(p)
}

func TestMinFreeHeap(t *testing.T) {
	l := newTestLamp()
	srv, err := NewServer(Config{Pin: "031-45-154", MinFreeHeap: 1 << 50}, l.acc)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestController(t, "c")
	c.connect(serve(t, srv))
	c.expectClosed()
}

func TestCheckPin(t *testing.T) {
	for pin, ok := range map[string]bool{
		"031-45-154": true,
		"03145154":   false,
		"031-45-15x": false,
		"111-11-111": false,
		"123-45-678": false,
		"876-54-321": false,
	} {
		if err := checkPin(pin); (err == nil) != ok {
			t.Errorf("%s: %v", pin, err)
		}
	}
}

func TestPairingsEncoding(t *testing.T) {
	pp := []pairing{{id: "a", ltpk: make([]byte, 32), admin: true}, {id: "b", ltpk: make([]byte, 32)}}
	var w tlv.Writer
	encodePairings(&w, pp)
	got, err := decodePairings(w.Data())
	if err != nil || len(got) != 2 || got[0].id != "a" || !got[0].admin || got[1].id != "b" || got[1].admin {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestFsStore(t *testing.T) {
	s := NewFsStore(t.TempDir())
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			val := []byte(strconv.Itoa(i))
			for range 20 {
				if err := s.Set("k", val); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.Get("k"); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
