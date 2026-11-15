package accessory

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/shabunin/tiny-hap-go/tlv"
)

func TestPairSetupMaxTries(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := newTestController(t, "ctrl")
	c.connect(addr)
	var terr tlvErr
	if _, _, err := c.pairSetup("111-22-333"); !errors.As(err, &terr) || byte(terr) != tlv.ErrAuthentication {
		t.Fatalf("wrong pin: %v", err)
	}
	srv.mu.Lock()
	failed := srv.failed
	srv.failed = maxFailed
	srv.mu.Unlock()
	if failed != 1 {
		t.Fatalf("wrong pin counted %d times, want 1", failed)
	}
	// After too many wrong pins even the right one is refused.
	if _, _, err := c.pairSetup("031-45-154"); !errors.As(err, &terr) || byte(terr) != tlv.ErrMaxTries {
		t.Fatalf("expected max tries error, got %v", err)
	}
	if srv.IsPaired() {
		t.Fatal("paired after max tries")
	}
}

func TestPairSetupOutOfOrder(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := newTestController(t, "ctrl")
	c.connect(addr)
	for _, state := range []byte{3, 5} {
		var w tlv.Writer
		w.Byte(tlv.State, state)
		w.Bytes(tlv.PublicKey, make([]byte, 384))
		w.Bytes(tlv.Proof, make([]byte, 64))
		w.Bytes(tlv.EncryptedData, make([]byte, 64))
		items, err := c.postTLV("/pair-setup", &w)
		if err != nil {
			t.Fatal(err)
		}
		var terr tlvErr
		if err := itemsError(items); !errors.As(err, &terr) || byte(terr) != tlv.ErrUnknown {
			t.Fatalf("M%d without earlier steps: %v", state, err)
		}
		if s, _ := items.Byte(tlv.State); s != state+1 {
			t.Fatalf("M%d answered with state %d", state, s)
		}
	}
	if srv.IsPaired() {
		t.Fatal("paired out of order")
	}
	// The connection can still pair properly afterwards.
	if _, _, err := c.pairSetup("031-45-154"); err != nil {
		t.Fatal(err)
	}
}

func TestPairSetupBadSignature(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := newTestController(t, "ctrl")
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.ltpk = other // signed with ltsk that does not match the key sent in M5
	c.connect(addr)
	var terr tlvErr
	if _, _, err := c.pairSetup("031-45-154"); !errors.As(err, &terr) || byte(terr) != tlv.ErrAuthentication {
		t.Fatalf("expected authentication error, got %v", err)
	}
	if srv.IsPaired() {
		t.Fatal("paired with bad signature")
	}
}

type failGetStore struct {
	Store
	failKey string
}

func (s *failGetStore) Get(key string) ([]byte, error) {
	if key == s.failKey {
		return nil, errors.New("flash read error")
	}
	return s.Store.Get(key)
}

func TestIdentityKeptOnStoreReadError(t *testing.T) {
	for _, failKey := range []string{"id", "key"} {
		t.Run(failKey, func(t *testing.T) {
			mem := NewMemStore()
			// One key is missing and the other cannot be read: the server must not
			// take that as a new accessory and write a new identity.
			store := &failGetStore{Store: mem, failKey: failKey}
			if _, err := NewServer(Config{Pin: "031-45-154", Store: store}, newTestLamp().acc); err == nil {
				t.Fatal("NewServer succeeded despite store read error")
			}
			for _, k := range []string{"id", "key"} {
				if _, err := mem.Get(k); !errors.Is(err, ErrNotFound) {
					t.Fatalf("%s was written after read error: %v", k, err)
				}
			}
		})
	}
}

func TestPlaintextAfterVerifyM3(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := pairedClient(t, srv, addr, "ctrl")
	c.connect(addr)
	// The request after M3 is sent in plain together with M3. The accessory
	// must not take it as encrypted traffic: it answers M4 and closes.
	posts := 0
	c.tamper = func(req []byte) []byte {
		if posts++; posts == 2 {
			return append(req, "GET /accessories HTTP/1.1\r\nHost: x\r\n\r\n"...)
		}
		return req
	}
	if err := c.pairVerify(srv.ltpk); err != nil {
		t.Fatal(err)
	}
	c.tamper = nil
	c.expectClosed()
}

func TestPairingLimits(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	a := pairedClient(t, srv, addr, "a")

	b := newTestController(t, "b")
	if err := updatePairingPerm(t, a, "b", b.ltpk, false); err != nil {
		t.Fatal(err)
	}
	// Same id with another key is refused, the stored key stays.
	other := newTestController(t, "b")
	var terr tlvErr
	if err := updatePairingPerm(t, a, "b", other.ltpk, true); !errors.As(err, &terr) || byte(terr) != tlv.ErrUnknown {
		t.Fatalf("key of b replaced: %v", err)
	}

	for i := 2; i < maxPairings; i++ {
		c := newTestController(t, "")
		if err := updatePairingPerm(t, a, fmt.Sprint("c", i), c.ltpk, false); err != nil {
			t.Fatalf("pairing %d: %v", i+1, err)
		}
	}
	extra := newTestController(t, "")
	if err := updatePairingPerm(t, a, "extra", extra.ltpk, false); !errors.As(err, &terr) || byte(terr) != tlv.ErrMaxPeers {
		t.Fatalf("pairing over %d: %v", maxPairings, err)
	}
	pp, err := listPairings(t, a)
	if err != nil || len(pp) != maxPairings {
		t.Fatalf("%d pairings, %v", len(pp), err)
	}
	if !bytes.Equal(pp[1].ltpk, b.ltpk) || pp[1].admin {
		t.Fatalf("pairing of b changed: %+v", pp[1])
	}
}

func TestBadRequests(t *testing.T) {
	_, addr, _ := testServer(t, nil)
	long := strings.Repeat("a", maxLine+1)
	many := strings.Repeat("X-A: 1\r\n", maxHeaders+1)
	for _, tt := range []struct{ name, req string }{
		{"no protocol", "GET /accessories\r\n\r\n"},
		{"not http", "GET /accessories SPDY/3\r\n\r\n"},
		{"long line", "GET /" + long + " HTTP/1.1\r\n\r\n"},
		{"many headers", "GET /accessories HTTP/1.1\r\n" + many + "\r\n"},
		{"header without colon", "GET /accessories HTTP/1.1\r\nHost\r\n\r\n"},
		{"negative length", "POST /pair-setup HTTP/1.1\r\nContent-Length: -1\r\n\r\n"},
		{"length not number", "POST /pair-setup HTTP/1.1\r\nContent-Length: 1e3\r\n\r\n"},
		{"body too large", fmt.Sprintf("POST /pair-setup HTTP/1.1\r\nContent-Length: %d\r\n\r\n", maxBody+1)},
		{"chunked", "POST /pair-setup HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestController(t, "c")
			c.connect(addr)
			if _, err := c.nc.Write([]byte(tt.req)); err != nil {
				t.Fatal(err)
			}
			c.expectClosed()
		})
	}
}

func TestMethodAndPath(t *testing.T) {
	srv, addr, _ := testServer(t, nil)
	c := newTestController(t, "c")
	c.connect(addr)
	for _, tt := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/pair-setup", 405},
		{"GET", "/pair-verify", 405},
		{"GET", "/identify", 405},
		{"GET", "/nothing", 470}, // unverified: nothing past this point is revealed
	} {
		if res := c.mustDo(tt.method, tt.path, "", nil); res.status != tt.status {
			t.Fatalf("%s %s: status %d, want %d", tt.method, tt.path, res.status, tt.status)
		}
	}

	v := pairedClient(t, srv, addr, "v")
	for _, tt := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/pairings", 405},
		{"POST", "/accessories", 405},
		{"POST", "/characteristics", 405},
		{"GET", "/nothing", 404},
	} {
		if res := v.mustDo(tt.method, tt.path, "", nil); res.status != tt.status {
			t.Fatalf("%s %s: status %d, want %d", tt.method, tt.path, res.status, tt.status)
		}
	}
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte("GET /accessories HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte("PUT /characteristics HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("POST /pair-setup HTTP/1.1\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: 6\r\n\r\n\x06\x01\x01\x00\x01\x00"))
	f.Add([]byte("GET /characteristics?id=1.10,1.11 HTTP/1.0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		rd := bufio.NewReaderSize(bytes.NewReader(b), 512)
		for range 4 {
			req, err := readRequest(rd, nil)
			if err != nil {
				return
			}
			if len(req.body) > maxBody {
				t.Fatalf("body of %d bytes", len(req.body))
			}
			if len(req.method)+len(req.path)+len(req.query) > len(b) {
				t.Fatal("request longer than input")
			}
		}
	})
}
