package mdns

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const ipOffset, udpOffset = 14, 14 + 20 + 8 // of Ethernet carrier

func query(t *testing.T, r *Responder, name string, typ uint16) {
	t.Helper()
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: name, Qtype: typ, Qclass: dns.ClassINET | 1<<15}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Demux(append(make([]byte, udpOffset), b...), udpOffset); err != nil {
		t.Fatal(err)
	}
}

// response returns message the responder sends now, nil if none.
func response(t *testing.T, r *Responder) *dns.Msg {
	t.Helper()
	carrier := make([]byte, 1514)
	n, err := r.Encapsulate(carrier, ipOffset, udpOffset)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return nil
	}
	if mac := net.HardwareAddr(carrier[:6]).String(); mac != "01:00:5e:00:00:fb" {
		t.Errorf("destination MAC %s", mac)
	}
	m := new(dns.Msg)
	if err := m.Unpack(carrier[udpOffset : udpOffset+n]); err != nil {
		t.Fatal(err)
	}
	return m
}

func newResponder(t *testing.T) *Responder {
	r := New("cardputer", [4]byte{192, 168, 2, 26})
	err := r.Advertise("Tiny Lamp", 51826, map[string]string{"id": "4B:47:CA:CA:DC:71", "sf": "1", "c#": "1"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAnnounce(t *testing.T) {
	r := newResponder(t)
	m := response(t, r)
	if m == nil {
		t.Fatal("no announcement")
	}
	if !m.Response || !m.Authoritative || len(m.Answer) != 4 {
		t.Fatalf("announcement:\n%v", m)
	}

	ptr := m.Answer[0].(*dns.PTR)
	if ptr.Hdr.Name != "_hap._tcp.local." || ptr.Ptr != `Tiny\ Lamp._hap._tcp.local.` {
		t.Errorf("PTR %v", ptr)
	}
	srv := m.Answer[1].(*dns.SRV)
	if srv.Port != 51826 || srv.Target != "cardputer.local." || srv.Hdr.Class != dns.ClassINET|1<<15 {
		t.Errorf("SRV %v", srv)
	}
	txt := m.Answer[2].(*dns.TXT)
	if want := []string{"c#=1", "id=4B:47:CA:CA:DC:71", "sf=1"}; len(txt.Txt) != 3 || txt.Txt[0] != want[0] ||
		txt.Txt[1] != want[1] || txt.Txt[2] != want[2] {
		t.Errorf("TXT %v", txt.Txt)
	}
	a := m.Answer[3].(*dns.A)
	if a.Hdr.Name != "cardputer.local." || a.A.String() != "192.168.2.26" {
		t.Errorf("A %v", a)
	}

	// second announcement comes a second later
	if m := response(t, r); m != nil {
		t.Fatal("announced again at once")
	}
	r.sent = r.sent.Add(-minInterval)
	if m := response(t, r); m == nil {
		t.Fatal("no second announcement")
	}
	r.sent = r.sent.Add(-minInterval)
	if m := response(t, r); m != nil {
		t.Fatal("third announcement")
	}
}

func TestAnswer(t *testing.T) {
	r := newResponder(t)
	r.announce = 0
	r.sent = time.Now().Add(-minInterval)

	for _, q := range []struct {
		name   string
		typ    uint16
		answer bool
	}{
		{"_hap._tcp.local.", dns.TypePTR, true},
		{"_HAP._tcp.local.", dns.TypePTR, true},
		{`Tiny\ Lamp._hap._tcp.local.`, dns.TypeSRV, true},
		{`tiny\ lamp._hap._tcp.local.`, dns.TypeTXT, true},
		{"cardputer.local.", dns.TypeA, true},
		{"cardputer.local.", dns.TypeANY, true},
		{"_hap._tcp.local.", dns.TypeSRV, false},
		{"_http._tcp.local.", dns.TypePTR, false},
		{"other.local.", dns.TypeA, false},
		{`Other._hap._tcp.local.`, dns.TypeSRV, false},
	} {
		query(t, r, q.name, q.typ)
		m := response(t, r)
		if (m != nil) != q.answer {
			t.Errorf("%s %s: answered %v", q.name, dns.TypeToString[q.typ], m != nil)
		}
		r.sent = time.Now().Add(-minInterval)
	}
}

func TestUpdate(t *testing.T) {
	r := newResponder(t)
	response(t, r)
	if err := r.Advertise("Tiny Lamp", 51826, map[string]string{"sf": "0", "c#": "12"}); err != nil {
		t.Fatal(err)
	}
	r.sent = r.sent.Add(-minInterval)
	m := response(t, r)
	if m == nil {
		t.Fatal("change not announced")
	}
	if txt := m.Answer[2].(*dns.TXT).Txt; len(txt) != 2 || txt[0] != "c#=12" || txt[1] != "sf=0" {
		t.Errorf("TXT %v", txt)
	}
}

func TestMalformed(t *testing.T) {
	r := newResponder(t)
	for _, b := range [][]byte{
		{0, 0, 0, 0, 0, 1},                               // short header
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a'},     // label past end
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12},   // pointer loop
		{0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}, // missing questions
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x80, 0, 0}, // bad label type
	} {
		if err := r.Demux(b, 0); err != nil {
			t.Error(err)
		}
	}
}

func TestZeroAllocDemux(t *testing.T) {
	r := newResponder(t)
	r.announce = 0
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: `Tiny\ Lamp._hap._tcp.local.`, Qtype: dns.TypeSRV, Qclass: dns.ClassINET}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	pkt := append(make([]byte, udpOffset), b...)
	if n := testing.AllocsPerRun(50, func() {
		if err := r.Demux(pkt, udpOffset); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("Demux allocated %g times, want 0", n)
	}
}

func TestOversizedAndValidation(t *testing.T) {
	r := newResponder(t)
	if err := r.Advertise("Lamp", 0, nil); err == nil {
		t.Fatal("port 0 accepted")
	}
	if err := r.Advertise("Lamp", 70000, nil); err == nil {
		t.Fatal("port > 65535 accepted")
	}

	// Non-query opcode (e.g. Update=5) is ignored.
	r.announce = 0
	m := new(dns.Msg)
	m.Opcode = dns.OpcodeUpdate
	m.Question = []dns.Question{{Name: "_hap._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Demux(b, 0); err != nil {
		t.Fatal(err)
	}
	if r.answer {
		t.Fatal("non-query opcode answered")
	}

	// Oversized response clears pending flags rather than retrying every tick.
	r.answer = true
	r.announce = 2
	small := make([]byte, udpOffset+16)
	if n, err := r.Encapsulate(small, ipOffset, udpOffset); err != nil || n != 0 {
		t.Fatalf("oversized Encapsulate returned (%d, %v)", n, err)
	}
	if r.answer || r.announce != 0 {
		t.Fatalf("oversized response left pending flags: answer=%v announce=%d", r.answer, r.announce)
	}
}

func TestAdvertiseTooLarge(t *testing.T) {
	r := newResponder(t)
	txt := map[string]string{}
	for i := range 8 {
		txt[fmt.Sprint("k", i)] = strings.Repeat("v", 200)
	}
	if err := r.Advertise("Lamp", 51826, txt); err == nil {
		t.Fatal("response larger than a packet accepted")
	}
	if r.name != "Tiny Lamp" {
		t.Fatalf("failed Advertise changed name to %q", r.name)
	}
}

func TestStop(t *testing.T) {
	r := newResponder(t)
	r.Stop()
	carrier := make([]byte, 1500)
	if n, err := r.Encapsulate(carrier, ipOffset, udpOffset); err != nil || n != 0 {
		t.Fatalf("stopped responder sent %d bytes, %v", n, err)
	}
	if err := r.Advertise("Tiny Lamp", 51826, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := r.Encapsulate(carrier, ipOffset, udpOffset); err != nil || n == 0 {
		t.Fatalf("responder did not announce after Advertise: %d, %v", n, err)
	}
}
