// Package mdns is a small mDNS responder for boards whose network stack has none,
// e.g. lneto, the stack of espradio on ESP32 and cyw43439 on Pico W.
//
// Responder answers queries for the accessory with all its records at once:
// PTR, SRV, TXT and A, and announces them when they change. It has no probing
// and no known-answer suppression.
//
// Responder is a lneto StackNode without importing lneto, register it for
// multicast group on mDNS port:
//
//	stack.SetAcceptMulticast4(true)
//	stack.RegisterUDP4(r, mdns.Group, mdns.Port)
package mdns

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const Port = 5353

// Group is the multicast address of mDNS.
var Group = [4]byte{224, 0, 0, 251}

const (
	typeA   = 1
	typePTR = 12
	typeTXT = 16
	typeSRV = 33
	typeANY = 255

	classIN    = 1
	cacheFlush = 0x8000

	hostTTL  = 120  // of SRV and A, RFC 6762 10
	otherTTL = 4500 // of PTR and TXT

	minInterval   = time.Second // between multicast answers, RFC 6762 6
	announcements = 2           // sent a second apart, RFC 6762 8.3
)

var serviceType = []string{"_hap", "_tcp", "local"}

// Responder implements accessory.Advertiser and lneto.StackNode.
type Responder struct {
	connID atomic.Uint32

	mu   sync.Mutex
	host string // label of host name, e.g. "cardputer" for cardputer.local
	ip   [4]byte
	name string
	port uint16
	txt  []byte

	answer   bool // query is waiting for answer
	announce int  // announcements left
	sent     time.Time
}

// New returns responder for host name, e.g. "cardputer" for cardputer.local, at IPv4 address.
// It answers after the first Advertise.
func New(host string, ip [4]byte) *Responder {
	return &Responder{host: host, ip: ip}
}

// Advertise sets service name, port and TXT record, and announces them.
func (r *Responder) Advertise(name string, port int, txt map[string]string) error {
	if name == "" || len(name) > 63 || len(r.host) == 0 || len(r.host) > 63 {
		return errors.New("mdns: name and host name must have 1 to 63 bytes")
	}
	if port <= 0 || port > 65535 {
		return errors.New("mdns: port out of range")
	}
	b, err := encodeTXT(txt)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.name, r.port, r.txt = name, uint16(port), b
	r.announce = announcements
	r.sent = time.Time{}
	return nil
}

// encodeTXT returns TXT record data: key=value strings with length byte, sorted by key.
func encodeTXT(txt map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(txt))
	for k := range txt {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b []byte
	for _, k := range keys {
		n := len(k) + 1 + len(txt[k])
		if n > 255 {
			return nil, errors.New("mdns: TXT entry " + k + " is too long")
		}
		b = append(b, byte(n))
		b = append(b, k...)
		b = append(b, '=')
		b = append(b, txt[k]...)
	}
	return b, nil
}

// LocalPort is a method of lneto.StackNode.
func (r *Responder) LocalPort() uint16 { return Port }

// Protocol is a method of lneto.StackNode: UDP.
func (r *Responder) Protocol() uint64 { return 17 }

// ConnectionID is a method of lneto.StackNode.
func (r *Responder) ConnectionID() *atomic.Uint32 { return &r.connID }

// Demux reads mDNS message at carrierData[frameOffset:] and answers questions about accessory.
func (r *Responder) Demux(carrierData []byte, frameOffset int) error {
	if frameOffset < 0 || frameOffset > len(carrierData) {
		return nil
	}
	msg := carrierData[frameOffset:]
	if len(msg) < 12 || msg[2]&0x80 != 0 || msg[2]&0x78 != 0 {
		return nil // not a standard query
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.name == "" {
		return nil
	}
	off := 12
	for range int(msg[4])<<8 | int(msg[5]) {
		spans, count, end, ok := readName(msg, off)
		if !ok || end+4 > len(msg) {
			return nil
		}
		typ := int(msg[end])<<8 | int(msg[end+1])
		off = end + 4
		if r.matches(msg, spans, count, typ) {
			r.answer = true
		}
	}
	return nil
}

// matches tells if question is about service type, accessory or its host.
func (r *Responder) matches(msg []byte, spans [4][2]int, count, typ int) bool {
	service := count == 3 && equalLabels(msg, spans[:3], serviceType)
	instance := count == 4 && equalFoldASCII(msg[spans[0][0]:spans[0][1]], r.name) && equalLabels(msg, spans[1:4], serviceType)
	host := count == 2 && equalFoldASCII(msg[spans[0][0]:spans[0][1]], r.host) && equalFoldASCII(msg[spans[1][0]:spans[1][1]], "local")
	switch typ {
	case typePTR:
		return service
	case typeSRV, typeTXT:
		return instance
	case typeA:
		return host
	case typeANY:
		return service || instance || host
	}
	return false
}

func equalLabels(msg []byte, spans [][2]int, target []string) bool {
	if len(spans) != len(target) {
		return false
	}
	for i, sp := range spans {
		if !equalFoldASCII(msg[sp[0]:sp[1]], target[i]) {
			return false
		}
	}
	return true
}

func equalFoldASCII(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i, c := range b {
		d := s[i]
		if c == d {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if d >= 'A' && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}

// readName walks name at off, following compression pointers.
// It returns up to 4 label spans, total label count, and offset after the name where it started.
func readName(msg []byte, off int) (spans [4][2]int, count, end int, ok bool) {
	end = -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return spans, 0, 0, false
		}
		n := int(msg[off])
		switch {
		case n == 0:
			if end < 0 {
				end = off + 1
			}
			return spans, count, end, true
		case n&0xC0 == 0xC0:
			if off+1 >= len(msg) || jumps > 10 {
				return spans, 0, 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = (n&0x3F)<<8 | int(msg[off+1])
			jumps++
		case n&0xC0 != 0:
			return spans, 0, 0, false
		default:
			if off+1+n > len(msg) {
				return spans, 0, 0, false
			}
			if count < len(spans) {
				spans[count] = [2]int{off + 1, off + 1 + n}
			}
			count++
			off += 1 + n
		}
	}
}

// Encapsulate writes answer or announcement into carrierData[offsetToFrame:]
// if one is due. Stack sends it to the group.
func (r *Responder) Encapsulate(carrierData []byte, offsetToIP, offsetToFrame int) (int, error) {
	if offsetToFrame < 0 || offsetToFrame > len(carrierData) {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.name == "" || !r.answer && r.announce == 0 {
		return 0, nil
	}
	now := time.Now()
	if now.Sub(r.sent) < minInterval {
		return 0, nil
	}
	avail := len(carrierData) - offsetToFrame
	msg := r.appendResponse(carrierData[offsetToFrame:offsetToFrame:len(carrierData)])
	if len(msg) > avail {
		// Drop oversized response so subsequent ticks do not spin allocating it.
		r.answer = false
		r.announce = 0
		return 0, nil
	}
	if r.announce > 0 {
		r.announce--
	}
	r.answer = false
	r.sent = now
	if offsetToIP >= 14 {
		// destination MAC of group: 01:00:5e and low 23 bits of its address
		copy(carrierData[:6], []byte{0x01, 0x00, 0x5e, Group[1] & 0x7f, Group[2], Group[3]})
	}
	return len(msg), nil
}

// appendResponse appends response with all records: PTR, SRV, TXT and A.
func (r *Responder) appendResponse(b []byte) []byte {
	// id 0, flags: response, authoritative; 4 answers
	b = append(b, 0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0)

	instance := append([]string{r.name}, serviceType...)
	host := []string{r.host, "local"}

	b = appendRecord(b, serviceType, typePTR, classIN, otherTTL)
	b = appendData(b, func(b []byte) []byte { return appendName(b, instance) })

	b = appendRecord(b, instance, typeSRV, classIN|cacheFlush, hostTTL)
	b = appendData(b, func(b []byte) []byte {
		b = append(b, 0, 0, 0, 0, byte(r.port>>8), byte(r.port)) // priority, weight, port
		return appendName(b, host)
	})

	b = appendRecord(b, instance, typeTXT, classIN|cacheFlush, otherTTL)
	b = appendData(b, func(b []byte) []byte { return append(b, r.txt...) })

	b = appendRecord(b, host, typeA, classIN|cacheFlush, hostTTL)
	return appendData(b, func(b []byte) []byte { return append(b, r.ip[:]...) })
}

func appendName(b []byte, labels []string) []byte {
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func appendRecord(b []byte, name []string, typ, class int, ttl uint32) []byte {
	b = appendName(b, name)
	return append(b, byte(typ>>8), byte(typ), byte(class>>8), byte(class),
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
}

// appendData appends record data written by f, after its length.
func appendData(b []byte, f func([]byte) []byte) []byte {
	start := len(b)
	b = f(append(b, 0, 0))
	n := len(b) - start - 2
	b[start], b[start+1] = byte(n>>8), byte(n)
	return b
}
