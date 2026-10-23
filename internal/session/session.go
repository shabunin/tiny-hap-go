// Package session encrypts HAP traffic after pair-verify: data is split into
// frames of at most 1024 bytes, each sealed with its length as additional data
// and a counter as nonce, separately for each direction.
package session

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/shabunin/tiny-hap-go/internal/hapcrypto"
)

// MaxFrame is the max plain length of a frame.
const MaxFrame = 1024

// Session holds keys and counters of both directions.
type Session struct {
	encKey, decKey [32]byte

	emu      sync.Mutex
	encCount uint64

	decCount uint64
}

// NewAccessory returns session of accessory side for shared secret of pair-verify.
func NewAccessory(shared [32]byte) *Session {
	return &Session{
		encKey: hapcrypto.HKDF(shared[:], "Control-Salt", "Control-Read-Encryption-Key"),
		decKey: hapcrypto.HKDF(shared[:], "Control-Salt", "Control-Write-Encryption-Key"),
	}
}

// NewController returns session of controller side.
func NewController(shared [32]byte) *Session {
	return &Session{
		encKey: hapcrypto.HKDF(shared[:], "Control-Salt", "Control-Write-Encryption-Key"),
		decKey: hapcrypto.HKDF(shared[:], "Control-Salt", "Control-Read-Encryption-Key"),
	}
}

// Seal splits plain into frames and appends them to dst.
// Frames have to be written in the same order as they are sealed.
func (s *Session) Seal(dst, plain []byte) []byte {
	s.emu.Lock()
	defer s.emu.Unlock()
	for {
		n := min(len(plain), MaxFrame)
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], uint16(n))
		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], s.encCount)
		s.encCount++
		dst = append(dst, hdr[:]...)
		dst = hapcrypto.Seal(dst, s.encKey, nonce[:], plain[:n], hdr[:])
		plain = plain[n:]
		if len(plain) == 0 {
			return dst
		}
	}
}

var errFrameTooLong = errors.New("session: frame too long")

// Reader decrypts frames read from r. It is not safe for concurrent use.
type Reader struct {
	s     *Session
	r     io.Reader
	frame []byte // sealed frame
	plain []byte // decrypted, not read yet
}

// NewReader returns reader of decrypted data.
func NewReader(s *Session, r io.Reader) *Reader {
	return &Reader{s: s, r: r}
}

func (rd *Reader) Read(p []byte) (int, error) {
	for len(rd.plain) == 0 {
		if err := rd.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, rd.plain)
	rd.plain = rd.plain[n:]
	return n, nil
}

// next reads and decrypts one frame.
func (rd *Reader) next() error {
	var hdr [2]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return err
	}
	n := int(binary.LittleEndian.Uint16(hdr[:]))
	if n > MaxFrame {
		return errFrameTooLong
	}
	if cap(rd.frame) < n+hapcrypto.TagSize {
		rd.frame = make([]byte, MaxFrame+hapcrypto.TagSize)
	}
	frame := rd.frame[:n+hapcrypto.TagSize]
	if _, err := io.ReadFull(rd.r, frame); err != nil {
		return err
	}
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], rd.s.decCount)
	rd.s.decCount++
	plain, err := hapcrypto.Open(rd.s.decKey, nonce[:], frame, hdr[:])
	if err != nil {
		return err
	}
	rd.plain = plain
	return nil
}
