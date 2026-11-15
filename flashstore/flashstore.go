// Package flashstore keeps accessory state in two erase blocks of flash.
//
// Values are appended to one block as records with a checksum, the last record
// of a key wins. When the block is full, the latest records are copied to the
// other block, which becomes active once its header is written. Power loss at
// any moment leaves either the old or the new value of the key being set.
package flashstore

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/shabunin/tiny-hap-go/accessory"
)

// Device is flash as machine.Flash of TinyGo: erased bytes are 0xFF and writes
// only clear bits.
type Device interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	WriteBlockSize() int64
	EraseBlockSize() int64
	// EraseBlocks takes start and length in erase blocks.
	EraseBlocks(start, length int64) error
}

// MaxKey is the longest key.
const MaxKey = 32

// ErrNoSpace is returned by Set when the latest values do not fit a block.
var ErrNoSpace = errors.New("flashstore: no space")

const (
	magic      = 0x53504148 // "HAPS"
	headerLen  = 12         // magic, sequence number and its complement
	recordHead = 8          // key length, value length, checksum
	erased     = 0xFFFF
)

var _ accessory.Store = (*Store)(nil)

// Store is accessory.Store in flash.
type Store struct {
	mu     sync.Mutex
	dev    Device
	off    int64 // first block
	block  int64
	align  int64
	active int64 // 0 or 1
	seq    uint32
	end    int64 // end of valid records in active block
	dirty  bool  // bytes after end are not erased: compact on next Set
	buf    [2 * MaxKey]byte
}

// New returns store in two erase blocks of dev starting at off, which must be
// aligned to erase block. Blocks with no valid store are erased.
func New(dev Device, off int64) (*Store, error) {
	if dev.EraseBlockSize() <= 0 || dev.WriteBlockSize() <= 0 {
		return nil, errors.New("flashstore: invalid block size")
	}
	s := &Store{dev: dev, off: off, block: dev.EraseBlockSize(), align: max(dev.WriteBlockSize(), 4)}
	if off < 0 || off%s.block != 0 {
		return nil, errors.New("flashstore: offset not aligned to erase block")
	}
	if s.block <= s.roundUp(headerLen) {
		return nil, errors.New("flashstore: erase block too small")
	}
	found := false
	for i := range int64(2) {
		seq, ok := s.readHeader(i)
		if ok && (!found || int32(seq-s.seq) > 0) {
			s.active, s.seq, found = i, seq, true
		}
	}
	if !found {
		if err := s.format(0, 1); err != nil {
			return nil, err
		}
		s.active, s.seq = 0, 1
	}
	s.end, s.dirty = s.check()
	return s, nil
}

// Size is the flash taken by store on dev.
func Size(dev Device) int64 { return 2 * dev.EraseBlockSize() }

func (s *Store) base(i int64) int64 { return s.off + i*s.block }

func (s *Store) readHeader(i int64) (uint32, bool) {
	b := s.buf[:headerLen]
	if _, err := s.dev.ReadAt(b, s.base(i)); err != nil {
		return 0, false
	}
	seq := binary.LittleEndian.Uint32(b[4:])
	return seq, binary.LittleEndian.Uint32(b) == magic && ^seq == binary.LittleEndian.Uint32(b[8:])
}

// format erases block i and writes its header.
func (s *Store) format(i int64, seq uint32) error {
	if err := s.dev.EraseBlocks(s.base(i)/s.block, 1); err != nil {
		return err
	}
	return s.writeHeader(i, seq)
}

func (s *Store) writeHeader(i int64, seq uint32) error {
	b := make([]byte, s.roundUp(headerLen))
	for j := range b {
		b[j] = 0xFF
	}
	binary.LittleEndian.PutUint32(b, magic)
	binary.LittleEndian.PutUint32(b[4:], seq)
	binary.LittleEndian.PutUint32(b[8:], ^seq)
	_, err := s.dev.WriteAt(b, s.base(i))
	return err
}

func (s *Store) roundUp(n int64) int64 { return (n + s.align - 1) / s.align * s.align }

// record reads record head at pos of block i.
func (s *Store) record(i, pos int64) (keyLen, valLen int64, sum uint32, err error) {
	b := s.buf[:recordHead]
	if _, err = s.dev.ReadAt(b, s.base(i)+pos); err != nil {
		return
	}
	keyLen = int64(binary.LittleEndian.Uint16(b))
	valLen = int64(binary.LittleEndian.Uint16(b[2:]))
	return keyLen, valLen, binary.LittleEndian.Uint32(b[4:]), nil
}

func (s *Store) recordLen(keyLen, valLen int64) int64 { return s.roundUp(recordHead + keyLen + valLen) }

// check returns end of valid records in active block, and whether anything after
// them is not erased.
func (s *Store) check() (int64, bool) {
	pos := s.roundUp(headerLen)
	for pos+recordHead <= s.block {
		keyLen, valLen, sum, err := s.record(s.active, pos)
		if err != nil {
			return pos, true
		}
		if keyLen == erased && valLen == erased {
			break
		}
		n := s.recordLen(keyLen, valLen)
		if keyLen == 0 || keyLen > MaxKey || pos+n > s.block || s.checksum(s.active, pos, keyLen+valLen) != sum {
			return pos, true
		}
		pos += n
	}
	for p := pos; p < s.block; p += int64(len(s.buf)) {
		b := s.buf[:min(int64(len(s.buf)), s.block-p)]
		if _, err := s.dev.ReadAt(b, s.base(s.active)+p); err != nil {
			return pos, true
		}
		for _, c := range b {
			if c != 0xFF {
				return pos, true
			}
		}
	}
	return pos, false
}

// checksum is FNV-1a over lengths, key and value of record at pos.
func (s *Store) checksum(i, pos, n int64) uint32 {
	h := fnv(2166136261, s.buf[:4])
	for p := pos + recordHead; p < pos+recordHead+n; p += int64(len(s.buf)) {
		b := s.buf[:min(int64(len(s.buf)), pos+recordHead+n-p)]
		if _, err := s.dev.ReadAt(b, s.base(i)+p); err != nil {
			return h ^ 1
		}
		h = fnv(h, b)
	}
	return h
}

func fnv(h uint32, b []byte) uint32 {
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// keyAt compares key of record at pos with key.
func (s *Store) keyAt(pos, keyLen int64, key string) (bool, error) {
	if keyLen != int64(len(key)) {
		return false, nil
	}
	b := s.buf[:keyLen]
	if _, err := s.dev.ReadAt(b, s.base(s.active)+pos+recordHead); err != nil {
		return false, err
	}
	return string(b) == key, nil
}

// find returns position of the latest record of key in active block.
func (s *Store) find(key string) (pos, valLen int64, ok bool, err error) {
	for p := s.roundUp(headerLen); p < s.end; {
		k, v, _, err := s.record(s.active, p)
		if err != nil {
			return 0, 0, false, err
		}
		match, err := s.keyAt(p, k, key)
		if err != nil {
			return 0, 0, false, err
		}
		if match {
			pos, valLen, ok = p, v, true
		}
		p += s.recordLen(k, v)
	}
	return
}

// Get returns accessory.ErrNotFound if key was never set.
func (s *Store) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pos, valLen, ok, err := s.find(key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, accessory.ErrNotFound
	}
	v := make([]byte, valLen)
	_, err = s.dev.ReadAt(v, s.base(s.active)+pos+recordHead+int64(len(key)))
	return v, err
}

// Set appends record, or compacts the block with it when the block is full.
func (s *Store) Set(key string, value []byte) error {
	if len(key) == 0 || len(key) > MaxKey {
		return errors.New("flashstore: bad key length")
	}
	if len(value) >= erased {
		return ErrNoSpace
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := make([]byte, s.recordLen(int64(len(key)), int64(len(value))))
	for i := recordHead + len(key) + len(value); i < len(rec); i++ {
		rec[i] = 0xFF
	}
	binary.LittleEndian.PutUint16(rec, uint16(len(key)))
	binary.LittleEndian.PutUint16(rec[2:], uint16(len(value)))
	copy(rec[recordHead:], key)
	copy(rec[recordHead+len(key):], value)
	binary.LittleEndian.PutUint32(rec[4:], fnv(fnv(2166136261, rec[:4]), rec[recordHead:recordHead+len(key)+len(value)]))
	if s.dirty || s.end+int64(len(rec)) > s.block {
		return s.compact(key, rec)
	}
	if _, err := s.dev.WriteAt(rec, s.base(s.active)+s.end); err != nil {
		s.dirty = true
		return err
	}
	s.end += int64(len(rec))
	return nil
}

// compact copies the latest record of each key but the one of rec to the other
// block, then rec, then writes header of that block to make it active.
func (s *Store) compact(key string, rec []byte) error {
	to := 1 - s.active
	if err := s.dev.EraseBlocks(s.base(to)/s.block, 1); err != nil {
		return err
	}
	dst := s.roundUp(headerLen)
	for p := s.roundUp(headerLen); p < s.end; {
		k, v, _, err := s.record(s.active, p)
		if err != nil {
			return err
		}
		n := s.recordLen(k, v)
		if latest, err := s.latest(p, k, v, key); err != nil {
			return err
		} else if latest {
			b := make([]byte, n)
			if _, err := s.dev.ReadAt(b, s.base(s.active)+p); err != nil {
				return err
			}
			if _, err := s.dev.WriteAt(b, s.base(to)+dst); err != nil {
				return err
			}
			dst += n
		}
		p += n
	}
	if dst+int64(len(rec)) > s.block {
		return ErrNoSpace
	}
	if _, err := s.dev.WriteAt(rec, s.base(to)+dst); err != nil {
		return err
	}
	if err := s.writeHeader(to, s.seq+1); err != nil {
		return err
	}
	s.active, s.seq, s.end, s.dirty = to, s.seq+1, dst+int64(len(rec)), false
	return nil
}

// latest tells if record at pos is the last one of its key, and its key is not skip.
func (s *Store) latest(pos, keyLen, valLen int64, skip string) (bool, error) {
	key := s.buf[MaxKey : MaxKey+keyLen]
	if _, err := s.dev.ReadAt(key, s.base(s.active)+pos+recordHead); err != nil {
		return false, err
	}
	if string(key) == skip {
		return false, nil
	}
	for p := pos + s.recordLen(keyLen, valLen); p < s.end; {
		k, v, _, err := s.record(s.active, p)
		if err != nil {
			return false, err
		}
		match, err := s.keyAt(p, k, string(s.buf[MaxKey:MaxKey+keyLen]))
		if err != nil {
			return false, err
		}
		if match {
			return false, nil
		}
		p += s.recordLen(k, v)
	}
	return true, nil
}
