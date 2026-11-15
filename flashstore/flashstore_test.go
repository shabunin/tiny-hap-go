package flashstore

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/shabunin/tiny-hap-go/accessory"
)

var errPower = errors.New("power lost")

// nor is flash in memory: erase sets bytes to 0xFF, write only clears bits.
// After budget bytes are written or erased, the operation stops halfway and
// every later one fails, as with power lost.
type nor struct {
	t      *testing.T
	mem    []byte
	wbs    int64
	budget int // -1 is unlimited
	writes int
}

func newNOR(t *testing.T, blocks int, wbs int64) *nor {
	d := &nor{t: t, mem: make([]byte, blocks*4096), wbs: wbs, budget: -1}
	rand.New(rand.NewSource(1)).Read(d.mem) // garbage of a previous program
	return d
}

func (d *nor) WriteBlockSize() int64 { return d.wbs }
func (d *nor) EraseBlockSize() int64 { return 4096 }

func (d *nor) ReadAt(p []byte, off int64) (int, error) {
	if d.budget == 0 {
		return 0, errPower
	}
	return copy(p, d.mem[off:]), nil
}

// spend returns how many of n bytes may be changed.
func (d *nor) spend(n int) int {
	if d.budget < 0 {
		return n
	}
	n = min(n, d.budget)
	d.budget -= n
	return n
}

func (d *nor) WriteAt(p []byte, off int64) (int, error) {
	if off%d.wbs != 0 || int64(len(p))%d.wbs != 0 {
		d.t.Fatalf("unaligned write of %d bytes at %d", len(p), off)
	}
	if d.budget == 0 {
		return 0, errPower
	}
	d.writes++
	n := d.spend(len(p))
	for i, c := range p[:n] {
		d.mem[off+int64(i)] &= c
	}
	if n < len(p) {
		return n, errPower
	}
	return n, nil
}

func (d *nor) EraseBlocks(start, length int64) error {
	if d.budget == 0 {
		return errPower
	}
	b := d.mem[start*4096 : (start+length)*4096]
	n := d.spend(len(b))
	for i := range b[:n] {
		b[i] = 0xFF
	}
	if n < len(b) {
		return errPower
	}
	return nil
}

func mount(t *testing.T, d *nor) *Store {
	t.Helper()
	s, err := New(d, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Store, key string) string {
	t.Helper()
	v, err := s.Get(key)
	if errors.Is(err, accessory.ErrNotFound) {
		return "<none>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func TestSetGet(t *testing.T) {
	for _, wbs := range []int64{4, 256} {
		t.Run(fmt.Sprint(wbs), func(t *testing.T) {
			d := newNOR(t, 4, wbs)
			s := mount(t, d)
			if v := get(t, s, "id"); v != "<none>" {
				t.Fatalf("empty store has id %q", v)
			}
			want := map[string]string{}
			r := rand.New(rand.NewSource(2))
			// Enough to fill the block many times: values move between the blocks.
			for i := range 500 {
				key := []string{"id", "key", "pairings", "config"}[r.Intn(4)]
				val := bytes.Repeat([]byte{byte(i)}, r.Intn(300))
				if err := s.Set(key, val); err != nil {
					t.Fatal(i, err)
				}
				want[key] = string(val)
				if i%50 == 0 {
					s = mount(t, d)
				}
				for k, v := range want {
					if got := get(t, s, k); got != v {
						t.Fatalf("set %d: %s is %d bytes, want %d", i, k, len(got), len(v))
					}
				}
			}
			for _, b := range d.mem[:4096] {
				if b != d.mem[0] {
					return
				}
			}
			t.Fatal("store wrote outside its blocks")
		})
	}
}

func TestNoSpace(t *testing.T) {
	d := newNOR(t, 4, 4)
	s := mount(t, d)
	if err := s.Set("pairings", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("pairings", make([]byte, 4096)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("got %v, want ErrNoSpace", err)
	}
	if err := s.Set("id", make([]byte, 4000)); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("pairings", make([]byte, 100)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("got %v, want ErrNoSpace", err)
	}
	s = mount(t, d)
	if v := get(t, s, "pairings"); v != "old" {
		t.Fatalf("pairings %q after failed sets", v)
	}
	if err := s.Set(string(make([]byte, MaxKey+1)), nil); err == nil {
		t.Fatal("long key accepted")
	}
}

// TestPowerLoss cuts power at every byte of a run of sets, then checks that the
// key being set has its old or new value, the others theirs, and the store works.
func TestPowerLoss(t *testing.T) {
	steps := func(n int) []string {
		var vals []string
		for i := range n {
			vals = append(vals, fmt.Sprintf("%d:%s", i, bytes.Repeat([]byte{'a' + byte(i%26)}, 200+i%7*100)))
		}
		return vals
	}
	keys := []string{"pairings", "config", "id"}
	for _, wbs := range []int64{4, 256} {
		t.Run(fmt.Sprint(wbs), func(t *testing.T) {
			nSteps := 40
			step := 7
			if wbs == 256 {
				nSteps = 20
				step = 19
			}
			vals := steps(nSteps)
			run := func(d *nor) (map[string]string, int, error) {
				done := map[string]string{}
				s, err := New(d, 4096)
				if err != nil {
					return done, -1, err
				}
				for i, v := range vals {
					if err := s.Set(keys[i%len(keys)], []byte(v)); err != nil {
						return done, i, err
					}
					done[keys[i%len(keys)]] = v
				}
				return done, len(vals), nil
			}

			full := newNOR(t, 4, wbs)
			full.budget = 1 << 30
			run(full)
			total := 1<<30 - full.budget
			for cut := 0; cut < total; cut += step {
				d := newNOR(t, 4, wbs)
				d.budget = cut
				done, failedAt, err := run(d)
				if !errors.Is(err, errPower) {
					t.Fatalf("cut %d: %v", cut, err)
				}
				d.budget = -1
				s, err := New(d, 4096)
				if err != nil {
					t.Fatalf("cut %d: %v", cut, err)
				}
				for _, k := range keys {
					got, want := get(t, s, k), done[k]
					if want == "" {
						want = "<none>"
					}
					if got == want {
						continue
					}
					if failedAt >= 0 && k == keys[failedAt%len(keys)] && got == vals[failedAt] {
						continue
					}
					t.Fatalf("cut %d at set %d: %s is %.10q, want %.10q", cut, failedAt, k, got, want)
				}
				if err := s.Set("config", []byte("after")); err != nil {
					t.Fatalf("cut %d: set after power loss: %v", cut, err)
				}
				if v := get(t, mount(t, d), "config"); v != "after" {
					t.Fatalf("cut %d: config %q", cut, v)
				}
			}
		})
	}
}

func TestReadError(t *testing.T) {
	d := newNOR(t, 4, 4)
	s := mount(t, d)
	if err := s.Set("id", []byte("12:34")); err != nil {
		t.Fatal(err)
	}
	d.budget = 0
	if _, err := s.Get("id"); !errors.Is(err, errPower) {
		t.Fatalf("got %v, want errPower", err)
	}
}
