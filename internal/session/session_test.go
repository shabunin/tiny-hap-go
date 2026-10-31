package session

import (
	"bytes"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var shared [32]byte
	shared[0] = 1
	for _, size := range []int{0, 1, MaxFrame - 1, MaxFrame, MaxFrame + 1, 3*MaxFrame + 5} {
		acc := NewAccessory(shared)
		msg := bytes.Repeat([]byte{byte(size)}, size)
		sealed := acc.Seal(nil, msg)
		frames := max(1, (size+MaxFrame-1)/MaxFrame)
		if want := size + frames*(2+16); len(sealed) != want {
			t.Fatalf("size %d: sealed %d bytes, want %d", size, len(sealed), want)
		}
		if size == 0 {
			continue // empty frame decrypts to nothing to read
		}
		for _, buf := range [][]byte{nil, make([]byte, FrameSize)} {
			ctrl := NewController(shared)
			got := make([]byte, size)
			if _, err := io.ReadFull(NewReader(ctrl, bytes.NewReader(sealed), buf), got); err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size %d: data differs", size)
			}
		}
	}
}

// Write sends the same frames as Seal, however message is split into parts,
// with its own buffer or one reused for all messages.
func TestWrite(t *testing.T) {
	var shared [32]byte
	reused := make([]byte, FrameSize)
	for _, size := range []int{0, 5, MaxFrame, MaxFrame + 1, 3*MaxFrame + 5} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		want := NewAccessory(shared).Seal(nil, msg)
		for _, cut := range []int{0, min(1, size), size / 2, size} {
			for _, buf := range [][]byte{nil, reused} {
				var got bytes.Buffer
				if err := NewAccessory(shared).Write(&got, buf, msg[:cut], nil, msg[cut:]); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("size %d cut at %d: frames differ from Seal", size, cut)
				}
			}
		}
	}
}

func TestWrongDirection(t *testing.T) {
	var shared [32]byte
	acc := NewAccessory(shared)
	sealed := acc.Seal(nil, []byte("hello"))
	// accessory can't decrypt its own frames: other key
	if _, err := NewReader(NewAccessory(shared), bytes.NewReader(sealed), nil).Read(make([]byte, 5)); err == nil {
		t.Fatal("expected error")
	}
}

func TestCounterOutOfOrder(t *testing.T) {
	var shared [32]byte
	acc, ctrl := NewAccessory(shared), NewController(shared)
	first := acc.Seal(nil, []byte("one"))
	second := acc.Seal(nil, []byte("two"))
	rd := NewReader(ctrl, bytes.NewReader(append(second, first...)), nil)
	if _, err := rd.Read(make([]byte, 3)); err == nil {
		t.Fatal("frame sealed with other counter must fail")
	}
}
