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
		acc, ctrl := NewAccessory(shared), NewController(shared)
		msg := bytes.Repeat([]byte{byte(size)}, size)
		sealed := acc.Seal(nil, msg)
		frames := max(1, (size+MaxFrame-1)/MaxFrame)
		if want := size + frames*(2+16); len(sealed) != want {
			t.Fatalf("size %d: sealed %d bytes, want %d", size, len(sealed), want)
		}
		if size == 0 {
			continue // empty frame decrypts to nothing to read
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(NewReader(ctrl, bytes.NewReader(sealed)), got); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: data differs", size)
		}
	}
}

func TestWrongDirection(t *testing.T) {
	var shared [32]byte
	acc := NewAccessory(shared)
	sealed := acc.Seal(nil, []byte("hello"))
	// accessory can't decrypt its own frames: other key
	if _, err := NewReader(NewAccessory(shared), bytes.NewReader(sealed)).Read(make([]byte, 5)); err == nil {
		t.Fatal("expected error")
	}
}

func TestCounterOutOfOrder(t *testing.T) {
	var shared [32]byte
	acc, ctrl := NewAccessory(shared), NewController(shared)
	first := acc.Seal(nil, []byte("one"))
	second := acc.Seal(nil, []byte("two"))
	rd := NewReader(ctrl, bytes.NewReader(append(second, first...)))
	if _, err := rd.Read(make([]byte, 3)); err == nil {
		t.Fatal("frame sealed with other counter must fail")
	}
}
