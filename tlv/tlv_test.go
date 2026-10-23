package tlv

import (
	"bytes"
	"testing"
)

func TestWriteParse(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 600)
	var w Writer
	w.Byte(State, 2)
	w.Bytes(PublicKey, long)
	w.String(Identifier, "ctrl")
	w.Bytes(Proof, nil)

	b := w.Data()
	// 600 bytes take items of 255, 255 and 90
	if want := 3 + (2 + 255) + (2 + 255) + (2 + 90) + 6 + 2; len(b) != want {
		t.Fatalf("length %d, want %d", len(b), want)
	}

	items, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := items.Byte(State); !ok || s != 2 {
		t.Fatalf("state %d %v", s, ok)
	}
	if v, _ := items.Get(PublicKey); !bytes.Equal(v, long) {
		t.Fatalf("public key has %d bytes, want 600", len(v))
	}
	if v, _ := items.Get(Identifier); string(v) != "ctrl" {
		t.Fatalf("identifier %q", v)
	}
	if v, ok := items.Get(Proof); !ok || len(v) != 0 {
		t.Fatalf("empty item %v %v", v, ok)
	}
	if _, ok := items.Get(Salt); ok {
		t.Fatal("missing item found")
	}
}

func TestParseList(t *testing.T) {
	var w Writer
	w.String(Identifier, "a")
	w.Byte(Permissions, 1)
	w.Separator()
	w.String(Identifier, "b")
	w.Byte(Permissions, 0)

	items, err := Parse(w.Data())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, it := range items {
		if it.Type == Identifier {
			ids = append(ids, string(it.Value))
		}
	}
	// short items of same type are not joined
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("ids %v", ids)
	}
}

func TestParseTruncated(t *testing.T) {
	for _, b := range [][]byte{{6}, {6, 2, 1}} {
		if _, err := Parse(b); err == nil {
			t.Fatalf("%v: expected error", b)
		}
	}
}
