// Package tlv reads and writes TLV8 items of HAP pairing messages
// without reflection, so it stays small on microcontrollers.
package tlv

import "errors"

// Item types of pairing messages.
const (
	Method        byte = 0x00
	Identifier    byte = 0x01
	Salt          byte = 0x02
	PublicKey     byte = 0x03
	Proof         byte = 0x04
	EncryptedData byte = 0x05
	State         byte = 0x06
	Error         byte = 0x07
	RetryDelay    byte = 0x08
	Certificate   byte = 0x09
	Signature     byte = 0x0a
	Permissions   byte = 0x0b
	FragmentData  byte = 0x0c
	FragmentLast  byte = 0x0d
	Flags         byte = 0x13
	Separator     byte = 0xff
)

// Error codes.
const (
	ErrUnknown        byte = 0x01
	ErrAuthentication byte = 0x02
	ErrBackoff        byte = 0x03
	ErrMaxPeers       byte = 0x04
	ErrMaxTries       byte = 0x05
	ErrUnavailable    byte = 0x06
	ErrBusy           byte = 0x07
)

// Writer appends items to a message.
type Writer struct {
	b []byte
}

// Byte appends item with one byte value.
func (w *Writer) Byte(typ, v byte) {
	w.b = append(w.b, typ, 1, v)
}

// Bytes appends item, values longer than 255 bytes are split into
// several items of the same type.
func (w *Writer) Bytes(typ byte, v []byte) {
	for {
		n := min(len(v), 255)
		w.b = append(w.b, typ, byte(n))
		w.b = append(w.b, v[:n]...)
		v = v[n:]
		if len(v) == 0 {
			return
		}
	}
}

// String appends item with text value.
func (w *Writer) String(typ byte, s string) {
	w.Bytes(typ, []byte(s))
}

// Separator separates items of a list, e.g. pairings.
func (w *Writer) Separator() {
	w.b = append(w.b, Separator, 0)
}

// Data returns the message.
func (w *Writer) Data() []byte {
	return w.b
}

// Item is one value of a message, fragments are already joined.
type Item struct {
	Type  byte
	Value []byte
}

// Items of a message in their order.
type Items []Item

var errTruncated = errors.New("tlv: truncated item")

// Parse splits message into items. Consecutive items of the same type
// are joined when the previous one is 255 bytes long.
func Parse(b []byte) (Items, error) {
	var items Items
	prevFull := false
	for len(b) > 0 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, errTruncated
		}
		typ, v := b[0], b[2:2+int(b[1])]
		b = b[2+len(v):]
		if prevFull && len(items) > 0 && items[len(items)-1].Type == typ {
			last := &items[len(items)-1]
			last.Value = append(last.Value, v...)
		} else {
			items = append(items, Item{Type: typ, Value: v})
		}
		prevFull = len(v) == 255
	}
	return items, nil
}

// Get returns value of the first item of type.
func (items Items) Get(typ byte) ([]byte, bool) {
	for _, it := range items {
		if it.Type == typ {
			return it.Value, true
		}
	}
	return nil, false
}

// Byte returns one byte value of the first item of type.
func (items Items) Byte(typ byte) (byte, bool) {
	v, ok := items.Get(typ)
	if !ok || len(v) != 1 {
		return 0, false
	}
	return v[0], true
}
