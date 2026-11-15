package accessory

import (
	"math"
	"testing"
)

func TestConvert(t *testing.T) {
	bright := NewBrightness()
	temp := NewCurrentTemperature()
	tests := []struct {
		c    *Characteristic
		in   any
		want any
	}{
		{NewOn(), true, true},
		{NewOn(), 1.0, true},
		{NewOn(), 0, false},
		{NewOn(), 2.0, nil},
		{NewOn(), "true", nil},
		{bright, 50.0, int64(50)},
		{bright, uint8(7), int64(7)},
		{bright, 50.5, nil},
		{bright, 101, nil},
		{bright, -1, nil},
		{NewContactState(), 2, nil}, // range 0..1
		{temp, 21.5, 21.5},
		{temp, float32(-3), -3.0},
		{temp, 150.0, nil},
		{temp, math.NaN(), nil},
		{NewName("x"), "kitchen", "kitchen"},
		{NewName("x"), string(make([]byte, 65)), nil},
		{NewCharacteristic("FF", FormatUint8, PermRead, 0), 256, nil},
		{NewCharacteristic("FF", FormatUint8, PermRead, 0), 255, int64(255)},
		{NewCharacteristic("FF", FormatUint64, PermRead, 0), uint64(1 << 50), int64(1 << 50)},
		{NewCharacteristic("FF", FormatUint64, PermRead, 0), uint64(1 << 63), nil},
		{NewCharacteristic("FF", FormatUint64, PermRead, 0), uint64(math.MaxUint64), nil},
		{&Characteristic{Type: "FF", Format: FormatUint8, ValidValues: []int{1, 3}}, 3, int64(3)},
		{&Characteristic{Type: "FF", Format: FormatUint8, ValidValues: []int{1, 3}}, 2, nil},
	}
	for i, tt := range tests {
		got, err := tt.c.convert(tt.in)
		if tt.want == nil {
			if err == nil {
				t.Errorf("%d: %v accepted as %v", i, tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%d: %v converted to %v (%T), %v; want %v", i, tt.in, got, got, err, tt.want)
		}
	}
}

func TestJSONString(t *testing.T) {
	var w jsonWriter
	w.str("a\"b\\c\nd\x01é")
	if got, want := string(w.b), `"a\"b\\c\u000ad\u0001é"`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestOnRead(t *testing.T) {
	c := NewCurrentTemperature()
	c.OnRead = func() any { return 21.5 }
	if c.Value() != 21.5 {
		t.Fatalf("value %v", c.Value())
	}
}
