package accessory

import (
	"errors"
	"math"
	"sync"
)

// Accessory is one accessory of the server, a bridge has several.
type Accessory struct {
	ID       uint64 // aid, assigned in order from 1 if zero
	Services []*Service
}

// Service groups characteristics, e.g. lightbulb with on and brightness.
type Service struct {
	ID              uint64 // iid, assigned if zero
	Type            string // short type, e.g. ServiceLightbulb
	Primary         bool
	Hidden          bool
	Characteristics []*Characteristic
}

// Format of characteristic value.
type Format string

const (
	FormatBool   Format = "bool"
	FormatUint8  Format = "uint8"
	FormatUint16 Format = "uint16"
	FormatUint32 Format = "uint32"
	FormatUint64 Format = "uint64"
	FormatInt    Format = "int"
	FormatFloat  Format = "float"
	FormatString Format = "string"
	FormatTLV8   Format = "tlv8" // base64 text
	FormatData   Format = "data" // base64 text
)

// Perm is a set of characteristic permissions.
type Perm uint8

const (
	PermRead           Perm = 1 << iota // pr: controller may read value
	PermWrite                           // pw: controller may write value
	PermEvents                          // ev: controller may subscribe to changes
	PermAdditionalAuth                  // aa
	PermTimedWrite                      // tw: write has to be prepared first
	PermHidden                          // hd: not shown to user
	PermWriteResponse                   // wr: write may return value
)

var permNames = [...]string{"pr", "pw", "ev", "aa", "tw", "hd", "wr"}

// Characteristic is a value of service, e.g. on/off state of lightbulb.
//
// Values are bool, int64 for integer formats, float64 and string.
// SetValue converts other integer and float types.
type Characteristic struct {
	ID          uint64 // iid, assigned if zero
	Type        string // short type, e.g. "25" for On
	Format      Format
	Perms       Perm
	Unit        string // e.g. "percentage", "celsius", "arcdegrees", "lux", "seconds"
	Min, Max    float64
	Step        float64
	HasRange    bool // Min, Max and Step are set
	MaxLen      int  // of string, 64 if zero
	Description string
	ValidValues []int

	// OnWrite is called when controller writes a value, before it is stored.
	// Returned error rejects the write.
	OnWrite func(v any) error

	// OnRead returns current value when controller reads it, e.g. of a sensor.
	// Without it, last stored value is returned.
	OnRead func() any

	mu    sync.Mutex
	value any
	aid   uint64
	srv   *Server
}

// NewCharacteristic returns characteristic with initial value.
func NewCharacteristic(typ string, format Format, perms Perm, value any) *Characteristic {
	c := &Characteristic{Type: typ, Format: format, Perms: perms}
	v, err := c.convert(value)
	if err != nil {
		panic("accessory: initial value of " + typ + ": " + err.Error())
	}
	c.value = v
	return c
}

// WithRange sets min, max and step of numeric value.
func (c *Characteristic) WithRange(min, max, step float64) *Characteristic {
	c.Min, c.Max, c.Step, c.HasRange = min, max, step, true
	return c
}

// WithUnit sets unit of value.
func (c *Characteristic) WithUnit(unit string) *Characteristic {
	c.Unit = unit
	return c
}

// Value returns current value: bool, int64, float64 or string.
func (c *Characteristic) Value() any {
	if c.OnRead != nil {
		if v, err := c.convert(c.OnRead()); err == nil {
			return v
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// SetValue changes value and sends it to subscribed controllers if it changed.
func (c *Characteristic) SetValue(v any) error {
	nv, err := c.convert(v)
	if err != nil {
		return err
	}
	if c.store(nv) && c.srv != nil {
		c.srv.notify(c, nv, nil)
	}
	return nil
}

// store sets value, reports if it changed.
func (c *Characteristic) store(v any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := c.value != v
	c.value = v
	return changed
}

var (
	errType  = errors.New("value has wrong type")
	errRange = errors.New("value out of range")
)

// convert checks value for format and range, converts numbers.
func (c *Characteristic) convert(v any) (any, error) {
	switch c.Format {
	case FormatBool:
		switch b := v.(type) {
		case bool:
			return b, nil
		default:
			// controllers send 0 and 1 too
			f, ok := toFloat(v)
			if !ok || (f != 0 && f != 1) {
				return nil, errType
			}
			return f == 1, nil
		}
	case FormatUint8, FormatUint16, FormatUint32, FormatUint64, FormatInt:
		f, ok := toFloat(v)
		if !ok || f != math.Trunc(f) {
			return nil, errType
		}
		lo, hi := formatRange(c.Format)
		// no builtin min and max of floats: TinyGo for 32-bit ARM Linux fails on them
		if f < lo || f > hi || c.HasRange && (f < c.Min || f > c.Max) {
			return nil, errRange
		}
		if len(c.ValidValues) > 0 && !validValue(c.ValidValues, int(f)) {
			return nil, errRange
		}
		// float64 keeps integers up to 2^53 exactly, enough for HAP values
		return int64(f), nil
	case FormatFloat:
		f, ok := toFloat(v)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errType
		}
		if c.HasRange && (f < c.Min || f > c.Max) {
			return nil, errRange
		}
		return f, nil
	case FormatString, FormatTLV8, FormatData:
		s, ok := v.(string)
		if !ok {
			return nil, errType
		}
		maxLen := c.MaxLen
		if maxLen == 0 && c.Format == FormatString {
			maxLen = 64
		}
		if maxLen > 0 && len(s) > maxLen {
			return nil, errRange
		}
		return s, nil
	}
	return nil, errType
}

func validValue(vv []int, v int) bool {
	for _, x := range vv {
		if x == v {
			return true
		}
	}
	return false
}

func formatRange(f Format) (lo, hi float64) {
	switch f {
	case FormatUint8:
		return 0, math.MaxUint8
	case FormatUint16:
		return 0, math.MaxUint16
	case FormatUint32:
		return 0, math.MaxUint32
	case FormatUint64:
		return 0, math.MaxUint64
	}
	return math.MinInt32, math.MaxInt32
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}
