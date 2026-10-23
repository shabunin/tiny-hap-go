package accessory

import (
	"strconv"
)

// jsonWriter builds JSON by hand: no reflection, small on microcontrollers.
type jsonWriter struct {
	b []byte
}

func (w *jsonWriter) raw(s string) { w.b = append(w.b, s...) }

func (w *jsonWriter) uint(v uint64) { w.b = strconv.AppendUint(w.b, v, 10) }

func (w *jsonWriter) float(f float64) { w.b = strconv.AppendFloat(w.b, f, 'f', -1, 64) }

// key writes `"name":`, with comma before unless object just started.
func (w *jsonWriter) key(name string) {
	if n := len(w.b); n > 0 && w.b[n-1] != '{' && w.b[n-1] != '[' {
		w.b = append(w.b, ',')
	}
	w.b = append(w.b, '"')
	w.b = append(w.b, name...)
	w.b = append(w.b, '"', ':')
}

// comma separates elements of array.
func (w *jsonWriter) comma() {
	if n := len(w.b); n > 0 && w.b[n-1] != '[' {
		w.b = append(w.b, ',')
	}
}

const hexDigits = "0123456789abcdef"

func (w *jsonWriter) str(s string) {
	w.b = append(w.b, '"')
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\\':
			w.b = append(w.b, '\\', ch)
		case ch < 0x20:
			w.b = append(w.b, '\\', 'u', '0', '0', hexDigits[ch>>4], hexDigits[ch&0xf])
		default:
			w.b = append(w.b, ch)
		}
	}
	w.b = append(w.b, '"')
}

func (w *jsonWriter) value(v any) {
	switch x := v.(type) {
	case bool:
		if x {
			w.raw("true")
		} else {
			w.raw("false")
		}
	case int64:
		w.b = strconv.AppendInt(w.b, x, 10)
	case float64:
		w.float(x)
	case string:
		w.str(x)
	default:
		w.raw("null")
	}
}

// charFields selects optional fields of characteristic.
type charFields struct {
	aid   bool // with accessory id, for /characteristics
	value bool
	typ   bool
	perms bool
	meta  bool // format, unit, range
	ev    *bool
}

var allFields = charFields{value: true, typ: true, perms: true, meta: true}

func (w *jsonWriter) characteristic(c *Characteristic, f charFields) {
	w.raw("{")
	if f.aid {
		w.key("aid")
		w.uint(c.aid)
	}
	w.key("iid")
	w.uint(c.ID)
	if f.typ {
		w.key("type")
		w.str(c.Type)
	}
	if f.perms {
		w.key("perms")
		w.raw("[")
		for i, name := range permNames {
			if c.Perms&(1<<i) != 0 {
				w.comma()
				w.str(name)
			}
		}
		w.raw("]")
	}
	if f.meta {
		w.key("format")
		w.str(string(c.Format))
		if c.Unit != "" {
			w.key("unit")
			w.str(c.Unit)
		}
		if c.HasRange {
			w.key("minValue")
			w.float(c.Min)
			w.key("maxValue")
			w.float(c.Max)
			w.key("minStep")
			w.float(c.Step)
		}
		if c.MaxLen > 0 {
			w.key("maxLen")
			w.uint(uint64(c.MaxLen))
		}
		if len(c.ValidValues) > 0 {
			w.key("valid-values")
			w.raw("[")
			for _, v := range c.ValidValues {
				w.comma()
				w.b = strconv.AppendInt(w.b, int64(v), 10)
			}
			w.raw("]")
		}
		if c.Description != "" {
			w.key("description")
			w.str(c.Description)
		}
	}
	// write-only characteristics, e.g. Identify, have no value
	if f.value && c.Perms&PermRead != 0 {
		w.key("value")
		w.value(c.Value())
	}
	if f.ev != nil {
		w.key("ev")
		w.value(*f.ev)
	}
	w.raw("}")
}

// accessories writes accessory database, without values it describes
// structure only, which changes configuration number when it changes.
func (w *jsonWriter) accessories(accs []*Accessory, values bool) {
	f := allFields
	f.value = values
	w.raw(`{"accessories":[`)
	for _, a := range accs {
		w.comma()
		w.raw("{")
		w.key("aid")
		w.uint(a.ID)
		w.key("services")
		w.raw("[")
		for _, s := range a.Services {
			w.comma()
			w.raw("{")
			w.key("iid")
			w.uint(s.ID)
			w.key("type")
			w.str(s.Type)
			if s.Primary {
				w.key("primary")
				w.raw("true")
			}
			if s.Hidden {
				w.key("hidden")
				w.raw("true")
			}
			w.key("characteristics")
			w.raw("[")
			for _, c := range s.Characteristics {
				w.comma()
				w.characteristic(c, f)
			}
			w.raw("]}")
		}
		w.raw("]}")
	}
	w.raw("]}")
}
