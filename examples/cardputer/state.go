//go:build tinygo

package main

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/shabunin/tiny-hap-go/accessory"
)

// lampState keeps the lamp in store, so that it comes back as it was after a
// reset or power loss. It is saved once it stopped changing for a few seconds:
// a controller dragging a slider would wear out flash otherwise.
type lampState struct {
	store                           accessory.Store
	on, brightness, hue, saturation *accessory.Characteristic

	saved, last state
	changed     time.Time
}

// state is on, brightness, hue and saturation, both in tenths.
type state [6]byte

const (
	stateKey = "lamp"
	settle   = 3 * time.Second
)

func (l *lampState) state() state {
	var s state
	if l.on.Value().(bool) {
		s[0] = 1
	}
	s[1] = byte(l.brightness.Value().(int64))
	binary.LittleEndian.PutUint16(s[2:], uint16(math.Round(l.hue.Value().(float64)*10)))
	binary.LittleEndian.PutUint16(s[4:], uint16(math.Round(l.saturation.Value().(float64)*10)))
	return s
}

// restore sets characteristics to saved state, before server sends them anywhere.
func (l *lampState) restore() {
	b, err := l.store.Get(stateKey)
	if err == nil && len(b) == len(state{}) {
		l.on.SetValue(b[0] == 1)
		l.brightness.SetValue(int64(b[1]))
		l.hue.SetValue(float64(binary.LittleEndian.Uint16(b[2:])) / 10)
		l.saturation.SetValue(float64(binary.LittleEndian.Uint16(b[4:])) / 10)
	}
	l.saved = l.state()
	l.last = l.saved
}

// update saves state if it changed and then settled. It returns an error of
// saving, nil if there was nothing to save.
func (l *lampState) update(now time.Time) error {
	s := l.state()
	if s != l.last {
		l.last, l.changed = s, now
	}
	if s == l.saved || now.Sub(l.changed) < settle {
		return nil
	}
	if err := l.store.Set(stateKey, s[:]); err != nil {
		return err
	}
	l.saved = s
	return nil
}
