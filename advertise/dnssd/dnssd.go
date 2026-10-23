// Package dnssd announces accessory with mDNS using shabunin/dnssd,
// for Linux, macOS and other systems with full network stack.
package dnssd

import (
	"context"
	"sync"

	"github.com/shabunin/dnssd"
)

// Advertiser implements accessory.Advertiser.
type Advertiser struct {
	mu     sync.Mutex
	rs     dnssd.Responder
	handle dnssd.ServiceHandle
	cancel context.CancelFunc
	port   int
}

// New returns advertiser, it starts responding on first Advertise.
func New() *Advertiser {
	return &Advertiser{}
}

// Advertise announces service, or updates its TXT record.
func (a *Advertiser) Advertise(name string, port int, txt map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handle != nil && a.port == port {
		a.handle.UpdateText(txt, a.rs)
		return nil
	}
	a.stopLocked()

	rs, err := dnssd.NewResponder()
	if err != nil {
		return err
	}
	svc, err := dnssd.NewService(dnssd.Config{Name: name, Type: "_hap._tcp", Port: port, Text: txt})
	if err != nil {
		return err
	}
	h, err := rs.Add(svc)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	go rs.Respond(ctx)
	a.rs, a.handle, a.cancel, a.port = rs, h, cancel, port
	return nil
}

// Stop stops announcing, goodbye packets are sent.
func (a *Advertiser) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopLocked()
}

func (a *Advertiser) stopLocked() {
	if a.cancel != nil {
		a.cancel()
	}
	a.rs, a.handle, a.cancel = nil, nil, nil
}
