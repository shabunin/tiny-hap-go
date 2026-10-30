//go:build tinygo

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"
	"tinygo.org/x/espradio"

	"github.com/shabunin/tiny-hap-go/advertise/mdns"
)

const hostname = "cardputer"

// The network stack is set up here rather than with espradio's netlink, to size its
// buffers for the heap: Wi-Fi and the stack would take half of it with the defaults.
var (
	link = espradio.Link{Config: espradio.Config{
		Logging: espradio.LogLevelError,
		// The Wi-Fi blob uses about 34 KB of its pool, and a lamp needs no long
		// receive queue: the defaults are 48 KB and 16 frames.
		ArenaPoolSize: 40 * 1024,
		RxRingSize:    8,
	}}
	stack xnet.Netstack
)

func backoff(uint) time.Duration { return 5 * time.Millisecond }

func connectWiFi(con *console) netip.Addr {
	for {
		con.status("wifi: connecting to "+ssid, yellow)
		err := link.LinkConnect(espradio.STAConfig{SSID: ssid, Password: password})
		if err == nil {
			break
		}
		con.print("wifi: "+err.Error(), red)
		time.Sleep(3 * time.Second)
	}

	nd := link.NetDev()
	hw, err := nd.HardwareAddr6()
	if err == nil {
		err = stack.Reset(xnet.NetstackConfig{
			StackConfig: xnet.StackConfig{
				Hostname:          hostname,
				HardwareAddress:   hw,
				MTU:               1500,
				RandSeed:          time.Now().UnixNano() | 1,
				MaxActiveUDPPorts: 1, // mDNS
				MaxActiveTCPPorts: 1, // HAP
				PassivePeers:      16,
				AcceptMulticast:   true,
			},
			BackoffStack: backoff,
			// HAP frames are at most 1042 bytes: 2 KB to send fits one,
			// half of the 4 KB of espradio's netlink.
			TCPPoolConfig: xnet.TCPPoolConfig{
				PoolSize:           maxConns,
				QueueSize:          maxConns,
				TxBufSize:          2048,
				RxBufSize:          1024,
				EstablishedTimeout: 2 * time.Second,
				ClosingTimeout:     2 * time.Second,
				NewBackoff:         func() lneto.BackoffStrategy { return backoff },
			},
		})
	}
	if err != nil {
		con.print("stack: "+err.Error(), red)
		select {}
	}
	go func() {
		err := espradio.RunStack(context.Background(), nd, &stack)
		con.print("stack stopped: "+err.Error(), red)
	}()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		addr, _, _, err := stack.EnableDHCP(ctx, true, netip.Addr{})
		cancel()
		if err == nil {
			return addr
		}
		con.print("dhcp: "+err.Error(), red)
	}
}

// listen returns TCP listener at the address of the board.
func listen(ip netip.Addr, port uint16) (net.Listener, error) {
	c, err := stack.StackGo().SocketNetip(context.Background(), "tcp4", xnet.AF_INET, xnet.SOCK_STREAM,
		netip.AddrPortFrom(ip, port), netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	ln, ok := c.(net.Listener)
	if !ok {
		return nil, errors.New("stack returned no listener")
	}
	return ln, nil
}

// newAdvertiser starts mDNS responder at the network stack.
func newAdvertiser(ip netip.Addr) *mdns.Responder {
	r := mdns.New(hostname, ip.As4())
	if err := stack.StackAsync().RegisterUDP4(r, mdns.Group, mdns.Port); err != nil {
		println("mdns:", err.Error())
	}
	return r
}
