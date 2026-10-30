//go:build tinygo

package main

import (
	"net/netip"
	"time"

	"tinygo.org/x/drivers/netdev"
	nl "tinygo.org/x/drivers/netlink"
	espnet "tinygo.org/x/espradio/netlink"

	"github.com/shabunin/tiny-hap-go/advertise/mdns"
)

const hostname = "cardputer"

// The Wi-Fi blob uses about 32 KB of its pool, and a lamp needs no long receive queue:
// smaller ones than the defaults of 48 KB and 16 frames leave 20 KB more heap.
var wifi = espnet.Esplink{ArenaPoolSize: 40 * 1024, RxRingSize: 8}

func connectWiFi(con *console) netip.Addr {
	netdev.UseNetdev(&wifi)

	for {
		con.status("wifi: connecting to "+ssid, yellow)

		err := wifi.NetConnect(&nl.ConnectParams{Ssid: ssid, Passphrase: password, Hostname: hostname})
		if err == nil {
			break
		}

		con.print("wifi: "+err.Error(), red)
		time.Sleep(3 * time.Second)
	}

	addr, _ := wifi.Addr()
	return addr
}

// newAdvertiser starts mDNS responder at the network stack of espradio.
func newAdvertiser(ip netip.Addr) *mdns.Responder {
	r := mdns.New(hostname, ip.As4())
	stack := wifi.StackAsync()
	stack.SetAcceptMulticast4(true)
	if err := stack.RegisterUDP4(r, mdns.Group, mdns.Port); err != nil {
		println("mdns:", err.Error())
	}
	return r
}
