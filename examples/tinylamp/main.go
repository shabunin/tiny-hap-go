// Tinylamp is the lamp without mDNS and file storage, for TinyGo.
// On a board, connect to Wi-Fi before listening and announce the
// accessory with an mDNS responder of the board's network stack.
package main

import (
	"net"

	"github.com/shabunin/tiny-hap-go/accessory"
)

func main() {
	on := accessory.NewOn()
	on.OnWrite = func(v any) error {
		println("on:", v.(bool))
		return nil
	}
	brightness := accessory.NewBrightness()
	lamp := &accessory.Accessory{Services: []*accessory.Service{
		accessory.NewInfoService(accessory.Info{
			Name:         "Tiny Lamp",
			Manufacturer: "tiny-hap-go",
			Model:        "tinylamp",
			SerialNumber: "0001",
			Firmware:     "0.1.0",
		}),
		accessory.NewService(accessory.ServiceLightbulb, accessory.NewName("Tiny Lamp"), on, brightness),
	}}

	srv, err := accessory.NewServer(accessory.Config{
		Pin:      "031-45-154",
		Category: accessory.CategoryLightbulb,
		MaxConns: 4,
	}, lamp)
	if err != nil {
		panic(err)
	}
	ln, err := net.Listen("tcp", ":51901")
	if err != nil {
		panic(err)
	}
	println("accessory", srv.ID(), "listening on :51901")
	if err := srv.Serve(ln); err != nil {
		panic(err)
	}
}
