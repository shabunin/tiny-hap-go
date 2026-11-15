// Lamp is a dimmable lightbulb accessory, announced with mDNS.
// Pair it from Home app or another HomeKit controller with setup code 031-45-154.
package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/shabunin/tiny-hap-go/accessory"
	"github.com/shabunin/tiny-hap-go/advertise/dnssd"
)

func main() {
	store := flag.String("store", "./lamp-store", "directory for keys and pairings")
	addr := flag.String("addr", ":0", "address to listen on")
	pin := flag.String("pin", "031-45-154", "setup code")
	debug := flag.Bool("debug", false, "print debug log")
	flag.Parse()
	if *debug {
		accessory.SetLogger(log.Printf)
	}

	on := accessory.NewOn()
	on.OnWrite = func(v any) error {
		log.Println("on:", v)
		return nil
	}
	brightness := accessory.NewBrightness()
	brightness.OnWrite = func(v any) error {
		log.Println("brightness:", v)
		return nil
	}
	lamp := &accessory.Accessory{Services: []*accessory.Service{
		accessory.NewInfoService(accessory.Info{
			Name:         "Tiny Lamp",
			Manufacturer: "tiny-hap-go",
			Model:        "lamp",
			SerialNumber: "0001",
			Firmware:     "0.1.0",
		}),
		accessory.NewProtocolInfoService(),
		accessory.NewService(accessory.ServiceLightbulb, accessory.NewName("Tiny Lamp"), on, brightness),
	}}

	srv, err := accessory.NewServer(accessory.Config{
		Pin:        *pin,
		Category:   accessory.CategoryLightbulb,
		Store:      accessory.NewFsStore(*store),
		Advertiser: dnssd.New(),
		OnIdentify: func() { log.Println("identify") },
	}, lamp)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("accessory %s on %s, paired: %v, setup code %s", srv.ID(), ln.Addr(), srv.IsPaired(), *pin)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}
