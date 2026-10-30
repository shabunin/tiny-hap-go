//go:build tinygo

// Command cardputer makes the M5Stack Cardputer (ESP32-S3) a HomeKit color lamp:
// it joins Wi-Fi, announces itself with mDNS and shows the lamp on its screen.
// Pair it from Home app or hkontroller with setup code 031-45-154.
//
//	tinygo flash -target=m5stamp-s3a -port /dev/ttyACM0 \
//	  -ldflags "-X main.ssid=SSID -X main.password=PASSWORD" .
package main

import (
	"net"
	"strconv"
	"time"

	"github.com/shabunin/tiny-hap-go/accessory"
)

// Set at build time: -ldflags "-X main.ssid=... -X main.password=...".
var (
	ssid     string
	password string
)

const (
	pin  = "031-45-154"
	port = 51826
)

func main() {
	con := newConsole(openDisplay())
	con.status("tiny-hap-go  cardputer", cyan)

	if ssid == "" {
		con.print("built without -X main.ssid", red)
		select {}
	}

	ip := connectWiFi(con)
	con.print("wifi: "+ip.String(), green)

	accessory.SetLogger(func(format string, args ...any) { println(format) })

	// Writes come from connection goroutines, the screen is drawn here only.
	changed := make(chan struct{}, 1)
	onWrite := func(any) error {
		select {
		case changed <- struct{}{}:
		default:
		}
		return nil
	}

	on := accessory.NewOn()
	brightness := accessory.NewBrightness()
	hue := accessory.NewCharacteristic("13", accessory.FormatFloat,
		accessory.PermRead|accessory.PermWrite|accessory.PermEvents, 0.0).
		WithRange(0, 360, 1).WithUnit("arcdegrees")
	saturation := accessory.NewCharacteristic("2F", accessory.FormatFloat,
		accessory.PermRead|accessory.PermWrite|accessory.PermEvents, 0.0).
		WithRange(0, 100, 1).WithUnit("percentage")
	for _, c := range []*accessory.Characteristic{on, brightness, hue, saturation} {
		c.OnWrite = onWrite
	}

	lamp := &accessory.Accessory{Services: []*accessory.Service{
		accessory.NewInfoService(accessory.Info{
			Name:         "Cardputer",
			Manufacturer: "tiny-hap-go",
			Model:        "cardputer",
			SerialNumber: "0001",
			Firmware:     "0.1.0",
		}),
		accessory.NewProtocolInfoService(),
		accessory.NewService(accessory.ServiceLightbulb, accessory.NewName("Cardputer"),
			on, brightness, hue, saturation),
	}}

	srv, err := accessory.NewServer(accessory.Config{
		Pin:        pin,
		Category:   accessory.CategoryLightbulb,
		MaxConns:   3,
		Advertiser: newAdvertiser(ip),
		OnIdentify: func() { onWrite(nil) },
	}, lamp)
	if err != nil {
		con.print(err.Error(), red)
		select {}
	}

	// The stack of espradio does not accept connections to a listener on 0.0.0.0.
	ln, err := net.Listen("tcp", ip.String()+":"+strconv.Itoa(port))
	if err != nil {
		con.print("listen: "+err.Error(), red)
		select {}
	}
	con.print("id "+srv.ID(), grey)
	con.print("setup code "+pin, yellow)

	go func() {
		err := srv.Serve(ln)
		con.print("serve: "+err.Error(), red)
	}()

	paired := !srv.IsPaired()
	ticker := time.NewTicker(time.Second)
	for {
		if paired != srv.IsPaired() {
			paired = srv.IsPaired()
			if paired {
				con.status(ip.String()+"  paired", green)
			} else {
				con.status(ip.String()+"  not paired", yellow)
			}
		}
		con.lamp(on.Value().(bool), brightness.Value().(int64),
			hue.Value().(float64), saturation.Value().(float64))

		select {
		case <-changed:
		case <-ticker.C:
		}
	}
}
