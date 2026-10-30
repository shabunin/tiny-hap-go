//go:build tinygo

// Command cardputer makes the M5Stack Cardputer (ESP32-S3) a HomeKit color lamp:
// it joins Wi-Fi, announces itself with mDNS and shows the lamp on its screen.
// Pair it from Home app or hkontroller with setup code 031-45-154.
//
//	tinygo flash -target=m5stamp-s3a -port /dev/ttyACM0 \
//	  -ldflags "-X main.ssid=SSID -X main.password=PASSWORD" .
package main

import (
	"fmt"
	"machine"
	"runtime"
	"strconv"
	"time"

	"github.com/shabunin/tiny-hap-go/accessory"
	"github.com/shabunin/tiny-hap-go/flashstore"
)

// Set at build time: -ldflags "-X main.ssid=... -X main.password=...".
var (
	ssid     string
	password string
)

const (
	pin  = "031-45-154"
	port = 51826

	maxConns    = 4
	minFreeHeap = 12 * 1024
)

func main() {
	con := newConsole(openDisplay())
	con.status("tiny-hap-go  cardputer", cyan)

	// Without ssid, TinyGo drops everything below as dead code: measure size with it.
	if ssid == "" {
		con.print("built without -X main.ssid", red)
		select {}
	}

	ip := connectWiFi(con)
	con.print("wifi: "+ip.String(), green)

	accessory.SetLogger(func(format string, args ...any) { println(fmt.Sprintf(format, args...)) })

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

	// The last two sectors before 4 MB: the address stays when the program grows.
	store, err := flashstore.New(machine.Flash, machine.Flash.Size()-flashstore.Size(machine.Flash))
	if err != nil {
		con.print("flash: "+err.Error(), red)
		select {}
	}

	srv, err := accessory.NewServer(accessory.Config{
		Store:    store,
		Pin:      pin,
		Category: accessory.CategoryLightbulb,
		MaxConns: maxConns,
		// Wi-Fi takes half of the heap, leave room for requests of open connections.
		MinFreeHeap: minFreeHeap,
		Advertiser:  newAdvertiser(ip),
		OnIdentify:  func() { onWrite(nil) },
	}, lamp)
	if err != nil {
		con.print(err.Error(), red)
		select {}
	}

	ln, err := listen(ip, port)
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

	var status string
	ticker := time.NewTicker(time.Second)
	for {
		state, c := "not paired", yellow
		if srv.IsPaired() {
			state, c = "paired", green
		}
		if s := ip.String() + " " + state + " " + strconv.Itoa(int(freeHeap()/1024)) + "K free"; s != status {
			status = s
			con.status(status, c)
		}
		con.lamp(on.Value().(bool), brightness.Value().(int64),
			hue.Value().(float64), saturation.Value().(float64))

		select {
		case <-changed:
		case <-ticker.C:
		}
	}
}

// freeHeap returns heap free after garbage collection.
func freeHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapSys - m.HeapInuse
}
