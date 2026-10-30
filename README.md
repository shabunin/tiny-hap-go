# tiny-hap-go

HomeKit Accessory Protocol (HAP) in Go, small enough for microcontrollers
with [TinyGo](https://tinygo.org): make a board a HomeKit accessory, e.g. a lamp,
switch or sensor, that Home app and other controllers pair with and control.

The controller side will follow.

Requires Go 1.26 or newer, TinyGo 0.42 for boards.

## Status

Works on Linux with normal Go and TinyGo builds:
pair setup and verify, encrypted sessions, accessories, reading and writing
characteristics, events, adding and removing controllers.
Tested with [hkontroller](https://github.com/shabunin/hkontroller).

Works on M5Stack Cardputer (ESP32-S3) over Wi-Fi with TinyGo 0.44:
pairs and works with hkontroller. Pairings are not kept in flash yet.

## Example

```go
on := accessory.NewOn()
on.OnWrite = func(v any) error {
	relay.Set(v.(bool))
	return nil
}
lamp := &accessory.Accessory{Services: []*accessory.Service{
	accessory.NewInfoService(accessory.Info{Name: "Lamp", Manufacturer: "me",
		Model: "lamp", SerialNumber: "0001", Firmware: "0.1.0"}),
	accessory.NewService(accessory.ServiceLightbulb, accessory.NewName("Lamp"), on),
}}
srv, err := accessory.NewServer(accessory.Config{
	Pin:        "031-45-154",
	Category:   accessory.CategoryLightbulb,
	Store:      accessory.NewFsStore("./store"),
	Advertiser: dnssd.New(), // github.com/shabunin/tiny-hap-go/advertise/dnssd
}, lamp)
ln, err := net.Listen("tcp", ":0")
srv.Serve(ln)
```

Values changed on the accessory, e.g. by a button, go to controllers with `SetValue`.

[examples/lamp](examples/lamp) is a dimmable lamp to pair with Home app or hkontroller:

```sh
go run ./examples/lamp -debug
```

[examples/tinylamp](examples/tinylamp) is the same lamp for TinyGo, without mDNS and files.

[examples/cardputer](examples/cardputer) makes M5Stack Cardputer a color lamp shown on its screen,
over Wi-Fi with [espradio](https://github.com/tinygo-org/espradio):

```sh
cd examples/cardputer
tinygo flash -target=m5stamp-s3a -ldflags "-X main.ssid=SSID -X main.password=PASSWORD" .
```

## Size

TinyGo 0.42 builds of `examples/tinylamp`. Heap is measured: smallest heap limit
where pairing, loading accessories, reads, writes, events and unpairing work,
32-bit ARM with the boards' garbage collector.

| Board | Flash | Static RAM | RAM in TinyGo |
|---|---|---|---|
| Pico 2 W (RP2350) | 197 KB | 51 KB | 512 KB |
| Pico W (RP2040) | 215 KB | 51 KB | 256 KB |
| ESP32-S3 | 261 KB | 109 KB | 416 KB |
| ESP32-C3 | 261 KB | 99 KB | 321 KB |

Heap: about 40 KB. Goroutine stacks: one per connection and two more,
8 KB each on ESP32, set `-stack-size=8KB` on RP2040 and RP2350.
Wi-Fi driver and its network stack come on top.

## Design

- no `net/http`: own small HTTP/1.1 parser for the few requests of HAP
- no reflection in pairing: TLV8 items are read and written directly
- accessory JSON is written by hand, only write requests are parsed with `encoding/json`
- mDNS is an `Advertiser` interface, `advertise/dnssd` for systems with full network stack,
  `advertise/mdns` is a small responder for boards, e.g. with lneto network stack of espradio
- storage is a `Store` interface: files, memory, or your board's flash

## Credits

Protocol details follow [hkontroller](https://github.com/shabunin/hkontroller),
derived from [`github.com/brutella/hap`](https://github.com/brutella/hap).

## License

[Apache License 2.0](LICENSE)
