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

Works on M5Stack Cardputer (ESP32-S3) over Wi-Fi with TinyGo 0.44, with a controller
in Go and [aiohomekit](https://github.com/Jc2k/aiohomekit) of Home Assistant: an hour
of three controller connections, one of them reconnecting all the time, without
errors. Pairings and the lamp are kept in flash and survive resets and reflashing.

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

[examples/lamp](examples/lamp) is a dimmable lamp to pair with Home app or another HomeKit controller:

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

It keeps id, keys, pairings and the lamp in the two flash sectors below 4 MB, the lamp
once it stopped changing for 3 s. To forget them:

```sh
esptool --port /dev/ttyACM0 erase-region 0x3FE000 0x2000
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
`Serve` starts the goroutines of all `MaxConns` connections at once, so that their
stacks are allocated before the heap gets fragmented.
Wi-Fi driver and its network stack come on top: on the Cardputer they take about
100 KB of its 244 KB heap, see [examples/cardputer](examples/cardputer).

## Design

- no `net/http`: own small HTTP/1.1 parser for the few requests of HAP
- no reflection in pairing: TLV8 items are read and written directly
- accessory JSON is written by hand, only write requests are parsed with `encoding/json`
- mDNS is an `Advertiser` interface, `advertise/dnssd` for systems with full network stack,
  `advertise/mdns` is a small responder for boards, e.g. with lneto network stack of espradio
- storage is a `Store` interface: files, memory, or flash with `flashstore`, which appends
  records with checksums to one of two erase blocks and is safe against power loss
- small heap: requests are handled one at a time, encrypted responses are written
  frame by frame, `MaxConns` goroutines with their buffers are made once and reused,
  so serving connections does not fragment the heap; `MinFreeHeap` refuses
  connections when heap runs low
- events go out after the response to the write that caused them, with current
  value and a 1 s timeout: a controller that stops reading is disconnected
  without holding up the others

## Credits

- [hap](https://github.com/brutella/hap) by Matthias Hochgatterer: pairing, sessions
  and protocol details are built upon it
- [TinyGo](https://tinygo.org): compiler and runtime for boards
- [espradio](https://github.com/tinygo-org/espradio) by the TinyGo authors: Wi-Fi of ESP32-S3
- [lneto](https://github.com/soypat/lneto) by Patricio Whittingslow: TCP/IP stack on boards
- [drivers](https://github.com/tinygo-org/drivers) and
  [tinyfont](https://github.com/tinygo-org/tinyfont) of TinyGo: screen of the Cardputer
- [x/crypto](https://pkg.go.dev/golang.org/x/crypto) by the Go authors:
  ChaCha20-Poly1305, X25519, HKDF
- [edwards25519](https://github.com/FiloSottile/edwards25519) by Filippo Valsorda:
  Ed25519 verification without lookup table
- [go-pkgs](https://github.com/tadglines/go-pkgs) by Tad Glines: SRP of pair-setup
- [dnssd](https://github.com/shabunin/dnssd), fork of
  [brutella/dnssd](https://github.com/brutella/dnssd) by Matthias Hochgatterer: mDNS on Linux
- [dns](https://github.com/miekg/dns) by Miek Gieben: DNS messages in tests of the mDNS responder
- [aiohomekit](https://github.com/Jc2k/aiohomekit) of Home Assistant: second controller in
  interoperability and stress tests

## License

[Apache License 2.0](LICENSE)
