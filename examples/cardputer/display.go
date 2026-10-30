//go:build tinygo

package main

import (
	"image/color"
	"machine"
	"math"
	"strconv"

	"tinygo.org/x/drivers/pixel"
	"tinygo.org/x/drivers/st7789"
	"tinygo.org/x/tinyfont"
	"tinygo.org/x/tinyfont/proggy"
)

// The LCD of the Cardputer: an ST7789V2 with 135×240 pixels, used in landscape.
// The top row is a status line, below it a console on the left and the lamp on the right.
const (
	screenWidth  = 240
	screenHeight = 135

	charWidth  = 6
	lineHeight = 11
	baseline   = 8 // of proggy.TinySZ8pt7b within a line

	lampWidth    = 72
	consoleWidth = screenWidth - lampWidth - 4

	columns = consoleWidth / charWidth
	rows    = screenHeight / lineHeight
)

var (
	white  = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	grey   = color.RGBA{0x90, 0x90, 0x90, 0xFF}
	green  = color.RGBA{0x40, 0xFF, 0x60, 0xFF}
	yellow = color.RGBA{0xFF, 0xD0, 0x40, 0xFF}
	red    = color.RGBA{0xFF, 0x50, 0x50, 0xFF}
	cyan   = color.RGBA{0x40, 0xD0, 0xFF, 0xFF}
	black  = color.RGBA{0, 0, 0, 0xFF}
)

func openDisplay() *st7789.Device {
	machine.SPI0.Configure(machine.SPIConfig{
		Frequency: 40_000_000,
		SCK:       machine.GPIO36,
		SDO:       machine.GPIO35,
		SDI:       machine.NoPin,
	})
	d := st7789.New(machine.SPI0, machine.GPIO33, machine.GPIO34, machine.GPIO37, machine.GPIO38)
	d.Configure(st7789.Config{
		Width:        135,
		Height:       240,
		Rotation:     st7789.ROTATION_90,
		RowOffset:    40,
		ColumnOffset: 52,
	})
	d.EnableBacklight(true)
	return &d
}

// line is one text line, drawn in memory and sent in one go: drawing a font
// pixel by pixel over SPI would be far too slow.
type line struct {
	img pixel.Image[pixel.RGB565BE]
}

func (l *line) Size() (int16, int16) { return screenWidth, lineHeight }

func (l *line) SetPixel(x, y int16, c color.RGBA) {
	w, _ := l.img.Size()
	if x >= 0 && int(x) < w && y >= 0 && y < lineHeight {
		l.img.Set(int(x), int(y), pixel.NewColor[pixel.RGB565BE](c.R, c.G, c.B))
	}
}

func (l *line) Display() error { return nil }

func (l *line) draw(d *st7789.Device, x, y int16, text string, fg, bg color.RGBA) {
	l.img.FillSolidColor(pixel.NewColor[pixel.RGB565BE](bg.R, bg.G, bg.B))
	tinyfont.WriteLine(l, &proggy.TinySZ8pt7b, 0, baseline, text, fg)
	d.DrawBitmap(x, y, l.img)
}

type console struct {
	display *st7789.Device
	full    line // status line
	narrow  line // console and lamp lines

	lines  [rows - 1]string
	colors [rows - 1]color.RGBA

	lampColor color.RGBA
	lampText  string
}

func newConsole(d *st7789.Device) *console {
	c := &console{
		display: d,
		full:    line{img: pixel.NewImage[pixel.RGB565BE](screenWidth, lineHeight)},
		narrow:  line{img: pixel.NewImage[pixel.RGB565BE](consoleWidth, lineHeight)},
	}
	d.FillScreen(black)
	return c
}

func (c *console) status(text string, fg color.RGBA) {
	println(text)
	c.full.draw(c.display, 0, 0, clip(text, screenWidth/charWidth), fg, color.RGBA{0x20, 0x20, 0x40, 0xFF})
}

// print adds a line at the bottom of the console, wrapped at its width.
func (c *console) print(text string, fg color.RGBA) {
	println(text)
	for {
		part := clip(text, columns)
		copy(c.lines[:], c.lines[1:])
		copy(c.colors[:], c.colors[1:])
		c.lines[len(c.lines)-1] = part
		c.colors[len(c.colors)-1] = fg
		if len(text) <= columns {
			break
		}
		text = text[columns:]
	}
	for i, s := range c.lines {
		c.narrow.draw(c.display, 0, int16((1+i)*lineHeight), s, c.colors[i], black)
	}
}

// lamp shows the light: its color fills the right side of the screen.
func (c *console) lamp(on bool, brightness int64, hue, saturation float64) {
	col := black
	text := "off"
	if on {
		col = hsv(hue, saturation/100, float64(brightness)/100)
		text = strconv.Itoa(int(brightness)) + "%"
	}
	if col == c.lampColor && text == c.lampText {
		return
	}
	c.lampColor, c.lampText = col, text
	x := int16(screenWidth - lampWidth)
	c.display.FillRectangle(x, lineHeight, lampWidth, screenHeight-lineHeight, col)
	c.narrow.draw(c.display, x, screenHeight-lineHeight, clip(text, lampWidth/charWidth), white, black)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// hsv converts hue in degrees, saturation and value from 0 to 1 to a color.
func hsv(h, s, v float64) color.RGBA {
	c := v * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	var r, g, b float64
	switch {
	case h < 60:
		r, g = c, x
	case h < 120:
		r, g = x, c
	case h < 180:
		g, b = c, x
	case h < 240:
		g, b = x, c
	case h < 300:
		r, b = x, c
	default:
		r, b = c, x
	}
	m := v - c
	return color.RGBA{byte((r + m) * 255), byte((g + m) * 255), byte((b + m) * 255), 0xFF}
}
