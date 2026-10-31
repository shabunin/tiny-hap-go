package hapcrypto

import (
	"crypto/ed25519"
	"math/rand"
	"testing"
)

// Verify agrees with crypto/ed25519 on signatures, damaged signatures, keys
// and messages.
func TestVerify(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := range 200 {
		seed := make([]byte, ed25519.SeedSize)
		r.Read(seed)
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		msg := make([]byte, r.Intn(200))
		r.Read(msg)
		sig := ed25519.Sign(priv, msg)
		if !Verify(pub, msg, sig) {
			t.Fatalf("%d: valid signature rejected", i)
		}
		check := func(what string, pub, msg, sig []byte) {
			t.Helper()
			if got, want := Verify(pub, msg, sig), ed25519.Verify(pub, msg, sig); got != want {
				t.Fatalf("%d, %s: Verify %v, crypto/ed25519 %v", i, what, got, want)
			}
		}
		flip := func(b []byte) []byte {
			b = append([]byte(nil), b...)
			if len(b) > 0 {
				b[r.Intn(len(b))] ^= 1 << r.Intn(8)
			}
			return b
		}
		check("signature", pub, msg, flip(sig))
		check("key", flip(pub), msg, sig)
		check("message", pub, flip(msg), sig)
		check("short signature", pub, msg, sig[:63])
		if Verify(pub[:31], msg, sig) { // crypto/ed25519 panics
			t.Fatalf("%d: short key accepted", i)
		}
	}
}

// S not reduced modulo group order is rejected, as by crypto/ed25519.
func TestVerifyNonCanonicalS(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	// S + l, l = 2^252 + 27742317777372353535851937790883648493
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	bad := append([]byte(nil), sig...)
	var carry int
	for i := range 32 {
		v := int(bad[32+i]) + int(l[i]) + carry
		bad[32+i], carry = byte(v), v>>8
	}
	if ed25519.Verify(pub, msg, bad) || Verify(pub, msg, bad) {
		t.Fatal("S + l accepted")
	}
}

func BenchmarkVerify(b *testing.B) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, []byte("hello"))
	b.Run("hapcrypto", func(b *testing.B) {
		for range b.N {
			Verify(pub, []byte("hello"), sig)
		}
	})
	b.Run("crypto/ed25519", func(b *testing.B) {
		for range b.N {
			ed25519.Verify(pub, []byte("hello"), sig)
		}
	})
}
