package hapcrypto

import (
	"crypto/sha512"
	"crypto/subtle"

	"filippo.io/edwards25519"
)

// Verify reports whether sig is ed25519 signature of msg by public key pub, as
// crypto/ed25519.Verify does. It needs no lookup table: under TinyGo the 1280
// bytes of the table of crypto/ed25519 go to heap at every verification, and
// on a board the heap is too fragmented to always have them in one piece.
func Verify(pub, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 || sig[63]&224 != 0 {
		return false
	}
	var a edwards25519.Point
	if _, err := a.SetBytes(pub); err != nil {
		return false
	}
	var s edwards25519.Scalar
	if _, err := s.SetCanonicalBytes(sig[32:]); err != nil {
		return false
	}
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(pub)
	h.Write(msg)
	var digest [64]byte
	var k edwards25519.Scalar
	if _, err := k.SetUniformBytes(h.Sum(digest[:0])); err != nil {
		return false
	}

	// R = [s]B - [k]A, both bits of each place at once, with B - A ready
	// for places where both are set.
	var minusA, bMinusA edwards25519.Point
	minusA.Negate(&a)
	b := edwards25519.NewGeneratorPoint()
	bMinusA.Add(b, &minusA)
	sb, kb := s.Bytes(), k.Bytes()
	r := edwards25519.NewIdentityPoint()
	for i := 255; i >= 0; i-- {
		r.Double(r)
		switch sb[i/8]>>(i%8)&1 | kb[i/8]>>(i%8)&1<<1 {
		case 1:
			r.Add(r, b)
		case 2:
			r.Add(r, &minusA)
		case 3:
			r.Add(r, &bMinusA)
		}
	}
	return subtle.ConstantTimeCompare(sig[:32], r.Bytes()) == 1
}
