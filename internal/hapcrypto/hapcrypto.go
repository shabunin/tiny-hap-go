// Package hapcrypto has the crypto primitives of HAP pairing and sessions.
package hapcrypto

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// TagSize is the size of authentication tag appended to sealed data.
const TagSize = chacha20poly1305.Overhead

// nonce12 puts 8 byte nonce, e.g. "PS-Msg05" or counter, after 4 zero bytes.
func nonce12(nonce []byte) []byte {
	var n [chacha20poly1305.NonceSize]byte
	copy(n[4:], nonce)
	return n[:]
}

// Seal encrypts plain, appends it with tag to dst.
func Seal(dst []byte, key [32]byte, nonce, plain, aad []byte) []byte {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err) // key size is fixed
	}
	return aead.Seal(dst, nonce12(nonce), plain, aad)
}

var errShort = errors.New("hapcrypto: sealed data too short")

// Open decrypts sealed data with tag at its end.
func Open(key [32]byte, nonce, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, errShort
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	return aead.Open(nil, nonce12(nonce), sealed, aad)
}

// HKDF derives 32 byte key with HKDF-SHA512.
func HKDF(secret []byte, salt, info string) [32]byte {
	var k [32]byte
	r := hkdf.New(sha512.New, secret, []byte(salt), []byte(info))
	if _, err := io.ReadFull(r, k[:]); err != nil {
		panic(err) // can't fail for 32 bytes
	}
	return k
}

// X25519KeyPair generates key pair for pair-verify.
func X25519KeyPair() (public, private [32]byte, err error) {
	if _, err := rand.Read(private[:]); err != nil {
		return public, private, err
	}
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	copy(public[:], pub)
	return public, private, err
}

// X25519 returns shared secret, error for low order public key.
func X25519(private, public [32]byte) ([32]byte, error) {
	var shared [32]byte
	s, err := curve25519.X25519(private[:], public[:])
	copy(shared[:], s)
	return shared, err
}
