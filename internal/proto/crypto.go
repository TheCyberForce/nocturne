// Package proto implements the Nocturne wire protocol: the handshake,
// the transport framing, the replay window and the cookie mechanism.
// It performs no I/O.
package proto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize = 32
	TagSize = chacha20poly1305.Overhead
	MacSize = 16
)

// Domain separation labels. Changing any of these makes a different protocol.
const (
	labelProtocol  = "Nocturne v1 :: X25519+ML-KEM-768 / ChaCha20-Poly1305 / BLAKE2s"
	labelMix       = "nocturne v1 mix"
	labelTransport = "nocturne v1 transport"
	labelGate      = "nocturne v1 gate"
	labelCookie    = "nocturne v1 cookie"
)

var (
	ErrMalformed = errors.New("nocturne: malformed message")
	ErrAuth      = errors.New("nocturne: authentication failed")
)

func newHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// hashOf returns BLAKE2s-256 over the concatenation of parts.
func hashOf(parts ...[]byte) (out [KeySize]byte) {
	h := newHash()
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
	return
}

// mac returns keyed BLAKE2s-128 over the concatenation of parts.
func mac(key []byte, parts ...[]byte) (out [MacSize]byte) {
	h, err := blake2s.New128(key)
	if err != nil {
		panic(err)
	}
	for _, p := range parts {
		h.Write(p)
	}
	h.Sum(out[:0])
	return
}

// mixKey folds input key material into the chaining key and returns a
// fresh AEAD key: (ck', k) = HKDF-BLAKE2s(salt=ck, ikm, info=labelMix).
func mixKey(ck *[KeySize]byte, ikm []byte) (k [KeySize]byte) {
	okm, err := hkdf.Key(newHash, ikm, ck[:], labelMix, 2*KeySize)
	if err != nil {
		panic(err)
	}
	copy(ck[:], okm[:KeySize])
	copy(k[:], okm[KeySize:])
	wipe(okm)
	return
}

func mixHash(h *[KeySize]byte, data []byte) {
	*h = hashOf(h[:], data)
}

func nonce(counter uint64) (n [chacha20poly1305.NonceSize]byte) {
	binary.LittleEndian.PutUint64(n[4:], counter)
	return
}

func newAEAD(key *[KeySize]byte) cipher.AEAD {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err)
	}
	return a
}

// Handshake AEAD operations always use nonce 0: every handshake key is
// used for exactly one encryption.
func hsSeal(key *[KeySize]byte, dst, plaintext, ad []byte) []byte {
	n := nonce(0)
	return newAEAD(key).Seal(dst, n[:], plaintext, ad)
}

func hsOpen(key *[KeySize]byte, dst, ciphertext, ad []byte) ([]byte, error) {
	n := nonce(0)
	out, err := newAEAD(key).Open(dst, n[:], ciphertext, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GeneratePrivateKey returns a new X25519 static private key.
func GeneratePrivateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParsePrivateKey loads a 32-byte X25519 private key.
func ParsePrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

// PublicOf returns the 32-byte public key for priv.
func PublicOf(priv *ecdh.PrivateKey) (pub [KeySize]byte) {
	copy(pub[:], priv.PublicKey().Bytes())
	return
}

// dh performs X25519 and rejects low-order points (all-zero output).
func dh(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, ErrMalformed
	}
	out, err := priv.ECDH(pk)
	if err != nil {
		return nil, ErrAuth
	}
	return out, nil
}
