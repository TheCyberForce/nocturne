package proto

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cookies let a responder under load demand proof that an initiator can
// receive packets at its claimed source address before spending any
// public-key work on it.

const (
	CookieSize      = MacSize
	CookieReplySize = 8 + chacha20poly1305.NonceSizeX + CookieSize + TagSize // 64
	cookieLifetime  = 2 * time.Minute
)

// CookieJar issues address-bound cookies from a rotating secret.
type CookieJar struct {
	mu      sync.Mutex
	secret  [KeySize]byte
	rotated time.Time
}

// Cookie returns the cookie currently valid for addr.
func (j *CookieJar) Cookie(addr netip.AddrPort, now time.Time) [CookieSize]byte {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.rotated.IsZero() || now.Sub(j.rotated) > cookieLifetime {
		if _, err := rand.Read(j.secret[:]); err != nil {
			panic(err)
		}
		j.rotated = now
	}
	ip := addr.Addr().As16()
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port())
	return mac(j.secret[:], ip[:], port[:])
}

func cookieKey(responderStatic []byte) [KeySize]byte {
	return hashOf([]byte(labelCookie), responderStatic)
}

// CreateCookieReply seals cookie for the sender of init. The reply is
// bound to that Init's mac1, so only someone who saw the Init can use it.
func CreateCookieReply(localPub [KeySize]byte, init []byte, cookie [CookieSize]byte) []byte {
	msg := make([]byte, 8+chacha20poly1305.NonceSizeX, CookieReplySize)
	msg[0] = TypeCookie
	copy(msg[4:8], init[4:8]) // receiver index = the Init's sender index
	if _, err := rand.Read(msg[8:]); err != nil {
		panic(err)
	}
	key := cookieKey(localPub[:])
	aead, _ := chacha20poly1305.NewX(key[:])
	return aead.Seal(msg, msg[8:], cookie[:], InitMac1(init))
}

// CookieReceiver returns the receiver index of a CookieReply.
func CookieReceiver(msg []byte) (uint32, bool) {
	if len(msg) != CookieReplySize || msg[0] != TypeCookie {
		return 0, false
	}
	return binary.LittleEndian.Uint32(msg[4:]), true
}

// ConsumeCookieReply recovers the cookie from a reply to the Init whose
// mac1 is recorded in st.
func (st *InitState) ConsumeCookieReply(remoteStatic [KeySize]byte, msg []byte) ([]byte, error) {
	if idx, ok := CookieReceiver(msg); !ok || idx != st.LocalIndex {
		return nil, ErrMalformed
	}
	key := cookieKey(remoteStatic[:])
	aead, _ := chacha20poly1305.NewX(key[:])
	nonceEnd := 8 + chacha20poly1305.NonceSizeX
	cookie, err := aead.Open(nil, msg[8:nonceEnd], msg[nonceEnd:], st.Mac1[:])
	if err != nil {
		return nil, ErrAuth
	}
	return cookie, nil
}
