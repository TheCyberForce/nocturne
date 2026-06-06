package proto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"time"
)

// Message types (first byte of every datagram).
const (
	TypeInit     = 1
	TypeResponse = 2
	TypeData     = 3
	TypeCookie   = 4
)

// Wire sizes.
const (
	kemEKSize = mlkem.EncapsulationKeySize768 // 1184
	kemCTSize = mlkem.CiphertextSize768       // 1088

	initHeader  = 8
	initStatic  = initHeader + KeySize                  // 40: start of sealed static key
	initPayload = initStatic + KeySize + TagSize        // 88: start of sealed payload
	initMac1    = initPayload + 8 + kemEKSize + TagSize // 1296
	initMac2    = initMac1 + MacSize                    // 1312
	InitSize    = initMac2 + MacSize                    // 1328

	respHeader   = 12
	respKEM      = respHeader + KeySize  // 44
	respConfirm  = respKEM + kemCTSize   // 1132
	ResponseSize = respConfirm + TagSize // 1148

	DataHeader = 16 // type, reserved[3], receiver index, counter
)

// Keys is the outcome of a completed handshake.
type Keys struct {
	Send, Recv  cipher.AEAD
	RemoteIndex uint32
}

func initialState(responderStatic []byte) (ck, h [KeySize]byte) {
	ck = hashOf([]byte(labelProtocol))
	h = hashOf(ck[:], responderStatic)
	return
}

func gateKey(responderStatic []byte) [KeySize]byte {
	return hashOf([]byte(labelGate), responderStatic)
}

// InitState is what an initiator keeps between sending an Init and
// receiving the Response.
type InitState struct {
	LocalIndex uint32
	Mac1       [MacSize]byte

	ck, h [KeySize]byte
	eph   *ecdh.PrivateKey
	kem   *mlkem.DecapsulationKey768
}

// CreateInit builds a handshake initiation addressed to remoteStatic.
// cookie may be nil; when present it is used to compute mac2.
func CreateInit(local *ecdh.PrivateKey, remoteStatic [KeySize]byte, localIndex uint32, now time.Time, cookie []byte) ([]byte, *InitState, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	kem, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	st := &InitState{LocalIndex: localIndex, eph: eph, kem: kem}
	st.ck, st.h = initialState(remoteStatic[:])

	msg := make([]byte, InitSize)
	msg[0] = TypeInit
	binary.LittleEndian.PutUint32(msg[4:], localIndex)
	copy(msg[initHeader:], eph.PublicKey().Bytes())
	mixHash(&st.h, msg[:initStatic])

	// es: only the holder of the responder's static key can read our identity.
	es, err := dh(eph, remoteStatic[:])
	if err != nil {
		return nil, nil, err
	}
	k := mixKey(&st.ck, es)
	localPub := PublicOf(local)
	hsSeal(&k, msg[initStatic:initStatic], localPub[:], st.h[:])
	mixHash(&st.h, msg[initStatic:initPayload])

	// ss: authenticates the initiator.
	ss, err := dh(local, remoteStatic[:])
	if err != nil {
		return nil, nil, err
	}
	k = mixKey(&st.ck, ss)
	payload := make([]byte, 8+kemEKSize)
	binary.BigEndian.PutUint64(payload, uint64(now.UnixNano()))
	copy(payload[8:], kem.EncapsulationKey().Bytes())
	hsSeal(&k, msg[initPayload:initPayload], payload, st.h[:])
	mixHash(&st.h, msg[initPayload:initMac1])

	gk := gateKey(remoteStatic[:])
	st.Mac1 = mac(gk[:], msg[:initMac1])
	copy(msg[initMac1:], st.Mac1[:])
	if len(cookie) > 0 {
		m2 := mac(cookie, msg[:initMac2])
		copy(msg[initMac2:], m2[:])
	}
	wipe(es)
	wipe(ss)
	return msg, st, nil
}

// CheckGate verifies mac1 of an Init. It is the cheap first check a
// responder runs: a sender that does not know our public key cannot pass
// it, and we stay silent.
func CheckGate(localPub [KeySize]byte, msg []byte) bool {
	if len(msg) != InitSize || msg[0] != TypeInit {
		return false
	}
	gk := gateKey(localPub[:])
	want := mac(gk[:], msg[:initMac1])
	return subtle.ConstantTimeCompare(want[:], msg[initMac1:initMac2]) == 1
}

// InitMac1 returns the mac1 field of an Init message.
func InitMac1(msg []byte) []byte { return msg[initMac1:initMac2] }

// CheckMac2 verifies mac2 of an Init against the expected cookie.
func CheckMac2(cookie []byte, msg []byte) bool {
	want := mac(cookie, msg[:initMac2])
	return subtle.ConstantTimeCompare(want[:], msg[initMac2:InitSize]) == 1
}

// InitResult is a responder's view of a consumed Init.
type InitResult struct {
	PeerStatic  [KeySize]byte
	Timestamp   uint64
	RemoteIndex uint32

	ck, h [KeySize]byte
	ephI  []byte
	kemEK *mlkem.EncapsulationKey768
}

// ConsumeInit authenticates and decrypts an Init. The caller must have
// run CheckGate first, and must check PeerStatic and Timestamp before
// calling CreateResponse.
func ConsumeInit(local *ecdh.PrivateKey, msg []byte) (*InitResult, error) {
	if len(msg) != InitSize || msg[0] != TypeInit {
		return nil, ErrMalformed
	}
	localPub := PublicOf(local)
	r := &InitResult{RemoteIndex: binary.LittleEndian.Uint32(msg[4:])}
	r.ck, r.h = initialState(localPub[:])
	r.ephI = append([]byte(nil), msg[initHeader:initStatic]...)
	mixHash(&r.h, msg[:initStatic])

	es, err := dh(local, r.ephI)
	if err != nil {
		return nil, err
	}
	k := mixKey(&r.ck, es)
	wipe(es)
	static, err := hsOpen(&k, nil, msg[initStatic:initPayload], r.h[:])
	if err != nil {
		return nil, err
	}
	copy(r.PeerStatic[:], static)
	mixHash(&r.h, msg[initStatic:initPayload])

	ss, err := dh(local, r.PeerStatic[:])
	if err != nil {
		return nil, err
	}
	k = mixKey(&r.ck, ss)
	wipe(ss)
	payload, err := hsOpen(&k, nil, msg[initPayload:initMac1], r.h[:])
	if err != nil {
		return nil, err
	}
	mixHash(&r.h, msg[initPayload:initMac1])
	r.Timestamp = binary.BigEndian.Uint64(payload)
	if r.kemEK, err = mlkem.NewEncapsulationKey768(payload[8:]); err != nil {
		return nil, ErrMalformed
	}
	return r, nil
}

// CreateResponse completes the handshake on the responder side.
func (r *InitResult) CreateResponse(psk *[KeySize]byte, localIndex uint32) ([]byte, *Keys, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	msg := make([]byte, ResponseSize)
	msg[0] = TypeResponse
	binary.LittleEndian.PutUint32(msg[4:], localIndex)
	binary.LittleEndian.PutUint32(msg[8:], r.RemoteIndex)
	copy(msg[respHeader:], eph.PublicKey().Bytes())
	mixHash(&r.h, msg[:respKEM])

	ee, err := dh(eph, r.ephI)
	if err != nil {
		return nil, nil, err
	}
	mixKey(&r.ck, ee)
	se, err := dh(eph, r.PeerStatic[:])
	if err != nil {
		return nil, nil, err
	}
	mixKey(&r.ck, se)

	pq, ct := r.kemEK.Encapsulate()
	copy(msg[respKEM:], ct)
	mixHash(&r.h, ct)
	mixKey(&r.ck, pq)

	k := mixKey(&r.ck, psk[:])
	hsSeal(&k, msg[respConfirm:respConfirm], nil, r.h[:])

	recv, send := transportKeys(&r.ck, &r.h)
	wipe(ee)
	wipe(se)
	wipe(pq)
	return msg, &Keys{Send: send, Recv: recv, RemoteIndex: r.RemoteIndex}, nil
}

// ResponseReceiver returns the receiver index of a Response message.
func ResponseReceiver(msg []byte) (uint32, bool) {
	if len(msg) != ResponseSize || msg[0] != TypeResponse {
		return 0, false
	}
	return binary.LittleEndian.Uint32(msg[8:]), true
}

// ConsumeResponse completes the handshake on the initiator side.
func (st *InitState) ConsumeResponse(local *ecdh.PrivateKey, psk *[KeySize]byte, msg []byte) (*Keys, error) {
	if idx, ok := ResponseReceiver(msg); !ok || idx != st.LocalIndex {
		return nil, ErrMalformed
	}
	ck, h := st.ck, st.h // work on copies: a forged response must not corrupt state
	mixHash(&h, msg[:respKEM])

	ephR := msg[respHeader:respKEM]
	ee, err := dh(st.eph, ephR)
	if err != nil {
		return nil, err
	}
	mixKey(&ck, ee)
	se, err := dh(local, ephR)
	if err != nil {
		return nil, err
	}
	mixKey(&ck, se)

	ct := msg[respKEM:respConfirm]
	pq, err := st.kem.Decapsulate(ct)
	if err != nil {
		return nil, ErrMalformed
	}
	mixHash(&h, ct)
	mixKey(&ck, pq)

	k := mixKey(&ck, psk[:])
	if _, err := hsOpen(&k, nil, msg[respConfirm:], h[:]); err != nil {
		return nil, err
	}
	send, recv := transportKeys(&ck, &h)
	wipe(ee)
	wipe(se)
	wipe(pq)
	return &Keys{Send: send, Recv: recv, RemoteIndex: binary.LittleEndian.Uint32(msg[4:])}, nil
}

// transportKeys derives the two directional keys. The first is used by
// the initiator to send, the second by the responder.
func transportKeys(ck, h *[KeySize]byte) (i2r, r2i cipher.AEAD) {
	okm, err := hkdf.Key(newHash, h[:], ck[:], labelTransport, 2*KeySize)
	if err != nil {
		panic(err)
	}
	var a, b [KeySize]byte
	copy(a[:], okm[:KeySize])
	copy(b[:], okm[KeySize:])
	i2r, r2i = newAEAD(&a), newAEAD(&b)
	wipe(okm)
	wipe(a[:])
	wipe(b[:])
	wipe(ck[:])
	return
}

// SealData encrypts plaintext into a Data message. buf must hold
// DataHeader bytes of headroom followed by the plaintext, with TagSize
// bytes of spare capacity; the message is built in place and returned.
func SealData(aead cipher.AEAD, remoteIndex uint32, counter uint64, buf []byte) []byte {
	buf[0], buf[1], buf[2], buf[3] = TypeData, 0, 0, 0
	binary.LittleEndian.PutUint32(buf[4:], remoteIndex)
	binary.LittleEndian.PutUint64(buf[8:], counter)
	n := nonce(counter)
	return aead.Seal(buf[:DataHeader], n[:], buf[DataHeader:], buf[:DataHeader])
}

// ParseData returns the receiver index and counter of a Data message.
func ParseData(msg []byte) (index uint32, counter uint64, ok bool) {
	if len(msg) < DataHeader+TagSize || msg[0] != TypeData {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(msg[4:]), binary.LittleEndian.Uint64(msg[8:]), true
}

// OpenData decrypts a Data message in place and returns the plaintext.
func OpenData(aead cipher.AEAD, counter uint64, msg []byte) ([]byte, error) {
	n := nonce(counter)
	out, err := aead.Open(msg[DataHeader:DataHeader], n[:], msg[DataHeader:], msg[:DataHeader])
	if err != nil {
		return nil, ErrAuth
	}
	return out, nil
}
