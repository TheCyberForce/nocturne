package proto

import (
	"bytes"
	"crypto/ecdh"
	"net/netip"
	"testing"
	"time"
)

func mustKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var noPSK [KeySize]byte

func handshake(t *testing.T, ini, res *ecdh.PrivateKey, pskI, pskR *[KeySize]byte) (*Keys, *Keys, error) {
	t.Helper()
	msg, st, err := CreateInit(ini, PublicOf(res), 7, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != InitSize {
		t.Fatalf("init size %d, want %d", len(msg), InitSize)
	}
	if !CheckGate(PublicOf(res), msg) {
		t.Fatal("gate rejected a valid init")
	}
	r, err := ConsumeInit(res, msg)
	if err != nil {
		t.Fatal(err)
	}
	if r.PeerStatic != PublicOf(ini) {
		t.Fatal("responder learned the wrong identity")
	}
	resp, rk, err := r.CreateResponse(pskR, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != ResponseSize {
		t.Fatalf("response size %d, want %d", len(resp), ResponseSize)
	}
	ik, err := st.ConsumeResponse(ini, pskI, resp)
	return ik, rk, err
}

func TestHandshakeAndTransport(t *testing.T) {
	ik, rk, err := handshake(t, mustKey(t), mustKey(t), &noPSK, &noPSK)
	if err != nil {
		t.Fatal(err)
	}
	if ik.RemoteIndex != 9 || rk.RemoteIndex != 7 {
		t.Fatalf("indexes: %d %d", ik.RemoteIndex, rk.RemoteIndex)
	}
	for _, dir := range []struct{ a, b *Keys }{{ik, rk}, {rk, ik}} {
		pt := []byte("sixteen byte msg")
		buf := make([]byte, DataHeader+len(pt), DataHeader+len(pt)+TagSize)
		copy(buf[DataHeader:], pt)
		msg := SealData(dir.a.Send, dir.a.RemoteIndex, 42, buf)
		idx, ctr, ok := ParseData(msg)
		if !ok || idx != dir.a.RemoteIndex || ctr != 42 {
			t.Fatal("bad data header")
		}
		tampered := append([]byte(nil), msg...)
		tampered[5] ^= 1 // header is authenticated
		if _, err := OpenData(dir.b.Recv, ctr, tampered); err == nil {
			t.Fatal("tampered header accepted")
		}
		if _, err := OpenData(dir.a.Recv, ctr, append([]byte(nil), msg...)); err == nil {
			t.Fatal("directional keys are identical")
		}
		got, err := OpenData(dir.b.Recv, ctr, msg)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("decrypt: %v", err)
		}
	}
}

func TestPSKMismatch(t *testing.T) {
	a, b := [KeySize]byte{1}, [KeySize]byte{2}
	if _, _, err := handshake(t, mustKey(t), mustKey(t), &a, &b); err == nil {
		t.Fatal("handshake succeeded with different preshared keys")
	}
	if _, _, err := handshake(t, mustKey(t), mustKey(t), &a, &a); err != nil {
		t.Fatal(err)
	}
}

func TestInitToWrongResponder(t *testing.T) {
	ini, res, other := mustKey(t), mustKey(t), mustKey(t)
	msg, _, _ := CreateInit(ini, PublicOf(res), 1, time.Now(), nil)
	if CheckGate(PublicOf(other), msg) {
		t.Fatal("gate passed for the wrong responder")
	}
	if _, err := ConsumeInit(other, msg); err == nil {
		t.Fatal("wrong responder decrypted the init")
	}
}

// Flipping any single byte of either handshake message must be detected.
func TestHandshakeTamper(t *testing.T) {
	ini, res := mustKey(t), mustKey(t)
	msg, st, _ := CreateInit(ini, PublicOf(res), 1, time.Now(), nil)
	for i := 0; i < initMac1; i += 13 {
		bad := append([]byte(nil), msg...)
		bad[i] ^= 0x40
		if CheckGate(PublicOf(res), bad) {
			t.Fatalf("gate accepted init with byte %d flipped", i)
		}
		r, err := ConsumeInit(res, bad)
		if err != nil {
			continue
		}
		// Header bytes are only bound through the transcript: the
		// initiator must then reject the response.
		resp, _, _ := r.CreateResponse(&noPSK, 2)
		if _, err := st.ConsumeResponse(ini, &noPSK, resp); err == nil {
			t.Fatalf("init with byte %d flipped produced a session", i)
		}
	}
	r, _ := ConsumeInit(res, msg)
	resp, _, _ := r.CreateResponse(&noPSK, 2)
	for i := 4; i < ResponseSize; i += 11 {
		if i >= 8 && i < 12 {
			continue // receiver index: rejected by lookup, tested below
		}
		bad := append([]byte(nil), resp...)
		bad[i] ^= 0x40
		if _, err := st.ConsumeResponse(ini, &noPSK, bad); err == nil {
			t.Fatalf("response with byte %d flipped accepted", i)
		}
	}
	bad := append([]byte(nil), resp...)
	bad[8] ^= 1
	if _, err := st.ConsumeResponse(ini, &noPSK, bad); err == nil {
		t.Fatal("response for another index accepted")
	}
	// The state survives forged responses.
	if _, err := st.ConsumeResponse(ini, &noPSK, resp); err != nil {
		t.Fatal(err)
	}
}

func TestResponseFromImpostor(t *testing.T) {
	ini, res, impostor := mustKey(t), mustKey(t), mustKey(t)
	msg, st, _ := CreateInit(ini, PublicOf(res), 1, time.Now(), nil)
	// The impostor cannot even read the init; give it one of its own to
	// answer and splice the indexes.
	msg2, _, _ := CreateInit(ini, PublicOf(impostor), 1, time.Now(), nil)
	r, err := ConsumeInit(impostor, msg2)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, _ := r.CreateResponse(&noPSK, 2)
	if _, err := st.ConsumeResponse(ini, &noPSK, resp); err == nil {
		t.Fatal("accepted a response from the wrong responder")
	}
	_ = msg
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	steps := []struct {
		ctr  uint64
		want bool
	}{
		{0, true}, {0, false}, {1, true}, {1, false}, {5, true}, {3, true}, {3, false},
		{5, false}, {4, true}, {2, true}, {2, false},
		{WindowSize + 10, true}, {WindowSize + 10, false},
		{10, false},             // fell out of the window
		{11, true}, {11, false}, // oldest still inside
		{WindowSize + 9, true},
		{10 * WindowSize, true}, {10*WindowSize - 1, true}, {10*WindowSize - 1, false},
		{9 * WindowSize, false}, {9*WindowSize + 1, true},
	}
	for i, s := range steps {
		if got := w.Accept(s.ctr); got != s.want {
			t.Fatalf("step %d: Accept(%d) = %v, want %v", i, s.ctr, got, s.want)
		}
	}
	// Every counter is accepted exactly once, in any order within the window.
	var w2 ReplayWindow
	for c := uint64(0); c < 3*WindowSize; c += 2 {
		if !w2.Accept(c+1) || !w2.Accept(c) || w2.Accept(c+1) || w2.Accept(c) {
			t.Fatalf("pairwise reorder failed at %d", c)
		}
	}
}

func TestCookie(t *testing.T) {
	ini, res := mustKey(t), mustKey(t)
	var jar CookieJar
	addr := netip.MustParseAddrPort("192.0.2.7:4000")
	now := time.Now()
	msg, st, _ := CreateInit(ini, PublicOf(res), 3, now, nil)
	cookie := jar.Cookie(addr, now)
	if CheckMac2(cookie[:], msg) {
		t.Fatal("mac2 valid without a cookie")
	}
	reply := CreateCookieReply(PublicOf(res), msg, cookie)
	if len(reply) != CookieReplySize {
		t.Fatalf("cookie reply size %d", len(reply))
	}
	got, err := st.ConsumeCookieReply(PublicOf(res), reply)
	if err != nil || !bytes.Equal(got, cookie[:]) {
		t.Fatalf("cookie roundtrip: %v", err)
	}
	reply[40] ^= 1
	if _, err := st.ConsumeCookieReply(PublicOf(res), reply); err == nil {
		t.Fatal("tampered cookie reply accepted")
	}
	msg2, _, _ := CreateInit(ini, PublicOf(res), 4, now, got)
	if !CheckGate(PublicOf(res), msg2) || !CheckMac2(cookie[:], msg2) {
		t.Fatal("init with cookie rejected")
	}
	other := jar.Cookie(netip.MustParseAddrPort("192.0.2.8:4000"), now)
	if CheckMac2(other[:], msg2) {
		t.Fatal("cookie is not bound to the source address")
	}
	later := jar.Cookie(addr, now.Add(cookieLifetime+time.Second))
	if later == cookie {
		t.Fatal("cookie secret did not rotate")
	}
}
