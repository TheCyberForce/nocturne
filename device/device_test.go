package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/TheCyberForce/nocturne/internal/proto"
)

// chanTun is an in-memory TUN: the test injects outbound packets on in
// and collects delivered packets from out.
type chanTun struct {
	in, out chan []byte
	done    chan struct{}
}

func newChanTun() *chanTun {
	return &chanTun{make(chan []byte, 256), make(chan []byte, 256), make(chan struct{})}
}
func (t *chanTun) Read(b []byte) (int, error) {
	select {
	case p := <-t.in:
		return copy(b, p), nil
	case <-t.done:
		return 0, errors.New("closed")
	}
}
func (t *chanTun) Write(b []byte) (int, error) {
	t.out <- append([]byte(nil), b...)
	return len(b), nil
}
func (t *chanTun) Close() error { close(t.done); return nil }

func (t *chanTun) expect(tb testing.TB, want []byte) {
	tb.Helper()
	select {
	case got := <-t.out:
		if !bytes.Equal(got, want) {
			tb.Fatalf("delivered packet differs: got %d bytes, want %d", len(got), len(want))
		}
	case <-time.After(3 * time.Second):
		tb.Fatal("packet was not delivered")
	}
}

func (t *chanTun) expectNothing(tb testing.TB, wait time.Duration) {
	tb.Helper()
	select {
	case got := <-t.out:
		tb.Fatalf("unexpected packet delivered (%d bytes)", len(got))
	case <-time.After(wait):
	}
}

func ipv4(src, dst string, payload int) []byte {
	p := make([]byte, 20+payload)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:], s[:])
	copy(p[16:], d[:])
	for i := 20; i < len(p); i++ {
		p[i] = byte(i)
	}
	return p
}

func listen(tb testing.TB) *net.UDPConn {
	tb.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

func addrOf(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

type node struct {
	dev  *Device
	tun  *chanTun
	conn *net.UDPConn
}

// pair builds client A (10.9.0.1) and server B (10.9.0.2). A knows B's
// endpoint (or via, if set); B learns A's from the handshake.
func pair(tb testing.TB, timing *Timing, via netip.AddrPort, tweak func(a, b *Config)) (a, b node) {
	tb.Helper()
	ka, _ := proto.GeneratePrivateKey()
	kb, _ := proto.GeneratePrivateKey()
	a.conn, b.conn = listen(tb), listen(tb)
	a.tun, b.tun = newChanTun(), newChanTun()
	ep := addrOf(b.conn)
	if via.IsValid() {
		ep = via
	}
	ca := Config{PrivateKey: ka, Timing: timing, Peers: []PeerConfig{{
		PublicKey: proto.PublicOf(kb), Endpoint: ep,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")},
	}}}
	cb := Config{PrivateKey: kb, Timing: timing, Peers: []PeerConfig{{
		PublicKey:  proto.PublicOf(ka),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")},
	}}}
	if tweak != nil {
		tweak(&ca, &cb)
	}
	var err error
	if a.dev, err = New(a.tun, a.conn, ca); err != nil {
		tb.Fatal(err)
	}
	if b.dev, err = New(b.tun, b.conn, cb); err != nil {
		tb.Fatal(err)
	}
	a.dev.Start()
	b.dev.Start()
	tb.Cleanup(func() { a.dev.Close(); b.dev.Close() })
	return
}

func TestTunnelBothDirections(t *testing.T) {
	a, b := pair(t, nil, netip.AddrPort{}, nil)
	// Odd sizes exercise padding and its removal.
	for _, size := range []int{0, 1, 15, 16, 17, 700, DefaultMTU - 20} {
		out := ipv4("10.9.0.1", "10.9.0.2", size)
		a.tun.in <- out
		b.tun.expect(t, out)
		back := ipv4("10.9.0.2", "10.9.0.1", size)
		b.tun.in <- back
		a.tun.expect(t, back)
	}
}

// The server has no endpoint for the client and nothing queued may leak:
// packets sent before any handshake are held, then delivered.
func TestQueueUntilHandshake(t *testing.T) {
	a, b := pair(t, nil, netip.AddrPort{}, nil)
	var sent [][]byte
	for i := 0; i < 10; i++ {
		p := ipv4("10.9.0.1", "10.9.0.2", 100+i)
		sent = append(sent, p)
		a.tun.in <- p
	}
	for _, p := range sent {
		b.tun.expect(t, p)
	}
}

func TestSpoofedInnerSourceDropped(t *testing.T) {
	a, b := pair(t, nil, netip.AddrPort{}, func(ca, cb *Config) {
		// A will route this destination to B, but B does not allow A to
		// speak for 10.9.0.77.
		ca.Peers[0].AllowedIPs = append(ca.Peers[0].AllowedIPs, netip.MustParsePrefix("10.9.1.0/24"))
	})
	a.tun.in <- ipv4("10.9.0.77", "10.9.1.5", 64)
	b.tun.expectNothing(t, 300*time.Millisecond)
	ok := ipv4("10.9.0.1", "10.9.1.5", 64)
	a.tun.in <- ok
	b.tun.expect(t, ok)
}

func TestPresharedKey(t *testing.T) {
	a, b := pair(t, nil, netip.AddrPort{}, func(ca, cb *Config) {
		ca.Peers[0].PSK = [32]byte{1, 2, 3}
		cb.Peers[0].PSK = [32]byte{1, 2, 3}
	})
	p := ipv4("10.9.0.1", "10.9.0.2", 64)
	a.tun.in <- p
	b.tun.expect(t, p)

	c, d := pair(t, nil, netip.AddrPort{}, func(ca, cb *Config) {
		ca.Peers[0].PSK = [32]byte{1, 2, 3}
	})
	c.tun.in <- p
	d.tun.expectNothing(t, 300*time.Millisecond)
}

func fastTiming() *Timing {
	t := DefaultTiming()
	t.RekeyAfter = 300 * time.Millisecond
	t.RejectAfter = 900 * time.Millisecond
	t.HandshakeRetry = 150 * time.Millisecond
	t.HandshakeGiveUp = 2 * time.Second
	t.Tick = 10 * time.Millisecond
	return &t
}

// Traffic keeps flowing across several rekeys, with no packet lost.
func TestRekey(t *testing.T) {
	a, b := pair(t, fastTiming(), netip.AddrPort{}, nil)
	first := map[*Device]*session{}
	for i := 0; i < 150; i++ {
		out := ipv4("10.9.0.1", "10.9.0.2", i)
		a.tun.in <- out
		b.tun.expect(t, out)
		back := ipv4("10.9.0.2", "10.9.0.1", i)
		b.tun.in <- back
		a.tun.expect(t, back)
		if i == 0 {
			first[a.dev], first[b.dev] = a.dev.order[0].current(), b.dev.order[0].current()
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, n := range []node{a, b} {
		cur := n.dev.order[0].current()
		if cur == nil || cur == first[n.dev] {
			t.Fatal("session was never rekeyed")
		}
	}
	// Old sessions are forgotten: only current/previous/next (+ a pending
	// handshake) may be indexed.
	a.dev.imu.RLock()
	defer a.dev.imu.RUnlock()
	if len(a.dev.index) > 4 {
		t.Fatalf("%d indexes retained", len(a.dev.index))
	}
}

// An idle session expires and its keys are dropped; the next packet
// triggers a fresh handshake.
func TestExpiryAndRecovery(t *testing.T) {
	a, b := pair(t, fastTiming(), netip.AddrPort{}, nil)
	p := ipv4("10.9.0.1", "10.9.0.2", 64)
	a.tun.in <- p
	b.tun.expect(t, p)
	time.Sleep(1100 * time.Millisecond)
	if a.dev.order[0].current() != nil || b.dev.order[0].current() != nil {
		t.Fatal("expired session still installed")
	}
	a.tun.in <- p
	b.tun.expect(t, p)
}

func TestPersistentKeepalive(t *testing.T) {
	a, b := pair(t, fastTiming(), netip.AddrPort{}, func(ca, cb *Config) {
		ca.Peers[0].Keepalive = 50 * time.Millisecond
	})
	// Without any traffic from A, B must learn A's endpoint and be able
	// to reach it, and stay able to across rekeys.
	for i := 0; i < 4; i++ {
		time.Sleep(400 * time.Millisecond)
		p := ipv4("10.9.0.2", "10.9.0.1", 64+i)
		b.tun.in <- p
		a.tun.expect(t, p)
	}
}

// relay is a hostile network: it forwards datagrams between two parties
// and can duplicate them, rewrite them, or record them.
type relay struct {
	conn   *net.UDPConn
	server netip.AddrPort
	client netip.AddrPort
	mangle func(fromClient bool, msg []byte) [][]byte
}

func newRelay(tb testing.TB, mangle func(bool, []byte) [][]byte) *relay {
	r := &relay{conn: listen(tb), mangle: mangle}
	tb.Cleanup(func() { r.conn.Close() })
	return r
}

func (r *relay) run() {
	buf := make([]byte, 4096)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		fromClient := from != r.server
		to := r.server
		if fromClient {
			r.client = from
		} else {
			to = r.client
		}
		for _, m := range r.mangle(fromClient, append([]byte(nil), buf[:n]...)) {
			r.conn.WriteToUDPAddrPort(m, to)
		}
	}
}

// Every datagram is delivered twice: each inner packet must still be
// delivered exactly once, and duplicated handshake messages must be harmless.
func TestReplayedDatagramsDropped(t *testing.T) {
	r := newRelay(t, func(_ bool, m []byte) [][]byte { return [][]byte{m, m} })
	a, b := pair(t, nil, addrOf(r.conn), nil)
	r.server = addrOf(b.conn)
	go r.run()
	for i := 0; i < 20; i++ {
		out := ipv4("10.9.0.1", "10.9.0.2", 50+i)
		a.tun.in <- out
		b.tun.expect(t, out)
		back := ipv4("10.9.0.2", "10.9.0.1", 50+i)
		b.tun.in <- back
		a.tun.expect(t, back)
	}
	a.tun.expectNothing(t, 200*time.Millisecond)
	b.tun.expectNothing(t, 0)
}

// Flipping one bit anywhere in any data packet must prevent delivery.
func TestTamperedDataDropped(t *testing.T) {
	pos := 0
	r := newRelay(t, func(fromClient bool, m []byte) [][]byte {
		if m[0] == proto.TypeData && fromClient && len(m) > proto.DataHeader+proto.TagSize {
			m[pos%len(m)] ^= 0x01
			pos += 7
		}
		return [][]byte{m}
	})
	a, b := pair(t, nil, addrOf(r.conn), nil)
	r.server = addrOf(b.conn)
	go r.run()
	for i := 0; i < 40; i++ {
		a.tun.in <- ipv4("10.9.0.1", "10.9.0.2", 64)
	}
	b.tun.expectNothing(t, 500*time.Millisecond)
}

// The client's source address changes mid-session (NAT rebinding, wifi to
// cellular). The server must follow it without a new handshake.
func TestRoaming(t *testing.T) {
	a, b := pair(t, nil, netip.AddrPort{}, nil)
	p := ipv4("10.9.0.1", "10.9.0.2", 64)
	a.tun.in <- p
	b.tun.expect(t, p)
	before := b.dev.order[0].current()

	// Put a relay in the path: from B's point of view A has moved.
	r := newRelay(t, func(_ bool, m []byte) [][]byte { return [][]byte{m} })
	r.server = addrOf(b.conn)
	go r.run()
	ap := a.dev.order[0]
	ap.mu.Lock()
	ap.endpoint = addrOf(r.conn)
	ap.mu.Unlock()

	a.tun.in <- p
	b.tun.expect(t, p)
	back := ipv4("10.9.0.2", "10.9.0.1", 64)
	b.tun.in <- back
	a.tun.expect(t, back)
	bp := b.dev.order[0]
	bp.mu.Lock()
	ep := bp.endpoint
	bp.mu.Unlock()
	if ep != addrOf(r.conn) {
		t.Fatalf("server did not follow the client: endpoint %v", ep)
	}
	if b.dev.order[0].current() != before {
		t.Fatal("roaming forced a new session")
	}
}

// A server must not answer anything from a sender that cannot prove it
// knows the server's public key.
func TestSilentToStrangers(t *testing.T) {
	_, b := pair(t, nil, netip.AddrPort{}, nil)
	probe := listen(t)
	defer probe.Close()
	stranger, _ := proto.GeneratePrivateKey()
	wrongKey, _ := proto.GeneratePrivateKey()
	// A syntactically perfect Init, but built for the wrong server key.
	blind, _, _ := proto.CreateInit(stranger, proto.PublicOf(wrongKey), 1, time.Now(), nil)
	// A correct gate, from a key the server does not list as a peer.
	unknown, _, _ := proto.CreateInit(stranger, b.dev.pub, 1, time.Now(), nil)
	probes := [][]byte{
		blind, unknown, {}, {1}, {2}, {3}, {4}, bytes.Repeat([]byte{1}, proto.InitSize),
		bytes.Repeat([]byte{2}, proto.ResponseSize), bytes.Repeat([]byte{3}, 64),
		bytes.Repeat([]byte{4}, proto.CookieReplySize), bytes.Repeat([]byte{0xff}, 1400),
	}
	for _, m := range probes {
		probe.WriteToUDPAddrPort(m, addrOf(b.conn))
	}
	probe.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _, err := probe.ReadFromUDPAddrPort(make([]byte, 2048)); err == nil {
		t.Fatalf("server answered a stranger with %d bytes", n)
	}
}

// Even under load, when the server answers Inits with cookie replies, a
// sender that does not know the server's public key gets nothing.
func TestSilentToStrangersUnderLoad(t *testing.T) {
	timing := DefaultTiming()
	timing.LoadThreshold = 0
	_, b := pair(t, &timing, netip.AddrPort{}, nil)
	probe := listen(t)
	defer probe.Close()
	stranger, _ := proto.GeneratePrivateKey()
	wrongKey, _ := proto.GeneratePrivateKey()
	blind, _, _ := proto.CreateInit(stranger, proto.PublicOf(wrongKey), 1, time.Now(), nil)
	probe.WriteToUDPAddrPort(blind, addrOf(b.conn))
	probe.WriteToUDPAddrPort(bytes.Repeat([]byte{1}, proto.InitSize), addrOf(b.conn))
	probe.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _, err := probe.ReadFromUDPAddrPort(make([]byte, 2048)); err == nil {
		t.Fatalf("server answered a stranger with %d bytes", n)
	}
}

// Under load the server demands a cookie; an honest client obtains one
// and connects, and the server does no public-key work before that.
func TestCookieUnderLoad(t *testing.T) {
	timing := DefaultTiming()
	timing.LoadThreshold = 0 // always under load
	var cookies, inits int
	r := newRelay(t, func(fromClient bool, m []byte) [][]byte {
		switch m[0] {
		case proto.TypeCookie:
			cookies++
		case proto.TypeInit:
			inits++
		}
		return [][]byte{m}
	})
	a, b := pair(t, &timing, addrOf(r.conn), nil)
	r.server = addrOf(b.conn)
	go r.run()
	p := ipv4("10.9.0.1", "10.9.0.2", 64)
	a.tun.in <- p
	b.tun.expect(t, p)
	if cookies != 1 || inits != 2 {
		t.Fatalf("expected 1 cookie reply and 2 inits, saw %d and %d", cookies, inits)
	}
}

// A recorded Init replayed later must not disturb the live session.
func TestReplayedInitIgnored(t *testing.T) {
	var recorded []byte
	r := newRelay(t, func(fromClient bool, m []byte) [][]byte {
		if m[0] == proto.TypeInit && recorded == nil {
			recorded = m
		}
		return [][]byte{m}
	})
	a, b := pair(t, nil, addrOf(r.conn), nil)
	r.server = addrOf(b.conn)
	go r.run()
	p := ipv4("10.9.0.1", "10.9.0.2", 64)
	a.tun.in <- p
	b.tun.expect(t, p)

	attacker := listen(t)
	defer attacker.Close()
	attacker.WriteToUDPAddrPort(recorded, addrOf(b.conn))
	attacker.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := attacker.ReadFromUDPAddrPort(make([]byte, 2048)); err == nil {
		t.Fatal("server answered a replayed init")
	}
	back := ipv4("10.9.0.2", "10.9.0.1", 64)
	b.tun.in <- back
	a.tun.expect(t, back) // still reaches the real client, not the attacker
}

func TestConfigRejectsOverlap(t *testing.T) {
	k, _ := proto.GeneratePrivateKey()
	k1, _ := proto.GeneratePrivateKey()
	k2, _ := proto.GeneratePrivateKey()
	pfx := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	_, err := New(newChanTun(), nil, Config{PrivateKey: k, Peers: []PeerConfig{
		{PublicKey: proto.PublicOf(k1), AllowedIPs: pfx},
		{PublicKey: proto.PublicOf(k2), AllowedIPs: pfx},
	}})
	if err == nil {
		t.Fatal("two peers were given the same prefix")
	}
}

func BenchmarkTunnel(b *testing.B) {
	x, y := pair(b, nil, netip.AddrPort{}, nil)
	p := ipv4("10.9.0.1", "10.9.0.2", DefaultMTU-20)
	x.tun.in <- p
	y.tun.expect(b, p)
	b.SetBytes(int64(len(p)))
	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			x.tun.in <- p
		}
	}()
	got := 0
	deadline := time.After(20 * time.Second)
	for got < b.N {
		select {
		case <-y.tun.out:
			got++
		case <-time.After(200 * time.Millisecond):
			// UDP over loopback may drop under pressure; count what arrived.
			b.SetBytes(int64(len(p)) * int64(got) / int64(max(b.N, 1)))
			return
		case <-deadline:
			return
		}
	}
}
