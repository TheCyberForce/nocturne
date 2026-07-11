package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Dr33kos/nocturne/internal/proto"
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

