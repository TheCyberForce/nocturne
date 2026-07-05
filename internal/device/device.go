// Package device is the Nocturne tunnel engine. It moves IP packets
// between a TUN interface and a UDP socket, and runs the session state
// machine (handshakes, rekeying, roaming, keepalives) for each peer.
package device

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dr33kos/nocturne/internal/proto"
)

// Tun is the layer 3 interface the device reads from and writes to.
type Tun interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// Timing holds the protocol timers. Production code uses DefaultTiming.
type Timing struct {
	RekeyAfter      time.Duration // start a new handshake once a session is this old
	RejectAfter     time.Duration // never use a session older than this
	HandshakeRetry  time.Duration // resend an unanswered Init after this long
	HandshakeGiveUp time.Duration // stop retrying and drop queued packets
	Tick            time.Duration // timer resolution
	LoadThreshold   int           // Inits per second before cookies are required
}

func DefaultTiming() Timing {
	return Timing{
		RekeyAfter:      120 * time.Second,
		RejectAfter:     180 * time.Second,
		HandshakeRetry:  5 * time.Second,
		HandshakeGiveUp: 90 * time.Second,
		Tick:            100 * time.Millisecond,
		LoadThreshold:   50,
	}
}

const (
	rekeyAfterMessages = 1 << 60
	maxQueue           = 64
	DefaultMTU         = 1420
)

type PeerConfig struct {
	PublicKey  [proto.KeySize]byte
	PSK        [proto.KeySize]byte // all zero when unused
	Endpoint   netip.AddrPort      // zero when the peer must contact us first
	AllowedIPs []netip.Prefix
	Keepalive  time.Duration
}

type Config struct {
	PrivateKey *ecdh.PrivateKey
	MTU        int
	Peers      []PeerConfig
	Timing     *Timing
	Logf       func(format string, args ...any)
}

type route struct {
	prefix netip.Prefix
	peer   *Peer
}

type Device struct {
	tun  Tun
	conn *net.UDPConn
	priv *ecdh.PrivateKey
	pub  [proto.KeySize]byte
	mtu  int
	t    Timing
	logf func(string, ...any)

	peers  map[[proto.KeySize]byte]*Peer // immutable after New
	order  []*Peer
	routes []route // longest prefix first

	imu   sync.RWMutex
	index map[uint32]*Peer // local session/handshake index -> owner

	jar       proto.CookieJar
	loadMu    sync.Mutex
	loadStart time.Time
	loadCount int

	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New builds a device over an open TUN interface and a bound UDP socket.
func New(tun Tun, conn *net.UDPConn, cfg Config) (*Device, error) {
	if cfg.PrivateKey == nil {
		return nil, errors.New("nocturne: missing private key")
	}
	d := &Device{
		tun: tun, conn: conn, priv: cfg.PrivateKey, pub: proto.PublicOf(cfg.PrivateKey),
		mtu: cfg.MTU, t: DefaultTiming(), logf: cfg.Logf,
		peers: map[[proto.KeySize]byte]*Peer{}, index: map[uint32]*Peer{},
		closed: make(chan struct{}),
	}
	if d.mtu == 0 {
		d.mtu = DefaultMTU
	}
	if cfg.Timing != nil {
		d.t = *cfg.Timing
	}
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}
	for _, pc := range cfg.Peers {
		if pc.PublicKey == d.pub {
			return nil, errors.New("nocturne: a peer has our own public key")
		}
		if d.peers[pc.PublicKey] != nil {
			return nil, errors.New("nocturne: duplicate peer")
		}
		p := &Peer{d: d, pub: pc.PublicKey, psk: pc.PSK, endpoint: pc.Endpoint, keepalive: pc.Keepalive}
		for _, pfx := range pc.AllowedIPs {
			pfx = pfx.Masked()
			for _, r := range d.routes {
				if r.prefix == pfx {
					return nil, fmt.Errorf("nocturne: %v is assigned to two peers", pfx)
				}
			}
			p.allowed = append(p.allowed, pfx)
			d.routes = append(d.routes, route{pfx, p})
		}
		d.peers[pc.PublicKey] = p
		d.order = append(d.order, p)
	}
	sort.SliceStable(d.routes, func(i, j int) bool { return d.routes[i].prefix.Bits() > d.routes[j].prefix.Bits() })
	return d, nil
}

// Start launches the packet and timer loops.
func (d *Device) Start() {
	d.wg.Add(3)
	go d.tunLoop()
	go d.udpLoop()
	go d.timerLoop()
}

// Close stops the device and closes the TUN interface and the socket.
func (d *Device) Close() {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.tun.Close()
		d.conn.Close()
	})
	d.wg.Wait()
}

// Done is closed when the device stops, including after a fatal I/O error.
func (d *Device) Done() <-chan struct{} { return d.closed }

func (d *Device) stopped() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func (d *Device) fail(what string, err error) {
	if !d.stopped() {
		d.logf("%s: %v", what, err)
		d.closeOnce.Do(func() {
			close(d.closed)
			d.tun.Close()
			d.conn.Close()
		})
	}
}

func (d *Device) routeTo(dst netip.Addr) *Peer {
	for _, r := range d.routes {
		if r.prefix.Contains(dst) {
			return r.peer
		}
	}
	return nil
}

func (d *Device) newIndex(p *Peer) uint32 {
	d.imu.Lock()
	defer d.imu.Unlock()
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		idx := binary.LittleEndian.Uint32(b[:])
		if _, taken := d.index[idx]; !taken {
			d.index[idx] = p
			return idx
		}
	}
}

func (d *Device) dropIndex(idx uint32) {
	d.imu.Lock()
	delete(d.index, idx)
	d.imu.Unlock()
}

func (d *Device) lookup(idx uint32) *Peer {
	d.imu.RLock()
	defer d.imu.RUnlock()
	return d.index[idx]
}

// underLoad counts handshake initiations and reports whether the rate in
// the current one-second window exceeds the threshold.
func (d *Device) underLoad(now time.Time) bool {
	d.loadMu.Lock()
	defer d.loadMu.Unlock()
	if now.Sub(d.loadStart) >= time.Second {
		d.loadStart, d.loadCount = now, 0
	}
	d.loadCount++
	return d.loadCount > d.t.LoadThreshold
}

func (d *Device) write(msg []byte, to netip.AddrPort) {
	if _, err := d.conn.WriteToUDPAddrPort(msg, to); err != nil && !d.stopped() {
		d.logf("udp send to %v: %v", to, err)
	}
}

// tunLoop encrypts packets leaving the host.
func (d *Device) tunLoop() {
	defer d.wg.Done()
	buf := make([]byte, proto.DataHeader+d.mtu+proto.TagSize)
	for {
		n, err := d.tun.Read(buf[proto.DataHeader : proto.DataHeader+d.mtu])
		if err != nil {
			d.fail("tun read", err)
			return
		}
		_, dst, _, ok := parseIP(buf[proto.DataHeader : proto.DataHeader+n])
		if !ok {
			continue
		}
		if p := d.routeTo(dst); p != nil {
			p.send(buf, n)
		}
	}
}

// udpLoop handles everything arriving from the network.
func (d *Device) udpLoop() {
	defer d.wg.Done()
	buf := make([]byte, max(2048, d.mtu+256))
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			d.fail("udp read", err)
			return
		}
		if n == 0 {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		msg := buf[:n]
		switch msg[0] {
		case proto.TypeData:
			d.handleData(msg, from)
		case proto.TypeInit:
			d.handleInit(msg, from)
		case proto.TypeResponse:
			d.handleResponse(msg, from)
		case proto.TypeCookie:
			d.handleCookie(msg)
		}
	}
}

func (d *Device) timerLoop() {
	defer d.wg.Done()
	tick := time.NewTicker(d.t.Tick)
	defer tick.Stop()
	for {
		select {
		case <-d.closed:
			return
		case now := <-tick.C:
			for _, p := range d.order {
				p.tick(now)
			}
		}
	}
}

func (d *Device) handleInit(msg []byte, from netip.AddrPort) {
	// Anything failing the gate gets no reply at all: to a scanner this
	// port is indistinguishable from a closed one behind a drop rule.
	if !proto.CheckGate(d.pub, msg) {
		return
	}
	now := time.Now()
	if d.underLoad(now) {
		cookie := d.jar.Cookie(from, now)
		if !proto.CheckMac2(cookie[:], msg) {
			d.write(proto.CreateCookieReply(d.pub, msg, cookie), from)
			return
		}
	}
	r, err := proto.ConsumeInit(d.priv, msg)
	if err != nil {
		return
	}
	p := d.peers[r.PeerStatic]
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Timestamp <= p.lastInitTS {
		return // replayed or reordered Init
	}
	idx := d.newIndex(p)
	resp, keys, err := r.CreateResponse(&p.psk, idx)
	if err != nil {
		d.dropIndex(idx)
		return
	}
	p.lastInitTS = r.Timestamp
	if p.next != nil {
		d.dropIndex(p.next.localIdx)
	}
	// The session can receive immediately, but we only send on it (and
	// only trust the new endpoint) once the initiator proves it holds the
	// keys by sending us a valid packet.
	p.next = d.newSession(keys, idx, false, now)
	d.write(resp, from)
}

func (d *Device) handleResponse(msg []byte, from netip.AddrPort) {
	idx, ok := proto.ResponseReceiver(msg)
	if !ok {
		return
	}
	p := d.lookup(idx)
	if p == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	if p.hs == nil || p.hs.LocalIndex != idx {
		p.mu.Unlock()
		return
	}
	keys, err := p.hs.ConsumeResponse(d.priv, &p.psk, msg)
	if err != nil {
		p.mu.Unlock()
		return
	}
	p.hs = nil
	p.install(d.newSession(keys, idx, true, now), from, now)
	s, queue := p.cur, p.takeQueue()
	p.mu.Unlock()
	d.logf("peer %s: session established with %v", p.Name(), from)
	if len(queue) == 0 {
		// Confirms the session to the responder even if we have nothing to say.
		d.sendKeepalive(p, s, from)
	}
	for _, q := range queue {
		d.sendData(p, s, from, q.buf, q.n)
	}
}

func (d *Device) handleCookie(msg []byte) {
	idx, ok := proto.CookieReceiver(msg)
	if !ok {
		return
	}
	p := d.lookup(idx)
	if p == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hs == nil || p.hs.LocalIndex != idx {
		return
	}
	cookie, err := p.hs.ConsumeCookieReply(p.pub, msg)
	if err != nil {
		return
	}
	p.cookie, p.cookieAt = cookie, now
	if !p.cookieRetried {
		p.startHandshake(now, true)
	}
}

func (d *Device) handleData(msg []byte, from netip.AddrPort) {
	idx, ctr, ok := proto.ParseData(msg)
	if !ok {
		return
	}
	p := d.lookup(idx)
	if p == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	s := p.sessionFor(idx)
	p.mu.Unlock()
	if s == nil || now.Sub(s.created) > d.t.RejectAfter {
		return
	}
	pt, err := proto.OpenData(s.recv, ctr, msg)
	if err != nil {
		return
	}
	s.rmu.Lock()
	fresh := s.replay.Accept(ctr)
	s.rmu.Unlock()
	if !fresh {
		return
	}

	var queue []queued
	p.mu.Lock()
	if s == p.next {
		p.next = nil
		p.install(s, from, now)
		queue = p.takeQueue()
		d.logf("peer %s: session established with %v", p.Name(), from)
	} else if s == p.cur {
		p.endpoint = from // roaming: follow the newest authenticated source
	} else if s != p.prev {
		p.mu.Unlock()
		return // retired while we were decrypting
	}
	cur, ep := p.cur, p.endpoint
	p.mu.Unlock()
	for _, q := range queue {
		d.sendData(p, cur, ep, q.buf, q.n)
	}

	p.rx.Add(uint64(len(msg)))
	if len(pt) == 0 {
		return // keepalive
	}
	src, _, length, ok := parseIP(pt)
	if !ok || length > len(pt) || !p.allows(src) {
		return
	}
	if _, err := d.tun.Write(pt[:length]); err != nil && !d.stopped() {
		d.logf("tun write: %v", err)
	}
}

// sendData pads, encrypts and transmits the n-byte packet stored in buf
// after proto.DataHeader bytes of headroom.
func (d *Device) sendData(p *Peer, s *session, to netip.AddrPort, buf []byte, n int) {
	if !to.IsValid() {
		return
	}
	// Pad to a multiple of 16 to blur packet lengths, without exceeding the MTU.
	padded := min((n+15)&^15, max(n, d.mtu))
	end := proto.DataHeader + padded
	clear(buf[proto.DataHeader+n : end])
	msg := proto.SealData(s.send, s.remoteIdx, s.sendCtr.Add(1)-1, buf[:end])
	d.write(msg, to)
	p.lastSend.Store(time.Now().UnixNano())
	p.tx.Add(uint64(len(msg)))
}

func (d *Device) sendKeepalive(p *Peer, s *session, to netip.AddrPort) {
	d.sendData(p, s, to, make([]byte, proto.DataHeader, proto.DataHeader+proto.TagSize), 0)
}

func (d *Device) newSession(k *proto.Keys, localIdx uint32, initiator bool, now time.Time) *session {
	s := &session{localIdx: localIdx, remoteIdx: k.RemoteIndex, send: k.Send, recv: k.Recv, created: now}
	s.rekeyAt = d.t.RekeyAfter
	if !initiator {
		// Stagger so both ends do not start a rekey at the same instant.
		s.rekeyAt += d.t.RekeyAfter / 8
	}
	return s
}

// Status returns a human-readable summary of the device.
func (d *Device) Status() string {
	var b strings.Builder
	fmt.Fprintf(&b, "public key: %s\nlistening:  %v\n", EncodeKey(d.pub), d.conn.LocalAddr())
	now := time.Now()
	for _, p := range d.order {
		p.mu.Lock()
		fmt.Fprintf(&b, "\npeer %s\n", EncodeKey(p.pub))
		if p.endpoint.IsValid() {
			fmt.Fprintf(&b, "  endpoint:    %v\n", p.endpoint)
		}
		fmt.Fprintf(&b, "  allowed ips: %s\n", joinPrefixes(p.allowed))
		if p.cur != nil {
			fmt.Fprintf(&b, "  session:     %s old\n", now.Sub(p.cur.created).Round(time.Second))
		} else {
			fmt.Fprintf(&b, "  session:     none\n")
		}
		fmt.Fprintf(&b, "  transfer:    %d B received, %d B sent\n", p.rx.Load(), p.tx.Load())
		p.mu.Unlock()
	}
	return b.String()
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// parseIP extracts the addresses and total length of an IPv4 or IPv6 packet.
func parseIP(pkt []byte) (src, dst netip.Addr, length int, ok bool) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		src, dst = netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20]))
		length = int(binary.BigEndian.Uint16(pkt[2:4]))
		return src, dst, length, length >= 20
	case 6:
		if len(pkt) < 40 {
			return
		}
		src, dst = netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
		return src, dst, 40 + int(binary.BigEndian.Uint16(pkt[4:6])), true
	}
	return
}
