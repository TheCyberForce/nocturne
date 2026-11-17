package device

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TheCyberForce/nocturne/internal/proto"
)

// session is one set of transport keys. A peer holds up to three: the
// current one, the previous one (still valid for late packets) and, on
// the responder side, the next one awaiting confirmation.
type session struct {
	localIdx, remoteIdx uint32
	send, recv          cipher.AEAD
	sendCtr             atomic.Uint64
	created             time.Time
	rekeyAt             time.Duration

	rmu    sync.Mutex
	replay proto.ReplayWindow
}

type queued struct {
	buf []byte
	n   int
}

type Peer struct {
	d         *Device
	pub, psk  [proto.KeySize]byte
	allowed   []netip.Prefix
	keepalive time.Duration

	lastSend atomic.Int64 // unix nanoseconds
	rx, tx   atomic.Uint64

	mu              sync.Mutex
	endpoint        netip.AddrPort
	cur, prev, next *session
	hs              *proto.InitState // our pending Init, if any
	hsFirst, hsSent time.Time        // start of this series of attempts / of the latest one
	lastInitTS      uint64           // newest Init timestamp accepted from the peer
	cookie          []byte
	cookieAt        time.Time
	cookieRetried   bool
	queue           []queued // packets waiting for a session
}

// Name is a short identifier for logs.
func (p *Peer) Name() string { return EncodeKey(p.pub)[:8] }

func (p *Peer) allows(src netip.Addr) bool {
	for _, pfx := range p.allowed {
		if pfx.Contains(src) {
			return true
		}
	}
	return false
}

func (p *Peer) sessionFor(idx uint32) *session {
	for _, s := range []*session{p.cur, p.next, p.prev} {
		if s != nil && s.localIdx == idx {
			return s
		}
	}
	return nil
}

// install makes s the current session. Caller holds p.mu.
func (p *Peer) install(s *session, endpoint netip.AddrPort, now time.Time) {
	if p.prev != nil {
		p.d.dropIndex(p.prev.localIdx)
	}
	p.prev, p.cur = p.cur, s
	p.endpoint = endpoint
}

func (p *Peer) takeQueue() []queued {
	q := p.queue
	p.queue = nil
	return q
}

// send transmits the n-byte IP packet held in buf (after DataHeader bytes
// of headroom), or queues it and starts a handshake if no session exists.
func (p *Peer) send(buf []byte, n int) {
	now := time.Now()
	p.mu.Lock()
	s := p.cur
	if s == nil || now.Sub(s.created) > p.d.t.RejectAfter || s.sendCtr.Load() >= rekeyAfterMessages {
		if len(p.queue) == maxQueue {
			p.queue = p.queue[1:]
		}
		cp := make([]byte, len(buf))
		copy(cp, buf[:proto.DataHeader+n])
		p.queue = append(p.queue, queued{cp, n})
		p.wantHandshake(now)
		p.mu.Unlock()
		return
	}
	if now.Sub(s.created) > s.rekeyAt {
		p.wantHandshake(now)
	}
	ep := p.endpoint
	p.mu.Unlock()
	p.d.sendData(p, s, ep, buf, n)
}

// wantHandshake starts a handshake unless one is already in flight.
// Caller holds p.mu.
func (p *Peer) wantHandshake(now time.Time) {
	if p.hs != nil || !p.endpoint.IsValid() {
		return
	}
	p.hsFirst = now
	p.startHandshake(now, false)
}

// startHandshake sends a fresh Init, replacing any pending one.
// Caller holds p.mu.
func (p *Peer) startHandshake(now time.Time, afterCookie bool) {
	if p.hs != nil {
		p.d.dropIndex(p.hs.LocalIndex)
		p.hs = nil
	}
	var cookie []byte
	if p.cookie != nil && now.Sub(p.cookieAt) < time.Minute {
		cookie = p.cookie
	}
	idx := p.d.newIndex(p)
	msg, st, err := proto.CreateInit(p.d.priv, p.pub, idx, now, cookie)
	if err != nil {
		p.d.dropIndex(idx)
		p.d.logf("peer %s: handshake: %v", p.Name(), err)
		return
	}
	p.hs, p.hsSent, p.cookieRetried = st, now, afterCookie
	p.d.write(msg, p.endpoint)
}

// tick runs the peer's timers.
func (p *Peer) tick(now time.Time) {
	d := p.d
	p.mu.Lock()
	for _, sp := range []**session{&p.cur, &p.prev, &p.next} {
		if s := *sp; s != nil && now.Sub(s.created) > d.t.RejectAfter {
			d.dropIndex(s.localIdx)
			*sp = nil
		}
	}
	if p.hs != nil && now.Sub(p.hsSent) >= d.t.HandshakeRetry {
		if now.Sub(p.hsFirst) >= d.t.HandshakeGiveUp {
			d.dropIndex(p.hs.LocalIndex)
			p.hs, p.queue = nil, nil
		} else {
			p.startHandshake(now, false)
		}
	}
	var ka *session
	if p.keepalive > 0 && p.endpoint.IsValid() {
		switch {
		case p.cur == nil || now.Sub(p.cur.created) > p.cur.rekeyAt:
			p.wantHandshake(now)
		case now.Sub(time.Unix(0, p.lastSend.Load())) >= p.keepalive:
			ka = p.cur
		}
	}
	ep := p.endpoint
	p.mu.Unlock()
	if ka != nil {
		d.sendKeepalive(p, ka, ep)
	}
}

// EncodeKey renders a key the way config files and the CLI show it.
func EncodeKey(k [proto.KeySize]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// DecodeKey parses a base64 32-byte key.
func DecodeKey(s string) (k [proto.KeySize]byte, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != proto.KeySize {
		return k, errors.New("nocturne: key must be 32 bytes of base64")
	}
	copy(k[:], b)
	return k, nil
}

func (p *Peer) current() *session {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur
}

// GenerateKey returns a new private key and its public key, both encoded
// for use in a tunnel file.
func GenerateKey() (private, public string, err error) {
	k, err := proto.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return EncodeKey([proto.KeySize]byte(k.Bytes())), EncodeKey(proto.PublicOf(k)), nil
}

// PeerStats is a snapshot of one peer, for user interfaces.
type PeerStats struct {
	PublicKey    string
	Endpoint     netip.AddrPort // zero if unknown
	Connected    bool           // a current session exists
	SessionStart time.Time      // zero if not connected
	Rx, Tx       uint64         // bytes on the wire
}

// Stats returns a snapshot of every peer.
func (d *Device) Stats() []PeerStats {
	out := make([]PeerStats, 0, len(d.order))
	for _, p := range d.order {
		p.mu.Lock()
		s := PeerStats{PublicKey: EncodeKey(p.pub), Endpoint: p.endpoint, Rx: p.rx.Load(), Tx: p.tx.Load()}
		if p.cur != nil {
			s.Connected, s.SessionStart = true, p.cur.created
		}
		p.mu.Unlock()
		out = append(out, s)
	}
	return out
}
