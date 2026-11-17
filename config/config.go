// Package config parses Nocturne tunnel files.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/TheCyberForce/nocturne/device"
	"github.com/TheCyberForce/nocturne/internal/proto"
)

// Tunnel is a parsed tunnel file.
type Tunnel struct {
	Name      string
	Addresses []netip.Prefix
	Listen    netip.AddrPort // port 0: pick any
	Device    device.Config
}

// Load reads and validates the tunnel file at path. The interface name
// defaults to the file name without its extension.
func Load(path string) (*Tunnel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Windows has no permission bits; access there is governed by ACLs.
	if st, err := f.Stat(); err == nil && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s is readable by other users; it holds a private key (chmod 600)\n", path)
	}
	return Parse(path, f)
}

// Parse reads and validates a tunnel file from r. path is used for error
// messages and for the default interface name.
func Parse(path string, f io.Reader) (*Tunnel, error) {
	var err error
	t := &Tunnel{
		Name:   strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Listen: netip.AddrPortFrom(netip.IPv6Unspecified(), 0),
	}
	t.Device.MTU = device.DefaultMTU

	var section string
	var peer *device.PeerConfig
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		fail := func(err error) error { return fmt.Errorf("%s:%d: %w", path, line, err) }
		if strings.HasPrefix(text, "[") {
			section = strings.ToLower(text)
			switch section {
			case "[tunnel]":
			case "[peer]":
				t.Device.Peers = append(t.Device.Peers, device.PeerConfig{})
				peer = &t.Device.Peers[len(t.Device.Peers)-1]
			default:
				return nil, fail(fmt.Errorf("unknown section %s", text))
			}
			continue
		}
		key, val, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fail(fmt.Errorf("expected key = value"))
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		switch section + key {
		case "[tunnel]private_key":
			k, e := device.DecodeKey(val)
			if e == nil {
				t.Device.PrivateKey, e = proto.ParsePrivateKey(k[:])
			}
			err = e
		case "[tunnel]name":
			t.Name = val
		case "[tunnel]address":
			t.Addresses, err = prefixes(val, false)
		case "[tunnel]listen":
			if port, e := strconv.ParseUint(val, 10, 16); e == nil {
				t.Listen = netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(port))
			} else {
				t.Listen, err = netip.ParseAddrPort(val)
			}
		case "[tunnel]mtu":
			t.Device.MTU, err = strconv.Atoi(val)
			if err == nil && (t.Device.MTU < 576 || t.Device.MTU > 65000) {
				err = fmt.Errorf("mtu out of range")
			}
		case "[peer]public_key":
			peer.PublicKey, err = device.DecodeKey(val)
		case "[peer]preshared_key":
			peer.PSK, err = device.DecodeKey(val)
		case "[peer]endpoint":
			peer.Endpoint, err = resolve(val)
		case "[peer]allowed_ips":
			peer.AllowedIPs, err = prefixes(val, true)
		case "[peer]keepalive":
			var secs int
			secs, err = strconv.Atoi(val)
			if err == nil && (secs < 0 || secs > 3600) {
				err = fmt.Errorf("keepalive out of range")
			}
			peer.Keepalive = time.Duration(secs) * time.Second
		default:
			err = fmt.Errorf("unknown setting %q in %s", key, section)
		}
		if err != nil {
			return nil, fail(err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if t.Device.PrivateKey == nil {
		return nil, fmt.Errorf("%s: [tunnel] private_key is required", path)
	}
	if len(t.Addresses) == 0 {
		return nil, fmt.Errorf("%s: [tunnel] address is required", path)
	}
	var zero [proto.KeySize]byte
	for i, p := range t.Device.Peers {
		if p.PublicKey == zero {
			return nil, fmt.Errorf("%s: peer %d has no public_key", path, i+1)
		}
		for _, pfx := range p.AllowedIPs {
			if pfx.Bits() == 0 {
				return nil, fmt.Errorf("%s: peer %d: default routes (%v) are not supported in this version", path, i+1, pfx)
			}
		}
	}
	return t, nil
}

// Routes lists every prefix that should be routed into the tunnel.
func (t *Tunnel) Routes() (out []string) {
	for _, p := range t.Device.Peers {
		for _, pfx := range p.AllowedIPs {
			out = append(out, pfx.String())
		}
	}
	return
}

func prefixes(list string, mask bool) (out []netip.Prefix, err error) {
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		p, e := netip.ParsePrefix(s)
		if e != nil {
			a, e2 := netip.ParseAddr(s)
			if e2 != nil {
				return nil, e
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if mask {
			p = p.Masked()
		}
		out = append(out, p)
	}
	return
}

func resolve(hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
	}
	ua, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
