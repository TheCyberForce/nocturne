// Package tun opens Linux TUN interfaces.
package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIff = 0x400454ca
	ifNameMax = 15
)

// Open creates the TUN interface name and returns its file. The
// interface exists for as long as the file stays open.
func Open(name string) (*os.File, error) {
	if len(name) == 0 || len(name) > ifNameMax || strings.ContainsAny(name, "/ \t\n") {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var ifr [40]byte // struct ifreq
	copy(ifr[:ifNameMax], name)
	binary.NativeEndian.PutUint16(ifr[16:], iffTUN|iffNoPI)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("create interface %s: %w (are you root?)", name, errno)
	}
	// Non-blocking so the Go runtime poller owns the descriptor and Close
	// interrupts a pending Read.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

// Configure assigns addresses, sets the MTU, brings the interface up and
// installs a route for every prefix.
func Configure(name string, mtu int, addresses, routes []string) error {
	for _, a := range addresses {
		if err := ip("address", "add", a, "dev", name); err != nil {
			return err
		}
	}
	if err := ip("link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	for _, r := range routes {
		fam := "-4"
		if strings.Contains(r, ":") {
			fam = "-6"
		}
		if err := ip(fam, "route", "replace", r, "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), bytes.TrimSpace(out))
	}
	return nil
}
