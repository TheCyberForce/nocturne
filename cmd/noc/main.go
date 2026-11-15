// noc is the Nocturne command line tool.
package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Dr33kos/nocturne/internal/config"
	"github.com/Dr33kos/nocturne/internal/device"
	"github.com/Dr33kos/nocturne/internal/proto"
	"github.com/Dr33kos/nocturne/internal/tun"
)

const version = "0.4.0"

const banner = `
      _..._        N O C T U R N E
    .'  .-'
   /   /           move in silence.
   |   |
   \   \           v%s
    '.  '-._
      '-...-'
`

const usage = `usage:
  noc keygen            print a new private key
  noc pubkey            read a private key on stdin, print its public key
  noc psk               print a new preshared key
  noc up <tunnel.conf>  bring a tunnel up (runs in the foreground)
  noc status [name]     show running tunnels
  noc down <name>       stop a running tunnel
  noc version
`

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, banner+"\n"+usage, version)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; {
	case cmd == "keygen" && len(args) == 0:
		err = keygen()
	case cmd == "pubkey" && len(args) == 0:
		err = pubkey()
	case cmd == "psk" && len(args) == 0:
		var k [proto.KeySize]byte
		if _, err = rand.Read(k[:]); err == nil {
			fmt.Println(device.EncodeKey(k))
		}
	case cmd == "up" && len(args) == 1:
		err = up(args[0])
	case cmd == "status" && len(args) <= 1:
		err = status(args)
	case cmd == "down" && len(args) == 1:
		_, err = control(args[0], "down")
	case cmd == "version":
		fmt.Printf("nocturne %s (protocol v1)\n", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("noc: %v", err)
	}
}

func keygen() error {
	k, err := proto.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(device.EncodeKey([proto.KeySize]byte(k.Bytes())))
	return nil
}

func pubkey() error {
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	raw, err := device.DecodeKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	k, err := proto.ParsePrivateKey(raw[:])
	if err != nil {
		return err
	}
	fmt.Println(device.EncodeKey(proto.PublicOf(k)))
	return nil
}

func up(path string) error {
	t, err := config.Load(path)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(t.Listen))
	if err != nil {
		return err
	}
	tf, err := tun.Open(t.Name)
	if err != nil {
		conn.Close()
		return err
	}
	t.Device.Logf = log.Printf
	dev, err := device.New(tf, conn, t.Device)
	if err != nil {
		tf.Close()
		conn.Close()
		return err
	}
	defer dev.Close()

	addrs := make([]string, len(t.Addresses))
	for i, a := range t.Addresses {
		addrs[i] = a.String()
	}
	if err := tun.Configure(t.Name, t.Device.MTU, addrs, t.Routes()); err != nil {
		return err
	}
	dev.Start()

	stop := make(chan struct{}, 1)
	if ln, err := listenControl(t.Name); err != nil {
		log.Printf("warning: status/down unavailable: %v", err)
	} else {
		defer os.Remove(ln.Addr().String())
		defer ln.Close()
		go serveControl(ln, dev, stop)
	}

	fmt.Fprintf(os.Stderr, banner, version)
	log.Printf("%s is up on %v, %d peer(s)", t.Name, conn.LocalAddr(), len(t.Device.Peers))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case <-stop:
	case <-dev.Done():
		return fmt.Errorf("%s stopped unexpectedly", t.Name)
	}
	log.Printf("%s is down", t.Name)
	return nil
}

// The control socket is a root-only unix socket speaking one line per
// request: "status" or "down".

func runDir() string {
	if d := os.Getenv("NOCTURNE_RUNDIR"); d != "" {
		return d
	}
	return "/run/nocturne"
}

func listenControl(name string) (net.Listener, error) {
	if err := os.MkdirAll(runDir(), 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(runDir(), name+".sock")
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("tunnel %s is already running", name)
	}
	os.Remove(path) // stale socket from a crashed process
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}

func serveControl(ln net.Listener, dev *device.Device, stop chan<- struct{}) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(io.LimitReader(c, 64)).ReadString('\n')
		switch strings.TrimSpace(line) {
		case "status":
			io.WriteString(c, dev.Status())
		case "down":
			io.WriteString(c, "ok\n")
			select {
			case stop <- struct{}{}:
			default:
			}
		}
		c.Close()
	}
}

func control(name, cmd string) (string, error) {
	c, err := net.DialTimeout("unix", filepath.Join(runDir(), name+".sock"), 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("tunnel %s is not running (or you are not root)", name)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, cmd+"\n"); err != nil {
		return "", err
	}
	out, err := io.ReadAll(c)
	return string(out), err
}

func status(args []string) error {
	names := args
	if len(names) == 0 {
		socks, _ := filepath.Glob(filepath.Join(runDir(), "*.sock"))
		for _, s := range socks {
			names = append(names, strings.TrimSuffix(filepath.Base(s), ".sock"))
		}
		if len(names) == 0 {
			fmt.Println("no tunnels are running")
			return nil
		}
	}
	for i, n := range names {
		out, err := control(n, "status")
		if err != nil {
			return err
		}
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("tunnel %s\n%s", n, out)
	}
	return nil
}
