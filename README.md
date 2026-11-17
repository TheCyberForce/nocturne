<p align="center">
  <img src="assets/logo.svg" width="520" alt="Nocturne: move in silence">
</p>

# Nocturne

A small, quiet VPN with its own protocol.

- **One round trip** to connect, mutual authentication by public key.
- **Hybrid post-quantum** key exchange: X25519 + ML-KEM-768.
- **Silent**: without your public key, nobody can make a Nocturne server answer.
- **Roams** across networks without reconnecting.
- **Small**: about 1,800 lines of Go, one dependency, one static binary.

> **Experimental.** Nocturne is a new protocol that has not been audited.
> Use it to learn and experiment, not to protect anything important.
> The full protocol is described in [SPEC.md](SPEC.md).

## Build

Needs Go 1.26 or newer and Linux.

```sh
go build -o bin/noc ./cmd/noc
```

## Quick start

On each machine:

```sh
noc keygen > private.key
noc pubkey < private.key
```

Server, `/etc/nocturne/noc0.conf`:

```ini
[tunnel]
private_key = <server private key>
address     = 10.77.0.1/24
listen      = 51900

[peer]
public_key  = <client public key>
allowed_ips = 10.77.0.2/32
```

Client, `/etc/nocturne/noc0.conf`:

```ini
[tunnel]
private_key = <client private key>
address     = 10.77.0.2/24

[peer]
public_key  = <server public key>
endpoint    = vpn.example.com:51900
allowed_ips = 10.77.0.0/24
keepalive   = 25
```

Then, as root on both:

```sh
noc up /etc/nocturne/noc0.conf
```

The interface is named after the file (`noc0`). `noc status` shows
sessions and traffic; `noc down noc0` or Ctrl-C stops the tunnel.

## Configuration reference

`[tunnel]`

| Key | Meaning |
|---|---|
| `private_key` | This machine's key, from `noc keygen`. Required. |
| `address` | Address(es) of the tunnel interface, comma separated. Required. |
| `listen` | UDP port, or `ip:port`. Default: a random port. |
| `mtu` | Default 1420. |
| `name` | Interface name. Default: the file name. |

`[peer]` (repeatable)

| Key | Meaning |
|---|---|
| `public_key` | The peer's public key. Required. |
| `allowed_ips` | Prefixes routed to this peer, and the only source addresses accepted from it. |
| `endpoint` | `host:port` to reach the peer. Omit on servers. |
| `preshared_key` | Optional extra symmetric key, from `noc psk`. Must match on both sides. |
| `keepalive` | Seconds between keepalives. Use 25 behind NAT. |

## Testing

```sh
go test ./...                          # protocol and engine tests
unshare -Urnm scripts/netns-test.sh    # a real tunnel between two network namespaces
```

## Not yet supported

- Routing all traffic through the tunnel (`0.0.0.0/0`).
- Operating systems other than Linux.
- Changing peers without restarting the tunnel.

## License

Free for everyone to use, modify and share, under the [MIT License](LICENSE.md).
