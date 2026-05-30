# The Nocturne Protocol, version 1

Nocturne is a layer 3 tunnel over UDP. Two peers that know each other's
static public key establish a session in one round trip and then exchange
encrypted IP packets. This document describes the wire format and the
rules every implementation must follow.

Status: **experimental and unaudited.** See [Limitations](#9-limitations).

## 1. Goals

- **Small.** One handshake pattern, one cipher suite, no negotiation, no
  options. There is nothing to downgrade.
- **Silent.** A host that does not know a server's public key cannot make
  it send a single byte.
- **Forward secret, including against future quantum computers.** Session
  keys come from ephemeral X25519 *and* ephemeral ML-KEM-768. Recording
  traffic today and breaking X25519 later does not reveal it.
- **Roaming.** Sessions are bound to keys, not to IP addresses.

Nocturne shares no code and no wire format with any other VPN. It is built
only from standard, published primitives; no new cryptography is invented.

## 2. Primitives

| Purpose | Primitive |
|---|---|
| Key agreement | X25519 (RFC 7748) |
| Post-quantum key encapsulation | ML-KEM-768 (FIPS 203) |
| Authenticated encryption | ChaCha20-Poly1305 (RFC 8439) |
| Cookie encryption | XChaCha20-Poly1305 |
| Hash | BLAKE2s-256 (RFC 7693) |
| MAC | keyed BLAKE2s-128 |
| Key derivation | HKDF (RFC 5869) over BLAKE2s-256 |

Notation:

- `H(a, b, ...)` is BLAKE2s-256 of the concatenation.
- `MAC(key, a, ...)` is keyed BLAKE2s with a 16 byte output.
- `DH(priv, pub)` is X25519. An all-zero result aborts the handshake.
- `SEAL(k, n, pt, ad)` is ChaCha20-Poly1305 with a 96-bit nonce made of
  four zero bytes followed by `n` as a little-endian 64-bit integer.
- `MIX(ck, ikm)` computes `HKDF(salt = ck, ikm, info = "nocturne v1 mix")`
  to 64 bytes; the first 32 replace `ck`, the last 32 are returned as a key.

All integers on the wire are little-endian except the handshake timestamp,
which is big-endian.

## 3. Identities

Each peer has a static X25519 key pair. Public keys are exchanged out of
band. A pair of peers may also share a 32 byte preshared key (PSK); when
unused it is 32 zero bytes.

## 4. Messages

The first byte of every datagram is its type. Bytes 1 to 3 are reserved
and must be zero.

### 4.1 Init (type 1, 1328 bytes), initiator to responder

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | type and reserved |
| 4 | 4 | sender index |
| 8 | 32 | initiator ephemeral X25519 public key `Ei` |
| 40 | 48 | sealed initiator static public key |
| 88 | 1208 | sealed payload: timestamp (8) and ML-KEM-768 encapsulation key (1184) |
| 1296 | 16 | mac1 |
| 1312 | 16 | mac2 |

Construction, with `Sr` the responder's static public key and
`(si, Si)` the initiator's static key pair:

```
ck = H("Nocturne v1 :: X25519+ML-KEM-768 / ChaCha20-Poly1305 / BLAKE2s")
h  = H(ck, Sr)
h  = H(h, msg[0:40])                       # header and Ei
k  = MIX(ck, DH(ei, Sr))
msg[40:88]   = SEAL(k, 0, Si, h);                  h = H(h, msg[40:88])
k  = MIX(ck, DH(si, Sr))
msg[88:1296] = SEAL(k, 0, timestamp || kem_ek, h); h = H(h, msg[88:1296])
mac1 = MAC(H("nocturne v1 gate", Sr), msg[0:1296])
mac2 = MAC(cookie, msg[0:1312])            # zero if no cookie is held
```

`timestamp` is nanoseconds since the Unix epoch. `kem_ek` is a fresh
ML-KEM-768 encapsulation key generated for this handshake only.

### 4.2 Response (type 2, 1148 bytes), responder to initiator

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | type and reserved |
| 4 | 4 | sender index |
| 8 | 4 | receiver index (the Init's sender index) |
| 12 | 32 | responder ephemeral X25519 public key `Er` |
| 44 | 1088 | ML-KEM-768 ciphertext |
| 1132 | 16 | confirmation tag |

Continuing from the state after the Init:

```
h = H(h, msg[0:44])                        # header and Er
MIX(ck, DH(er, Ei))
MIX(ck, DH(er, Si))
(pq, ct) = ML-KEM-768.Encapsulate(kem_ek)
h = H(h, ct)
MIX(ck, pq)
k = MIX(ck, psk)
msg[1132:1148] = SEAL(k, 0, "", h)
```

### 4.3 Transport keys

Both sides then derive

```
k_i2r || k_r2i = HKDF(salt = ck, ikm = h, info = "nocturne v1 transport", 64 bytes)
```

The initiator sends with `k_i2r`; the responder sends with `k_r2i`.
`ck`, the ephemeral private keys and the ML-KEM decapsulation key are
erased.

### 4.4 Data (type 3), either direction

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | type and reserved |
| 4 | 4 | receiver index |
| 8 | 8 | counter |
| 16 | n + 16 | `SEAL(k, counter, packet, msg[0:16])` |

The 16 byte header is authenticated as associated data. `packet` is one
IPv4 or IPv6 packet, zero-padded to a multiple of 16 bytes (but never
beyond the tunnel MTU). The receiver recovers the true length from the IP
header. An empty `packet` is a keepalive.

Counters start at 0 and increase by one per packet. A sender must stop
using a session before the counter reaches 2^60.

### 4.5 Cookie reply (type 4, 64 bytes), responder to initiator

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | type and reserved |
| 4 | 4 | receiver index (the Init's sender index) |
| 8 | 24 | random nonce |
| 32 | 32 | XChaCha20-Poly1305 of the cookie, keyed with `H("nocturne v1 cookie", Sr)`, with the Init's mac1 as associated data |

The cookie is `MAC(secret, source IP || source port)` where `secret` is a
random value the responder replaces every two minutes.

