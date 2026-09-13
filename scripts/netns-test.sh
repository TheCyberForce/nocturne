#!/usr/bin/env bash
# End-to-end test: two network namespaces joined by a veth pair, a real
# Nocturne tunnel between them, and traffic through it.
#
#   sudo scripts/netns-test.sh           # as root
#   unshare -Urnm scripts/netns-test.sh  # unprivileged, in a user namespace
set -euo pipefail

cd "$(dirname "$0")/.."
NOC="$PWD/bin/noc"
[ -x "$NOC" ] || { echo "build first: go build -o bin/noc ./cmd/noc" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root or under: unshare -Urnm" >&2; exit 1; }

WORK=$(mktemp -d)
export NOCTURNE_RUNDIR="$WORK/run"
PIDS=()
cleanup() {
	kill "${PIDS[@]}" 2>/dev/null || true
	wait 2>/dev/null || true
	ip netns del noc-a 2>/dev/null || true
	ip netns del noc-b 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

# In a fresh user namespace /run is not ours to write; give ip-netns its own.
if ! mkdir -p /run/netns 2>/dev/null || ! [ -w /run/netns ]; then
	mount -t tmpfs tmpfs /run
fi

step() { printf '\n== %s\n' "$*"; }
A() { ip netns exec noc-a "$@"; }
B() { ip netns exec noc-b "$@"; }

step "building the underlay: noc-a 192.168.50.1 <-> noc-b 192.168.50.2"
ip netns add noc-a
ip netns add noc-b
ip link add veth-a netns noc-a type veth peer name veth-b netns noc-b
A ip addr add 192.168.50.1/24 dev veth-a; A ip link set veth-a up; A ip link set lo up
B ip addr add 192.168.50.2/24 dev veth-b; B ip link set veth-b up; B ip link set lo up

step "generating keys"
KA=$("$NOC" keygen); PA=$(echo "$KA" | "$NOC" pubkey)
KB=$("$NOC" keygen); PB=$(echo "$KB" | "$NOC" pubkey)
PSK=$("$NOC" psk)
umask 077
cat > "$WORK/noca.conf" <<EOF
[tunnel]
private_key = $KA
address = 10.77.0.1/24, fd77::1/64
[peer]
public_key = $PB
preshared_key = $PSK
endpoint = 192.168.50.2:51900
allowed_ips = 10.77.0.2/32, fd77::2/128
EOF
cat > "$WORK/nocb.conf" <<EOF
[tunnel]
private_key = $KB
address = 10.77.0.2/24, fd77::2/64
listen = 51900
[peer]
public_key = $PA
preshared_key = $PSK
allowed_ips = 10.77.0.1/32, fd77::1/128
EOF

step "bringing both ends up"
# Not via the A/B helpers: $! must be the tunnel's own pid for cleanup.
ip netns exec noc-b "$NOC" up "$WORK/nocb.conf" 2>"$WORK/b.log" & PIDS+=($!)
ip netns exec noc-a "$NOC" up "$WORK/noca.conf" 2>"$WORK/a.log" & PIDS+=($!)
for _ in $(seq 50); do
	[ -S "$NOCTURNE_RUNDIR/noca.sock" ] && [ -S "$NOCTURNE_RUNDIR/nocb.sock" ] && break
	sleep 0.1
done
[ -S "$NOCTURNE_RUNDIR/noca.sock" ] || { cat "$WORK/a.log" "$WORK/b.log"; exit 1; }

step "IPv4 through the tunnel"
A ping -c 3 -i 0.2 -W 2 10.77.0.2
step "IPv6 through the tunnel"
A ping -6 -c 3 -i 0.2 -W 2 fd77::2
step "large packets (fragmented inside the tunnel)"
A ping -c 2 -i 0.2 -W 2 -s 4000 10.77.0.2
step "reverse direction"
B ping -c 2 -i 0.2 -W 2 10.77.0.1

step "nothing crosses the underlay in the clear"
if command -v tcpdump >/dev/null; then
	# Ping payloads filled with a known pattern must not show up on the wire.
	A tcpdump -i veth-a -U -w "$WORK/cap.pcap" 2>/dev/null & CAP=$!
	sleep 1
	A ping -c 3 -i 0.2 -W 2 -p 6e6f637475726e65 10.77.0.2 >/dev/null
	sleep 1
	kill "$CAP"; wait "$CAP" 2>/dev/null || true
	[ -s "$WORK/cap.pcap" ] || { echo "FAIL: capture is empty"; exit 1; }
	if grep -qa "nocturnenocturne" "$WORK/cap.pcap"; then
		echo "FAIL: plaintext found on the underlay"; exit 1
	fi
	echo "ok: pattern not visible in $(stat -c %s "$WORK/cap.pcap") captured bytes"
else
	echo "skipped: tcpdump not installed"
fi

step "status"
"$NOC" status
"$NOC" status nocb | grep -q "session:     [0-9]" || { echo "FAIL: no session on b"; exit 1; }

step "noc down"
"$NOC" down noca
sleep 0.5
if A ip link show noca 2>/dev/null; then echo "FAIL: interface survived"; exit 1; fi
echo "ok: interface removed"

printf '\nALL END-TO-END CHECKS PASSED\n'
