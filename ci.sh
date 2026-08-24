#!/bin/bash

set -euo pipefail

# Warnings are errors: the feature combinations below are also checked for dead
# code, which is what tells us a `#[cfg]` is missing somewhere.
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"

# Print each cargo command before running it, so a failing step can be
# reproduced by pasting the line. The RUSTFLAGS export is included because it is
# part of what makes the step pass or fail.
run() {
  echo "RUSTFLAGS='$RUSTFLAGS' $*"
  "$@"
}

# Every combination of the media / protocol / socket features is built. The
# media and protocol axes need at least one feature each (the crate root says so
# with a `compile_error!`); the socket axis may be empty.
MEDIA=("medium-ethernet" "medium-ip" "medium-ieee802154" "medium-ethernet,medium-ip" "medium-ethernet,medium-ip,medium-ieee802154")
PROTOS=("ipv4" "ipv6" "ipv4,ipv6")
SOCKETS=(
  ""
  "raw"
  "udp"
  "tcp"
  "raw,udp"
  "raw,tcp"
  "udp,tcp"
  "raw,udp,tcp"
)

# The other axes are checked against the full feature set only; combining them
# with all of the above would be thousands of builds for no extra coverage.
for alloc in "" "alloc"; do
for extra in "" "defmt" "log" "std" "std,log" "std,defmt" "async" "std,log,async" \
             "icmp-errors" "icmp-ping-reply" "async,icmp-errors" \
             "packetmeta-id" "packetmeta-timestamp" "packetmeta-timestamp,defmt" \
             "tcp-timestamps" "tcp-timestamps,defmt" \
             "tcp-reno" "tcp-cubic" \
             "ipv4-fragmentation" "ipv4-reassembly" "ipv4-fragmentation,ipv4-reassembly,defmt" \
             "medium-ieee802154" "sixlowpan-fragmentation" "sixlowpan-reassembly" \
             "sixlowpan-fragmentation,sixlowpan-reassembly,defmt" \
             "dhcpv4" "dhcpv4,async" "dhcpv4,defmt" "dhcpv4-options" "dhcpv4-options,defmt" \
             "multicast" "multicast,defmt" "multicast,icmp-errors,icmp-ping-reply" \
             "std,log,async,icmp-errors,icmp-ping-reply,packetmeta-timestamp,tcp-timestamps,packet-log,dhcpv4,dhcpv4-options,multicast,ipv4-fragmentation,ipv4-reassembly,medium-ieee802154,sixlowpan-fragmentation,sixlowpan-reassembly,slaac"; do
  run cargo check --no-default-features \
    --features "medium-ethernet,medium-ip,ipv4,ipv6,raw,udp,tcp${extra:+,$extra}${alloc:+,$alloc}"
done
done

for medium in "${MEDIA[@]}"; do
  for proto in "${PROTOS[@]}"; do
    for socket in "${SOCKETS[@]}"; do
      features="$medium,$proto${socket:+,$socket}"
      # Bare, and with everything that adds code paths to the combination.
      for alloc in "" "alloc"; do
        run cargo check --no-default-features --features "$features${alloc:+,$alloc}"
        run cargo check --no-default-features \
          --features "$features,std,log,async,icmp-errors,icmp-ping-reply,packetmeta-timestamp,multicast${alloc:+,$alloc}"
      done
    done
  done
done

# Tests. Everything testable is hosted (`std`) and logs through `log`, so the
# `no_std` and `defmt` builds above are check-only. Unit tests are run for every
# combination; the doc tests and the examples are built against the default
# feature set only, since they are written against the whole API.
for medium in "${MEDIA[@]}"; do
  for proto in "${PROTOS[@]}"; do
    for socket in "${SOCKETS[@]}"; do
      run cargo test --lib --no-default-features \
        --features "alloc,$medium,$proto${socket:+,$socket},std,log,async,icmp-errors,icmp-ping-reply,multicast"
    done
  done
done

run cargo test
# Once more without `alloc`: the bounded containers and their full-table paths.
# Unit tests only: the examples and doc tests are written against the owned
# `Box`/`Vec` storage that only exists with `alloc`.
run cargo test --lib --no-default-features \
  --features "medium-ethernet,medium-ip,medium-ieee802154,ipv4,ipv6,raw,udp,tcp,tcp-listener,std,log,async,icmp-errors,icmp-ping-reply,multicast,slaac,dhcpv4,dhcpv4-options,dns,mdns,packetmeta-timestamp,tcp-timestamps,ipv4-fragmentation,ipv4-reassembly,sixlowpan-fragmentation,sixlowpan-reassembly"
# Once more with packet metadata: the default feature set leaves `PacketMeta`
# zero-sized, so the tests that exercise it are gated on the feature.
run cargo test --features packetmeta-timestamp
# Once more with TCP timestamps: without the feature no segment carries the
# option, so the tests that expect one are gated on it.
run cargo test --features tcp-timestamps
# Once more with Reno congestion control: the default set has CUBIC, and the
# two are mutually exclusive, so this is the default set with one swapped for
# the other. (Without either feature TCP does no congestion control at all, and
# the tests that exercise a congestion window are gated on `tcp-reno`.)
run cargo test --no-default-features \
  --features "alloc,std,log,async,icmp-ping-reply,icmp-errors,medium-ethernet,medium-ip,medium-ieee802154,ipv4,ipv6,raw,udp,tcp,tcp-listener,dhcpv4,dhcpv4-options,slaac,dns,mdns,multicast,tcp-reno,tcp-timestamps,packetmeta-timestamp,ipv4-fragmentation,ipv4-reassembly,sixlowpan-fragmentation,sixlowpan-reassembly"
run cargo build --examples
