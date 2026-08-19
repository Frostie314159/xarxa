#!/bin/bash

set -euo pipefail

# Warnings are errors: the feature combinations below are also checked for dead
# code, which is what tells us a `#[cfg]` is missing somewhere.
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"

# Every combination of the media / protocol / socket features is built. The
# media and protocol axes need at least one feature each (the crate root says so
# with a `compile_error!`); the socket axis may be empty.
MEDIA=("medium-ethernet" "medium-ip" "medium-ethernet,medium-ip")
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
for extra in "" "defmt" "log" "std" "std,log" "std,defmt" "async" "std,log,async" \
             "icmp-error-handling" "auto-icmp-echo-reply" "async,icmp-error-handling" \
             "packetmeta-id" "packetmeta-timestamp" "packetmeta-timestamp,defmt" \
             "tcp-timestamps" "tcp-timestamps,defmt" \
             "tcp-reno" "tcp-cubic" \
             "std,log,async,icmp-error-handling,auto-icmp-echo-reply,packetmeta-timestamp,tcp-timestamps"; do
  cargo check --no-default-features \
    --features "medium-ethernet,medium-ip,ipv4,ipv6,raw,udp,tcp${extra:+,$extra}"
done

for medium in "${MEDIA[@]}"; do
  for proto in "${PROTOS[@]}"; do
    for socket in "${SOCKETS[@]}"; do
      features="$medium,$proto${socket:+,$socket}"
      # Bare, and with everything that adds code paths to the combination.
      cargo check --no-default-features --features "$features"
      cargo check --no-default-features \
        --features "$features,std,log,async,icmp-error-handling,auto-icmp-echo-reply,packetmeta-timestamp"
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
      cargo test --lib --no-default-features \
        --features "$medium,$proto${socket:+,$socket},std,log,async,icmp-error-handling,auto-icmp-echo-reply"
    done
  done
done

cargo test
# Once more with packet metadata: the default feature set leaves `PacketMeta`
# zero-sized, so the tests that exercise it are gated on the feature.
cargo test --features packetmeta-timestamp
# Once more with TCP timestamps: without the feature no segment carries the
# option, so the tests that expect one are gated on it.
cargo test --features tcp-timestamps
# Once more with each congestion control algorithm: without either feature TCP
# does no congestion control, so the tests that exercise a congestion window are
# gated on `tcp-reno`.
cargo test --features tcp-reno
cargo test --features tcp-cubic
cargo build --examples
