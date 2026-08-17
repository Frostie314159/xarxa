#!/bin/bash

set -euo pipefail

# Warnings are errors: the feature combinations below are also checked for dead
# code, which is what tells us a `#[cfg]` is missing somewhere.
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"

# Every combination of the media / protocol / socket features is built. The
# media and protocol axes need at least one feature each (the crate root says so
# with a `compile_error!`); the socket axis may be empty.
MEDIA=("medium-ethernet" "medium-ip" "medium-ethernet,medium-ip")
PROTOS=("proto-ipv4" "proto-ipv6" "proto-ipv4,proto-ipv6")
SOCKETS=(
  ""
  "socket-raw"
  "socket-udp"
  "socket-tcp"
  "socket-raw,socket-udp"
  "socket-raw,socket-tcp"
  "socket-udp,socket-tcp"
  "socket-raw,socket-udp,socket-tcp"
)

# The other axes are checked against the full feature set only; combining them
# with all of the above would be thousands of builds for no extra coverage.
for extra in "" "defmt" "log" "std" "std,log" "std,defmt" "async" "std,log,async" \
             "icmp-error-handling" "auto-icmp-echo-reply" "async,icmp-error-handling" \
             "std,log,async,icmp-error-handling,auto-icmp-echo-reply"; do
  cargo check --no-default-features \
    --features "medium-ethernet,medium-ip,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp${extra:+,$extra}"
done

for medium in "${MEDIA[@]}"; do
  for proto in "${PROTOS[@]}"; do
    for socket in "${SOCKETS[@]}"; do
      features="$medium,$proto${socket:+,$socket}"
      # Bare, and with everything that adds code paths to the combination.
      cargo check --no-default-features --features "$features"
      cargo check --no-default-features \
        --features "$features,std,log,async,icmp-error-handling,auto-icmp-echo-reply"
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
cargo build --examples
