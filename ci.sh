#!/bin/bash

set -euxo pipefail

cargo check --no-default-features
cargo check --no-default-features --features defmt
cargo check --no-default-features --features log
cargo check --no-default-features --features std
cargo check --no-default-features --features std,log
cargo check --no-default-features --features std,defmt
cargo check --no-default-features --features async
cargo check --no-default-features --features std,log,async
