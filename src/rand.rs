//! Small non-cryptographic PRNG.
//!
//! This is used for:
//! - Source ports for TCP and UDP.
//! - TCP initial sequence numbers.

// In test builds the TCP initial sequence number is a fixed value, and without
// sockets nothing needs random numbers at all, leaving the PRNG unused.
#![cfg_attr(
    any(test, not(any(feature = "socket-udp", feature = "socket-tcp"))),
    allow(dead_code)
)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub(crate) struct Rand {
    state: u64,
}

impl Rand {
    pub(crate) const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn rand_u32(&mut self) -> u32 {
        // sPCG32 from https://www.pcg-random.org/paper.html
        // see also https://nullprogram.com/blog/2017/09/21/
        const M: u64 = 0xbb2efcec3c39611d;
        const A: u64 = 0x7590ef39;

        let s = self.state.wrapping_mul(M).wrapping_add(A);
        self.state = s;

        let shift = 29 - (s >> 61);
        (s >> shift) as u32
    }
}
