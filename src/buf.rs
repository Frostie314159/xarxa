//! Owned packet buffers.
//!
//! Every packet in the stack is a [`PacketBuf`]: one fixed-size buffer, owned by
//! whoever holds it (the driver, the stack, a socket, the application).
//!
//! Buffers are allocated from a static pool. The buffer type and the pool live
//! in the `xarxa-driver` crate (re-exported as [`crate::driver`]), so that
//! driver crates depend on it alone; this module re-exports them.

pub use crate::driver::{PACKET_BUF_ALIGN, PACKET_BUF_SIZE, PacketBuf};
