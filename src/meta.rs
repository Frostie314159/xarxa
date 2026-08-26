//! Per-packet metadata.
//!
//! A [`PacketMeta`] is a small set of attributes that travels together with a packet
//! all the way through the stack. It lives in the `xarxa-driver` crate (re-exported
//! as [`crate::driver`]), so that driver crates depend on it alone; this module
//! re-exports it.

pub use crate::driver::PacketMeta;
#[cfg(feature = "packetmeta-timestamp")]
pub use crate::driver::{Timestamp, TxTimestamp};
