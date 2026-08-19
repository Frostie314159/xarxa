#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![doc = include_str!("../README.md")]
//!
//! ## Feature flags
#![doc = document_features::document_features!(feature_label = r#"<span class="stab portability"><code>{feature}</code></span>"#)]

extern crate alloc;

#[cfg(not(any(feature = "medium-ethernet", feature = "medium-ip")))]
compile_error!("You must enable at least one of the following features: medium-ethernet, medium-ip");

#[cfg(not(any(feature = "ipv4", feature = "ipv6")))]
compile_error!("You must enable at least one of the following features: ipv4, ipv6");

#[cfg(all(feature = "tcp-reno", feature = "tcp-cubic"))]
compile_error!("The features tcp-reno and tcp-cubic are mutually exclusive.");

// Must go first so other modules see its macros.
#[macro_use]
mod fmt;

#[macro_use]
mod macros;

pub mod buf;
#[cfg(feature = "icmp-error-handling")]
mod icmp_error;
pub mod iface;
pub mod meta;
#[cfg(feature = "medium-ethernet")]
pub mod neighbor;
mod rand;
#[cfg(feature = "raw")]
pub mod raw;
pub mod route;
mod slab;
pub mod stack;
#[cfg(feature = "tcp")]
pub mod tcp;
pub mod time;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "async")]
mod waker;
pub mod wire;

pub use buf::{PACKET_BUF_SIZE, PacketBuf};
#[cfg(feature = "icmp-error-handling")]
pub use icmp_error::IcmpError;
pub use meta::PacketMeta;
#[cfg(feature = "packetmeta-timestamp")]
pub use meta::{Timestamp, TxTimestamp};
#[cfg(feature = "raw")]
pub use raw::{RawHandle, RawMode, RawSocket};
pub use route::{Route, Routes};
#[cfg(feature = "raw")]
pub use stack::RawSocketIter;
#[cfg(feature = "tcp-listener")]
pub use stack::TcpListenerIter;
#[cfg(feature = "tcp")]
pub use stack::TcpSocketIter;
#[cfg(feature = "udp")]
pub use stack::UdpSocketIter;
pub use stack::{Iface, IfaceHandle, IfaceIter, Stack};
#[cfg(feature = "tcp")]
pub use tcp::{TcpHandle, TcpSocket};
#[cfg(feature = "tcp-listener")]
pub use tcp::{TcpListener, TcpListenerHandle};
#[cfg(feature = "udp")]
pub use udp::{UdpHandle, UdpSocket};
