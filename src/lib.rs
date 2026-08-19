#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

#[cfg(not(any(feature = "medium-ethernet", feature = "medium-ip")))]
compile_error!("You must enable at least one of the following features: medium-ethernet, medium-ip");

#[cfg(not(any(feature = "proto-ipv4", feature = "proto-ipv6")))]
compile_error!("You must enable at least one of the following features: proto-ipv4, proto-ipv6");

#[cfg(all(feature = "socket-tcp-reno", feature = "socket-tcp-cubic"))]
compile_error!("The features socket-tcp-reno and socket-tcp-cubic are mutually exclusive.");

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
#[cfg(feature = "socket-raw")]
pub mod raw;
pub mod route;
mod slab;
pub mod stack;
#[cfg(feature = "socket-tcp")]
pub mod tcp;
pub mod time;
#[cfg(feature = "socket-udp")]
pub mod udp;
#[cfg(all(feature = "async", feature = "socket"))]
mod waker;
pub mod wire;

pub use buf::{PACKET_BUF_SIZE, PacketBuf};
#[cfg(feature = "icmp-error-handling")]
pub use icmp_error::IcmpError;
pub use meta::PacketMeta;
#[cfg(feature = "packetmeta-timestamp")]
pub use meta::{Timestamp, TxTimestamp};
#[cfg(feature = "socket-raw")]
pub use raw::{RawHandle, RawMode, RawSocket};
pub use route::{Route, Routes};
#[cfg(feature = "socket-raw")]
pub use stack::RawSocketIter;
#[cfg(feature = "socket-udp")]
pub use stack::UdpSocketIter;
pub use stack::{Iface, IfaceHandle, IfaceIter, Stack};
#[cfg(feature = "socket-tcp")]
pub use stack::{TcpListenerIter, TcpSocketIter};
#[cfg(feature = "socket-tcp")]
pub use tcp::{TcpHandle, TcpListener, TcpListenerHandle, TcpSocket};
#[cfg(feature = "socket-udp")]
pub use udp::{UdpHandle, UdpSocket};
