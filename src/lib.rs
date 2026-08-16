#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

// Must go first so other modules see its macros.
#[macro_use]
mod fmt;

#[macro_use]
mod macros;

pub mod buf;
pub mod iface;
pub mod neighbor;
mod rand;
pub mod raw;
pub mod route;
mod slab;
pub mod stack;
pub mod tcp;
pub mod time;
pub mod udp;
#[cfg(feature = "async")]
mod waker;
pub mod wire;

pub use buf::{PACKET_BUF_SIZE, PacketBuf};
pub use raw::{RawHandle, RawMode, RawSocket};
pub use route::{Route, Routes};
pub use stack::{Config, IfaceHandle, Stack};
pub use tcp::{TcpHandle, TcpListener, TcpListenerHandle, TcpSocket};
pub use udp::{UdpHandle, UdpSocket};
