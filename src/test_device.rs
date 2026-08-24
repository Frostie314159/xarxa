//! The mock [`Interface`] the tests drive the stack with.
//!
//! One device covers every test: it hands the stack the frames pushed into its
//! receive queue, records the ones it transmits, refuses to transmit when asked
//! to, and carries packet metadata in both directions. Everything a test looks
//! at is behind an `Rc`, so the handles stay usable after the device is given to
//! a stack.
//!
//! This file is compiled into the library's own unit tests and `#[path]`-included
//! by the integration tests, so it is written against the public API only.

#![allow(dead_code)]

use std::boxed::Box;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use xarxa::PacketBuf;
use xarxa::iface::{IfaceCapabilities, Interface, Medium};
#[cfg(feature = "packetmeta-id")]
use xarxa::meta::PacketMeta;
#[cfg(feature = "packetmeta-timestamp")]
use xarxa::meta::{Timestamp, TxTimestamp};
use xarxa::stack::{IfaceHandle, Stack};
use xarxa::wire::HardwareAddress;

/// Frames waiting to be received, oldest first.
pub type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Frames transmitted so far, oldest first.
pub type Sent = Rc<RefCell<Vec<Vec<u8>>>>;

/// The metadata of the transmitted frames, oldest first.
#[cfg(feature = "packetmeta-id")]
pub type SentMeta = Rc<RefCell<Vec<PacketMeta>>>;

/// How many more frames the device accepts. `None` is unlimited.
pub type Room = Rc<Cell<Option<usize>>>;

/// A mock network device.
///
/// Build one with [`TestDevice::new`] plus the `with_*` setters, then give it to
/// a stack with [`TestDevice::install`]. The configuration is read at install
/// time; the queues are shared, so keep the device around and read `rx`, `tx`,
/// `tx_meta` and `room` through it.
#[derive(Clone)]
pub struct TestDevice {
    /// The medium it reports.
    pub medium: Medium,
    /// The MTU it reports.
    pub mtu: usize,
    /// Frames to hand to the stack, oldest first.
    pub rx: Queue,
    /// Frames the stack transmitted, oldest first.
    pub tx: Sent,
    /// The metadata of those frames.
    #[cfg(feature = "packetmeta-id")]
    pub tx_meta: SentMeta,
    /// How many more frames it accepts.
    pub room: Room,
    /// Metadata stamped onto every received packet.
    #[cfg(feature = "packetmeta-id")]
    pub rx_meta: PacketMeta,
    /// Reported as the transmit timestamp of packets that ask for one.
    #[cfg(feature = "packetmeta-timestamp")]
    tx_stamp: Option<Timestamp>,
    /// Transmit timestamps not yet polled.
    #[cfg(feature = "packetmeta-timestamp")]
    tx_stamps: VecDeque<TxTimestamp>,
}

impl TestDevice {
    /// A device of the given medium, with a 1500-byte MTU and unlimited
    /// transmit room, receiving nothing.
    pub fn new(medium: Medium) -> Self {
        Self {
            medium,
            mtu: 1500,
            rx: Rc::new(RefCell::new(VecDeque::new())),
            tx: Rc::new(RefCell::new(Vec::new())),
            #[cfg(feature = "packetmeta-id")]
            tx_meta: Rc::new(RefCell::new(Vec::new())),
            room: Rc::new(Cell::new(None)),
            #[cfg(feature = "packetmeta-id")]
            rx_meta: PacketMeta::default(),
            #[cfg(feature = "packetmeta-timestamp")]
            tx_stamp: None,
            #[cfg(feature = "packetmeta-timestamp")]
            tx_stamps: VecDeque::new(),
        }
    }

    /// Sets the MTU it reports.
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Stamps every received packet with this metadata.
    #[cfg(feature = "packetmeta-id")]
    pub fn with_rx_meta(mut self, meta: PacketMeta) -> Self {
        self.rx_meta = meta;
        self
    }

    /// Reports this as the transmit timestamp of packets that ask for one.
    #[cfg(feature = "packetmeta-timestamp")]
    pub fn with_tx_stamp(mut self, stamp: Timestamp) -> Self {
        self.tx_stamp = Some(stamp);
        self
    }

    /// Adds the device to `stack` as an interface with hardware address `hw`.
    ///
    /// The stack gets its own copy, sharing this one's queues. It is leaked, so
    /// the interface lives as long as the test wants it to.
    pub fn install(&self, stack: &mut Stack<'_>, hw: HardwareAddress) -> IfaceHandle {
        stack.add_iface_borrowed(Box::leak(Box::new(self.clone())), hw).unwrap()
    }
}

impl Interface for TestDevice {
    fn capabilities(&self) -> IfaceCapabilities {
        let mut caps = IfaceCapabilities::default();
        caps.medium = self.medium;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let bytes = self.rx.borrow_mut().pop_front()?;
        let mut buf = PacketBuf::try_new().unwrap();
        buf.set_len(bytes.len());
        buf.copy_from_slice(&bytes);
        #[cfg(feature = "packetmeta-id")]
        {
            *buf.meta_mut() = self.rx_meta;
        }
        Some(buf)
    }

    fn can_transmit(&mut self) -> bool {
        self.room.get().is_none_or(|room| room > 0)
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        if !self.can_transmit() {
            return Err(buf);
        }
        if let Some(room) = self.room.get() {
            self.room.set(Some(room - 1));
        }
        #[cfg(feature = "packetmeta-id")]
        {
            let meta = buf.meta();
            self.tx_meta.borrow_mut().push(meta);
            #[cfg(feature = "packetmeta-timestamp")]
            if meta.request_timestamp
                && let Some(timestamp) = self.tx_stamp
            {
                self.tx_stamps.push_back(TxTimestamp { id: meta.id, timestamp });
            }
        }
        self.tx.borrow_mut().push(buf.to_vec());
        Ok(())
    }

    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        self.tx_stamps.pop_front()
    }
}
