/*! Network interfaces.

The `iface` module deals with the *network devices*. It provides the [Driver] trait, which
drivers implement to exchange owned [`PacketBuf`]s with the stack:

  * on receive, the driver hands a filled buffer up to the stack;
  * on transmit, the stack hands a built frame down to the driver, which owns the buffer
    until the hardware is done with it, then drops it.

This module provides two implementations of [Driver] for the host OS: the
[TunTapInterface], a virtual TUN/TAP interface, and the [RawSocketInterface], a
packet socket bound to an existing interface (Ethernet or IEEE 802.15.4).
*/

use crate::buf::PacketBuf;
use crate::wire::HardwareAddress;

#[cfg(all(feature = "std", any(feature = "medium-ethernet", feature = "medium-ip")))]
mod tuntap;

#[cfg(all(feature = "std", any(feature = "medium-ethernet", feature = "medium-ip")))]
pub use self::tuntap::TunTapInterface;

#[cfg(all(
    feature = "std",
    any(target_os = "linux", target_os = "android"),
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
mod raw_socket;

#[cfg(all(
    feature = "std",
    any(target_os = "linux", target_os = "android"),
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
pub use self::raw_socket::RawSocketInterface;

/// Link state of an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum LinkState {
    /// The link is down. No frames can pass.
    Down,
    /// The link is up.
    Up,
}

/// Type of medium of an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,

    /// IP medium. Devices of this type send and receive IP frames, without an
    /// Ethernet header. MAC addresses are not used.
    #[cfg(feature = "medium-ip")]
    Ip,

    /// IEEE 802.15.4 medium. Devices of this type send and receive 802.15.4
    /// MAC frames carrying 6LoWPAN.
    ///
    /// [`IfaceCapabilities::max_transmission_unit`] is the whole MAC frame
    /// without the FCS: 125 for a 127-byte PHY frame with a 2-byte FCS.
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154,
}

/// A description of checksum behavior for a particular protocol.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Checksum {
    /// Verify checksum when receiving and compute checksum when sending.
    #[default]
    Both,
    /// Verify checksum when receiving.
    Rx,
    /// Compute checksum before sending.
    Tx,
    /// Ignore checksum completely.
    None,
}

impl Checksum {
    /// Whether the checksum should be verified when receiving.
    pub fn rx(&self) -> bool {
        matches!(*self, Checksum::Both | Checksum::Rx)
    }

    /// Whether the checksum should be computed when sending.
    pub fn tx(&self) -> bool {
        matches!(*self, Checksum::Both | Checksum::Tx)
    }
}

/// A description of checksum behavior for every supported protocol.
///
/// This is what a device uses to tell the stack which checksums its hardware
/// takes care of, so the stack doesn't compute them again in software.
///
/// The default is [`Checksum::Both`] for every protocol: the stack computes and
/// verifies everything itself.
///
/// A checksum the stack does not compute is written as zero, so that a device
/// that fills it in finds a known value there.
///
/// The fields are the protocols with a checksum the stack handles. IGMP is not
/// among them: its checksum is always computed and verified in software.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChecksumCapabilities {
    /// Checksum behavior for the IPv4 header.
    pub ipv4: Checksum,
    /// Checksum behavior for UDP.
    pub udp: Checksum,
    /// Checksum behavior for TCP.
    pub tcp: Checksum,
    /// Checksum behavior for ICMPv4.
    pub icmpv4: Checksum,
    /// Checksum behavior for ICMPv6.
    pub icmpv6: Checksum,
}

impl ChecksumCapabilities {
    /// Checksum behavior that results in not computing or verifying checksums
    /// for any of the supported protocols.
    pub fn ignored() -> Self {
        ChecksumCapabilities {
            ipv4: Checksum::None,
            udp: Checksum::None,
            tcp: Checksum::None,
            icmpv4: Checksum::None,
            icmpv6: Checksum::None,
        }
    }
}

/// A description of iface capabilities.
///
/// This is `#[non_exhaustive]` so that capabilities can be added later without breaking
/// every driver. Drivers live outside this crate and so cannot use a struct expression,
/// they start from [`Default`] and overwrite the fields they care about:
///
/// ```
/// # use xarxa::iface::IfaceCapabilities;
/// let mut caps = IfaceCapabilities::default();
/// caps.max_transmission_unit = 1514;
/// // caps.medium = Medium::Ethernet; is the default when `medium-ethernet` is on
/// ```
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IfaceCapabilities {
    /// Medium of the iface.
    pub medium: Medium,

    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    pub max_transmission_unit: usize,

    /// Checksum behavior.
    ///
    /// If the network device is capable of verifying or computing checksums for some
    /// protocols, it can request that the stack not do so in software to improve
    /// performance.
    pub checksum: ChecksumCapabilities,
}

impl Default for IfaceCapabilities {
    fn default() -> Self {
        Self {
            #[cfg(feature = "medium-ethernet")]
            medium: Medium::Ethernet,
            #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ip"))]
            medium: Medium::Ip,
            #[cfg(all(not(feature = "medium-ethernet"), not(feature = "medium-ip")))]
            medium: Medium::Ieee802154,
            #[cfg(feature = "medium-ethernet")]
            max_transmission_unit: 1514,
            #[cfg(all(not(feature = "medium-ethernet"), feature = "medium-ip"))]
            max_transmission_unit: 1500,
            #[cfg(all(not(feature = "medium-ethernet"), not(feature = "medium-ip")))]
            max_transmission_unit: 125,
            checksum: ChecksumCapabilities::default(),
        }
    }
}

/// A network device driver, sending and receiving raw network frames.
pub trait Driver {
    /// Get a description of iface capabilities.
    fn capabilities(&self) -> IfaceCapabilities;

    /// Get the device's hardware address.
    ///
    /// The address kind must match the medium in [`capabilities`](Self::capabilities):
    /// an Ethernet address for [`Medium::Ethernet`], [`HardwareAddress::Ip`] for
    /// [`Medium::Ip`], an IEEE 802.15.4 address for [`Medium::Ieee802154`].
    ///
    /// The stack reads it once, when the interface is added. Use
    /// [`Iface::set_hardware_addr`](crate::Iface::set_hardware_addr) to change the
    /// address of an already-added interface.
    fn hardware_address(&self) -> HardwareAddress;

    /// Get the link state.
    ///
    /// Devices that cannot tell, or whose link is always up, return
    /// [`LinkState::Up`], which is the default implementation.
    fn link_state(&mut self) -> LinkState {
        LinkState::Up
    }

    /// Poll for a received frame.
    ///
    /// Returns a buffer holding the received frame if one is available, transferring
    /// ownership of it to the caller.
    ///
    /// A driver that has per-packet metadata to report, such as an identifier or a
    /// receive timestamp, sets it on the buffer's [`PacketMeta`](crate::PacketMeta)
    /// here. It travels with the packet up to the socket that receives it.
    fn receive(&mut self) -> Option<PacketBuf>;

    /// Whether the device can transmit one frame right now.
    ///
    /// Devices typically have a transmit packet queue. This returns
    /// whether this queue has space to take one more frame.
    ///
    /// If this returns `true`, the next `transmit()` call must not fail.
    ///
    /// In devices where there's no queue so transmit always succeeds, this
    /// should always return `true`.
    fn can_transmit(&mut self) -> bool;

    /// Queue a frame for transmission, transferring ownership of the buffer to the iface.
    ///
    /// The iface holds the buffer until the hardware is done with it, then drops it.
    /// If the frame cannot be queued right now (device busy or queue full), the buffer
    /// is handed back in the `Err` variant.
    ///
    /// The buffer's [`PacketMeta`](crate::PacketMeta) is whatever the sending socket
    /// attached to the packet (default for packets the stack generates itself). A
    /// driver that supports transmit timestamping timestamps the frame if
    /// [`request_timestamp`](crate::PacketMeta::request_timestamp) is set, and reports
    /// the result from [`poll_tx_timestamp`](Self::poll_tx_timestamp) tagged with the
    /// packet's [`id`](crate::PacketMeta::id).
    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf>;

    /// Poll for the timestamp of an already-transmitted packet.
    ///
    /// Returns the transmit timestamp of a packet previously sent with
    /// [`PacketMeta::request_timestamp`](crate::PacketMeta::request_timestamp) set,
    /// tagged with that packet's [`PacketMeta::id`](crate::PacketMeta::id), or `None`
    /// if no timestamp is available right now. Reached from the stack through
    /// [`Iface::poll_tx_timestamp`](crate::Iface::poll_tx_timestamp).
    ///
    /// Transmit timestamps are reported out of band, rather than on the packet like
    /// receive timestamps are, because a packet's transmit timestamp does not exist yet
    /// when [`transmit`](Self::transmit) returns: it has not gone out on the wire yet.
    ///
    /// Callers must be robust against all of the following:
    ///
    /// * Timestamps become available an arbitrary time after `transmit` returned, so
    ///   this should be polled repeatedly, not just once after sending.
    /// * Timestamps may be reported out of order with respect to transmission.
    /// * Timestamps may never arrive at all, e.g. because the hardware ran out of
    ///   timestamp slots. Never block waiting for a particular `id` to show up without
    ///   a timeout.
    ///
    /// Devices that do not support transmit timestamping always return `None`, which is
    /// the default implementation.
    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<crate::meta::TxTimestamp> {
        None
    }
}

impl<T: Driver + ?Sized> Driver for &mut T {
    fn capabilities(&self) -> IfaceCapabilities {
        T::capabilities(self)
    }
    fn hardware_address(&self) -> HardwareAddress {
        T::hardware_address(self)
    }
    fn link_state(&mut self) -> LinkState {
        T::link_state(self)
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        T::receive(self)
    }
    fn can_transmit(&mut self) -> bool {
        T::can_transmit(self)
    }
    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        T::transmit(self, buf)
    }
    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<crate::meta::TxTimestamp> {
        T::poll_tx_timestamp(self)
    }
}

/// Wait until given file descriptor becomes readable, but no longer than given timeout.
#[cfg(feature = "std")]
pub fn wait(fd: std::os::unix::io::RawFd, duration: Option<std::time::Duration>) -> std::io::Result<()> {
    use std::{io, mem, ptr};

    unsafe {
        let mut readfds = {
            let mut readfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(readfds.as_mut_ptr());
            libc::FD_SET(fd, readfds.as_mut_ptr());
            readfds.assume_init()
        };

        let mut writefds = {
            let mut writefds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(writefds.as_mut_ptr());
            writefds.assume_init()
        };

        let mut exceptfds = {
            let mut exceptfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(exceptfds.as_mut_ptr());
            exceptfds.assume_init()
        };

        let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let timeout_ptr = if let Some(duration) = duration {
            timeout.tv_sec = duration.as_secs() as libc::time_t;
            timeout.tv_usec = duration.subsec_micros() as libc::suseconds_t;
            &mut timeout as *mut _
        } else {
            ptr::null_mut()
        };

        let res = libc::select(fd + 1, &mut readfds, &mut writefds, &mut exceptfds, timeout_ptr);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
