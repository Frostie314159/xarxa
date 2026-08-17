/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides functions to extract
fields from sequences of octets, and to insert fields into sequences of octets. This
happens through the `Packet` family of structures, e.g. [EthernetFrame] or [Ipv4Packet].

[EthernetFrame]: struct.EthernetFrame.html
[Ipv4Packet]: struct.Ipv4Packet.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
mod arp;
mod ethernet;
#[cfg(feature = "proto-ipv4")]
mod icmpv4;
#[cfg(feature = "proto-ipv6")]
mod icmpv6;
pub(crate) mod ip;
#[cfg(feature = "proto-ipv4")]
pub(crate) mod ipv4;
#[cfg(feature = "proto-ipv6")]
pub(crate) mod ipv6;
#[cfg(feature = "proto-ipv6")]
mod ipv6ext;
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
mod ndisc;
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
mod ndiscoption;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(feature = "socket-udp")]
mod udp;

use core::fmt;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    HEADER_LEN as ETHERNET_HEADER_LEN,
};

#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
pub use self::arp::{
    BUFFER_LEN as ARP_BUFFER_LEN, Hardware as ArpHardware, Operation as ArpOperation, Packet as ArpPacket,
};

pub use self::ip::checksum;
pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint, ListenEndpoint as IpListenEndpoint,
    Protocol as IpProtocol, Version as IpVersion,
};

#[cfg(feature = "proto-ipv4")]
pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, HEADER_LEN as IPV4_HEADER_LEN, MIN_MTU as IPV4_MIN_MTU,
    Packet as Ipv4Packet,
};

#[cfg(feature = "proto-ipv4")]
pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, HEADER_LEN as IPV6_HEADER_LEN,
    LINK_LOCAL_ALL_NODES as IPV6_LINK_LOCAL_ALL_NODES, LINK_LOCAL_ALL_ROUTERS as IPV6_LINK_LOCAL_ALL_ROUTERS,
    MIN_MTU as IPV6_MIN_MTU, Packet as Ipv6Packet,
};
#[cfg(feature = "proto-ipv6")]
pub(crate) use self::ipv6::{AddressExt as Ipv6AddressExt, MulticastScope as Ipv6MulticastScope};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6ext::{
    ExtHeader as Ipv6ExtHeader, OptionFailureAction as Ipv6OptionFailureAction, OptionType as Ipv6OptionType,
    OptionsIter as Ipv6OptionsIter,
};

#[cfg(feature = "proto-ipv4")]
pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, TimeExceeded as Icmpv4TimeExceeded,
};

#[cfg(feature = "proto-ipv6")]
pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, TimeExceeded as Icmpv6TimeExceeded,
};

#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
pub use self::ndisc::{NeighborFlags as NdiscNeighborFlags, RouterFlags as NdiscRouterFlags};

#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
pub use self::ndiscoption::{NdiscOption, PrefixInfoFlags as NdiscPrefixInfoFlags, Type as NdiscOptionType};

#[cfg(feature = "socket-tcp")]
pub use self::tcp::{
    Control as TcpControl, HEADER_LEN as TCP_HEADER_LEN, Packet as TcpPacket, SeqNumber as TcpSeqNumber, TcpOption,
};

#[cfg(feature = "socket-udp")]
pub use self::udp::{HEADER_LEN as UDP_HEADER_LEN, Packet as UdpPacket};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by xarxa.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub const MAX_HARDWARE_ADDRESS_LEN: usize = 6;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RawHardwareAddress {
    len: u8,
    data: [u8; MAX_HARDWARE_ADDRESS_LEN],
}

impl RawHardwareAddress {
    /// Create a new `RawHardwareAddress` from a byte slice.
    ///
    /// # Panics
    /// Panics if `addr.len() > MAX_HARDWARE_ADDRESS_LEN`.
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HARDWARE_ADDRESS_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self {
            len: addr.len() as u8,
            data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Parse the address as an Ethernet address, if it has the right length.
    pub fn parse_ethernet(&self) -> Result<EthernetAddress> {
        if self.len() != 6 {
            return Err(Error);
        }
        Ok(EthernetAddress::from_bytes(self.as_bytes()))
    }
}

impl core::fmt::Display for RawHardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<EthernetAddress> for RawHardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}
