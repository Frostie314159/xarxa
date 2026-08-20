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

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
mod arp;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
mod dhcpv4;
#[cfg(feature = "dns")]
pub mod dns;
mod ethernet;
#[cfg(feature = "ipv4")]
mod icmpv4;
#[cfg(feature = "ipv6")]
mod icmpv6;
pub(crate) mod ip;
#[cfg(feature = "ipv4")]
pub(crate) mod ipv4;
#[cfg(feature = "ipv6")]
pub(crate) mod ipv6;
#[cfg(feature = "ipv6")]
mod ipv6ext;
#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
mod ndisc;
#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
mod ndiscoption;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(any(feature = "udp", feature = "dhcpv4"))]
mod udp;

use core::fmt;

use crate::iface::Medium;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    HEADER_LEN as ETHERNET_HEADER_LEN,
};

/// The headroom every egress packet reserves for the link-layer header below IP.
///
/// The Ethernet header in a build that drives Ethernet interfaces, since an IP
/// packet may end up going out of one. Zero in a build that only drives
/// [`Medium::Ip`] interfaces, which prepend nothing.
#[cfg(feature = "medium-ethernet")]
pub const LINK_HEADER_LEN: usize = ETHERNET_HEADER_LEN;

/// The headroom every egress packet reserves for the link-layer header below IP.
///
/// The Ethernet header in a build that drives Ethernet interfaces, since an IP
/// packet may end up going out of one. Zero in a build that only drives
/// [`Medium::Ip`] interfaces, which prepend nothing.
#[cfg(not(feature = "medium-ethernet"))]
pub const LINK_HEADER_LEN: usize = 0;

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
pub use self::arp::{
    BUFFER_LEN as ARP_BUFFER_LEN, Hardware as ArpHardware, Operation as ArpOperation, Packet as ArpPacket,
};

#[cfg(feature = "dhcpv4")]
pub(crate) use self::dhcpv4::field as dhcpv4_field;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
pub use self::dhcpv4::{
    CLIENT_PORT as DHCP_CLIENT_PORT, DhcpOption, Flags as DhcpFlags, HEADER_LEN as DHCP_HEADER_LEN,
    MAGIC_NUMBER as DHCP_MAGIC_NUMBER, MAX_DNS_SERVER_COUNT as DHCP_MAX_DNS_SERVER_COUNT,
    MessageType as DhcpMessageType, OpCode as DhcpOpCode, OptionWriter as DhcpOptionWriter, Packet as DhcpPacket,
    SERVER_PORT as DHCP_SERVER_PORT,
};

pub use self::ip::checksum;
pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint, ListenEndpoint as IpListenEndpoint,
    Protocol as IpProtocol, Version as IpVersion,
};

#[cfg(feature = "ipv4")]
pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, HEADER_LEN as IPV4_HEADER_LEN, MIN_MTU as IPV4_MIN_MTU,
    Packet as Ipv4Packet,
};

#[cfg(feature = "ipv4")]
pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;

#[cfg(feature = "ipv6")]
pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, HEADER_LEN as IPV6_HEADER_LEN,
    LINK_LOCAL_ALL_NODES as IPV6_LINK_LOCAL_ALL_NODES, LINK_LOCAL_ALL_ROUTERS as IPV6_LINK_LOCAL_ALL_ROUTERS,
    MIN_MTU as IPV6_MIN_MTU, Packet as Ipv6Packet,
};
#[cfg(feature = "ipv6")]
pub(crate) use self::ipv6::{AddressExt as Ipv6AddressExt, MulticastScope as Ipv6MulticastScope};

#[cfg(feature = "ipv6")]
pub use self::ipv6ext::{
    ExtHeader as Ipv6ExtHeader, OptionFailureAction as Ipv6OptionFailureAction, OptionType as Ipv6OptionType,
    OptionsIter as Ipv6OptionsIter,
};

#[cfg(feature = "ipv4")]
pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, TimeExceeded as Icmpv4TimeExceeded,
};

#[cfg(feature = "ipv6")]
pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, TimeExceeded as Icmpv6TimeExceeded,
};

#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
pub use self::ndisc::{NeighborFlags as NdiscNeighborFlags, RouterFlags as NdiscRouterFlags};

#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
pub use self::ndiscoption::{NdiscOption, PrefixInfoFlags as NdiscPrefixInfoFlags, Type as NdiscOptionType};

#[cfg(feature = "tcp")]
pub use self::tcp::{
    Control as TcpControl, HEADER_LEN as TCP_HEADER_LEN, Packet as TcpPacket, SeqNumber as TcpSeqNumber, TcpOption,
};

#[cfg(any(feature = "udp", feature = "dhcpv4"))]
pub use self::udp::{HEADER_LEN as UDP_HEADER_LEN, Packet as UdpPacket};

#[cfg(feature = "dns")]
pub use self::dns::{
    Flags as DnsFlags, HEADER_LEN as DNS_HEADER_LEN, Opcode as DnsOpcode, Packet as DnsPacket, Question as DnsQuestion,
    Rcode as DnsRcode, Record as DnsRecord, RecordData as DnsRecordData, Type as DnsType,
};

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

/// A hardware (link-layer) address.
///
/// Which variants exist depends on the enabled `medium-*` features. In a build
/// that only drives [`Medium::Ip`] interfaces this type has a single variant and
/// takes up no space.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareAddress {
    /// An Ethernet (MAC) address. Requires the `medium-ethernet` feature.
    #[cfg(feature = "medium-ethernet")]
    Ethernet(EthernetAddress),
    /// No address, for interfaces that send and receive bare IP packets.
    /// Requires the `medium-ip` feature.
    #[cfg(feature = "medium-ip")]
    Ip,
}

impl HardwareAddress {
    /// The medium this kind of address belongs to.
    pub const fn medium(&self) -> Medium {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(_) => Medium::Ethernet,
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => Medium::Ip,
        }
    }

    /// The Ethernet address, or `None` if this is not one.
    #[cfg(feature = "medium-ethernet")]
    pub const fn ethernet(&self) -> Option<EthernetAddress> {
        match self {
            HardwareAddress::Ethernet(addr) => Some(*addr),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn ethernet_or_panic(&self) -> EthernetAddress {
        match self {
            HardwareAddress::Ethernet(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("hardware address is not an Ethernet address"),
        }
    }
}

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => write!(f, "none"),
        }
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

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

#[cfg(test)]
mod test {
    /// A build that only drives IP interfaces pays nothing for hardware addresses.
    #[test]
    #[cfg(all(feature = "medium-ip", not(feature = "medium-ethernet")))]
    fn test_hardware_address_is_zero_sized() {
        assert_eq!(core::mem::size_of::<super::HardwareAddress>(), 0);
    }
}
