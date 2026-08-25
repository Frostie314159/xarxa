//! Next header compression ([RFC 6282 § 4]).
//!
//! [RFC 6282 § 4]: https://datatracker.ietf.org/doc/html/rfc6282#section-4
use super::{DISPATCH_EXT_HEADER, DISPATCH_UDP_HEADER, Error, NextHeader, Result};
use crate::wire::IpProtocol;
use byteorder::{ByteOrder, NetworkEndian};

macro_rules! get_field {
    ($name:ident, $mask:expr, $shift:expr) => {
        fn $name(&self) -> u8 {
            let raw = &self.buffer[0];
            ((raw >> $shift) & $mask) as u8
        }
    };
}

macro_rules! set_field {
    ($name:ident, $mask:expr, $shift:expr) => {
        fn $name(&mut self, val: u8) {
            let mut raw = self.buffer[0];
            raw = (raw & !($mask << $shift)) | (val << $shift);
            self.buffer[0] = raw;
        }
    };
}

/// The kind of compressed next header a buffer starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NhcPacket {
    /// A compressed IPv6 extension header, see [`ExtHeaderPacket`].
    ExtHeader,
    /// A compressed UDP header, see [`UdpNhcPacket`].
    UdpHeader,
}

impl NhcPacket {
    /// Read the dispatch byte of a compressed next header.
    ///
    /// Errors:
    /// - `Error` if the buffer is empty, or the dispatch is neither an
    ///   extension header nor a UDP header.
    pub fn dispatch(buffer: &[u8]) -> Result<Self> {
        let raw = buffer;
        if raw.is_empty() {
            return Err(Error);
        }

        if raw[0] >> 4 == DISPATCH_EXT_HEADER {
            // We have a compressed IPv6 Extension Header.
            Ok(Self::ExtHeader)
        } else if raw[0] >> 3 == DISPATCH_UDP_HEADER {
            // We have a compressed UDP header.
            Ok(Self::UdpHeader)
        } else {
            Err(Error)
        }
    }
}

/// The IPv6 extension header a compressed extension header stands for.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ExtHeaderId {
    HopByHopHeader,
    RoutingHeader,
    FragmentHeader,
    DestinationOptionsHeader,
    MobilityHeader,
    Header,
    Reserved,
}

impl From<ExtHeaderId> for IpProtocol {
    fn from(val: ExtHeaderId) -> Self {
        match val {
            ExtHeaderId::HopByHopHeader => Self::HopByHop,
            ExtHeaderId::RoutingHeader => Self::Ipv6Route,
            ExtHeaderId::FragmentHeader => Self::Ipv6Frag,
            ExtHeaderId::DestinationOptionsHeader => Self::Ipv6Opts,
            ExtHeaderId::MobilityHeader => Self::from(0),
            ExtHeaderId::Header => Self::from(0),
            ExtHeaderId::Reserved => Self::from(0),
        }
    }
}

/// A read/write wrapper around a 6LoWPAN NHC extension header.
/// [RFC 6282 § 4.2] specifies the format of the header.
///
/// The header has the following format:
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | 1 | 1 | 0 |    EID    |NH |
/// +---+---+---+---+---+---+---+---+
/// ```
///
/// With:
/// - EID: the extension header ID
/// - NH: Next Header
///
/// [RFC 6282 § 4.2]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.2
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtHeaderPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> ExtHeaderPacket<'a> {
    /// Imbue a raw octet buffer with a 6LoWPAN NHC Extension Header structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        ExtHeaderPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;

        if packet.eid_field() > 7 {
            return Err(Error);
        }

        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.is_empty() {
            return Err(Error);
        }

        let mut len = 2;
        len += self.next_header_size();

        if len <= self.buffer.len() { Ok(()) } else { Err(Error) }
    }

    get_field!(dispatch_field, 0b1111, 4);
    get_field!(eid_field, 0b111, 1);
    get_field!(nh_field, 0b1, 0);

    /// Return the Extension Header ID.
    pub fn extension_header_id(&self) -> ExtHeaderId {
        match self.eid_field() {
            0 => ExtHeaderId::HopByHopHeader,
            1 => ExtHeaderId::RoutingHeader,
            2 => ExtHeaderId::FragmentHeader,
            3 => ExtHeaderId::DestinationOptionsHeader,
            4 => ExtHeaderId::MobilityHeader,
            5 | 6 => ExtHeaderId::Reserved,
            7 => ExtHeaderId::Header,
            _ => unreachable!(),
        }
    }

    /// Return the length field: the length of the payload, in bytes.
    pub fn length(&self) -> u8 {
        self.buffer[1 + self.next_header_size()]
    }

    /// Parse the next header field.
    pub fn next_header(&self) -> NextHeader {
        if self.nh_field() == 1 {
            NextHeader::Compressed
        } else {
            // The full 8 bits for Next Header are carried in-line.
            NextHeader::Uncompressed(IpProtocol::from(self.buffer[1]))
        }
    }

    /// Return the size of the Next Header field.
    fn next_header_size(&self) -> usize {
        // If nh is set, then the Next Header is compressed using LOWPAN_NHC
        match self.nh_field() {
            0 => 1,
            1 => 0,
            _ => unreachable!(),
        }
    }

    /// Return the length of the header, not counting the payload.
    pub fn header_len(&self) -> usize {
        2 + self.next_header_size()
    }

    /// Return a pointer to the payload.
    ///
    /// # Panics
    /// Panics if the buffer is shorter than the length field says.
    pub fn payload(&self) -> &[u8] {
        let start = 2 + self.next_header_size();
        let len = self.length() as usize;
        &self.buffer[start..][..len]
    }

    /// Return a mutable pointer to the payload.
    ///
    /// # Panics
    /// Panics if the buffer is shorter than the length field says.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = 2 + self.next_header_size();
        let len = self.length() as usize;
        &mut self.buffer[start..][..len]
    }

    /// Set the dispatch field to `0b1110`.
    fn set_dispatch_field(&mut self) {
        let data = &mut self.buffer;
        data[0] = (data[0] & !(0b1111 << 4)) | (DISPATCH_EXT_HEADER << 4);
    }

    set_field!(set_eid_field, 0b111, 1);
    set_field!(set_nh_field, 0b1, 0);

    /// Set the Extension Header ID field.
    fn set_extension_header_id(&mut self, ext_header_id: ExtHeaderId) {
        let id = match ext_header_id {
            ExtHeaderId::HopByHopHeader => 0,
            ExtHeaderId::RoutingHeader => 1,
            ExtHeaderId::FragmentHeader => 2,
            ExtHeaderId::DestinationOptionsHeader => 3,
            ExtHeaderId::MobilityHeader => 4,
            ExtHeaderId::Reserved => 5,
            ExtHeaderId::Header => 7,
        };

        self.set_eid_field(id);
    }

    /// Set the Next Header.
    fn set_next_header(&mut self, next_header: NextHeader) {
        match next_header {
            NextHeader::Compressed => self.set_nh_field(0b1),
            NextHeader::Uncompressed(nh) => {
                self.set_nh_field(0b0);

                let start = 1;
                self.buffer[start] = nh.into();
            }
        }
    }

    /// Set the length.
    fn set_length(&mut self, length: u8) {
        let start = 1 + self.next_header_size();
        self.buffer[start] = length;
    }
}

/// The fields of a 6LoWPAN NHC extension header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtHeaderRepr {
    pub ext_header_id: ExtHeaderId,
    pub next_header: NextHeader,
    /// The length of the payload, in bytes.
    pub length: u8,
}

impl ExtHeaderRepr {
    /// Parse a 6LoWPAN NHC extension header.
    pub fn parse(packet: &ExtHeaderPacket<'_>) -> Result<Self> {
        // Ensure basic accessors will work.
        packet.check_len()?;

        if packet.dispatch_field() != DISPATCH_EXT_HEADER {
            return Err(Error);
        }

        Ok(Self {
            ext_header_id: packet.extension_header_id(),
            next_header: packet.next_header(),
            length: packet.length(),
        })
    }

    /// Return the length of the header this will emit, not counting the payload.
    pub fn buffer_len(&self) -> usize {
        let mut len = 1; // The minimal header size

        if self.next_header != NextHeader::Compressed {
            len += 1;
        }

        len += 1; // The length

        len
    }

    /// Write the header into a packet.
    ///
    /// The buffer must be zeroed first.
    pub fn emit(&self, packet: &mut ExtHeaderPacket<'_>) {
        packet.set_dispatch_field();
        packet.set_extension_header_id(self.ext_header_id);
        packet.set_next_header(self.next_header);
        packet.set_length(self.length);
    }
}

/// A read/write wrapper around a 6LoWPAN NHC UDP header.
/// [RFC 6282 § 4.3] specifies the format of the header.
///
/// The base header has the following format:
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | 1 | 1 | 1 | 0 | C |   P   |
/// +---+---+---+---+---+---+---+---+
/// With:
/// - C: checksum, specifies if the checksum is elided.
/// - P: ports, specifies if the ports are elided.
/// ```
///
/// [RFC 6282 § 4.3]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.3
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UdpNhcPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> UdpNhcPacket<'a> {
    /// Imbue a raw octet buffer with a LOWPAN_NHC frame structure for UDP.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Self> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.is_empty() {
            return Err(Error);
        }

        let index = 1 + self.ports_size() + self.checksum_size();
        if index > self.buffer.len() {
            return Err(Error);
        }

        Ok(())
    }

    get_field!(dispatch_field, 0b11111, 3);
    get_field!(checksum_field, 0b1, 2);
    get_field!(ports_field, 0b11, 0);

    /// Returns the index of the start of the next header compressed fields.
    const fn nhc_fields_start(&self) -> usize {
        1
    }

    /// Return the source port number.
    pub fn src_port(&self) -> u16 {
        match self.ports_field() {
            0b00 | 0b01 => {
                // The full 16 bits are carried in-line.
                let start = self.nhc_fields_start();

                NetworkEndian::read_u16(&self.buffer[start..start + 2])
            }
            0b10 => {
                // The first 8 bits are elided.
                let start = self.nhc_fields_start();

                0xf000 + self.buffer[start] as u16
            }
            0b11 => {
                // The first 12 bits are elided.
                let start = self.nhc_fields_start();

                0xf0b0 + (self.buffer[start] >> 4) as u16
            }
            _ => unreachable!(),
        }
    }

    /// Return the destination port number.
    pub fn dst_port(&self) -> u16 {
        match self.ports_field() {
            0b00 => {
                // The full 16 bits are carried in-line.
                let idx = self.nhc_fields_start();

                NetworkEndian::read_u16(&self.buffer[idx + 2..idx + 4])
            }
            0b01 => {
                // The first 8 bits are elided.
                let idx = self.nhc_fields_start();

                0xf000 + self.buffer[idx + 2] as u16
            }
            0b10 => {
                // The full 16 bits are carried in-line.
                let idx = self.nhc_fields_start();

                NetworkEndian::read_u16(&self.buffer[idx + 1..idx + 1 + 2])
            }
            0b11 => {
                // The first 12 bits are elided.
                let start = self.nhc_fields_start();

                0xf0b0 + (self.buffer[start] & 0x0f) as u16
            }
            _ => unreachable!(),
        }
    }

    /// Return the checksum, or `None` if it is elided.
    pub fn checksum(&self) -> Option<u16> {
        if self.checksum_field() == 0b0 {
            let start = self.nhc_fields_start() + self.ports_size();
            Some(NetworkEndian::read_u16(&self.buffer[start..start + 2]))
        } else {
            // The checksum is elided and needs to be recomputed on the 6LoWPAN termination point.
            None
        }
    }

    // Return the size of the checksum field.
    pub(crate) fn checksum_size(&self) -> usize {
        match self.checksum_field() {
            0b0 => 2,
            0b1 => 0,
            _ => unreachable!(),
        }
    }

    /// Returns the total size of both port numbers.
    pub(crate) fn ports_size(&self) -> usize {
        match self.ports_field() {
            0b00 => 4, // 16 bits + 16 bits
            0b01 => 3, // 16 bits + 8 bits
            0b10 => 3, // 8 bits + 16 bits
            0b11 => 1, // 4 bits + 4 bits
            _ => unreachable!(),
        }
    }

    /// Return the length of the header, not counting the payload.
    pub fn header_len(&self) -> usize {
        1 + self.ports_size() + self.checksum_size()
    }

    /// Return a pointer to the payload.
    pub fn payload(&self) -> &[u8] {
        let start = 1 + self.ports_size() + self.checksum_size();
        &self.buffer[start..]
    }

    /// Return a mutable pointer to the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = 1 + self.ports_size() + self.checksum_size();
        &mut self.buffer[start..]
    }

    /// Set the dispatch field to `0b11110`.
    fn set_dispatch_field(&mut self) {
        let data = &mut self.buffer;
        data[0] = (data[0] & !(0b11111 << 3)) | (DISPATCH_UDP_HEADER << 3);
    }

    set_field!(set_checksum_field, 0b1, 2);
    set_field!(set_ports_field, 0b11, 0);

    fn set_ports(&mut self, src_port: u16, dst_port: u16) {
        let mut idx = 1;

        match (src_port, dst_port) {
            (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => {
                // We can compress both the source and destination ports.
                self.set_ports_field(0b11);
                let data = &mut self.buffer;
                data[idx] = (((src_port - 0xf0b0) as u8) << 4) | ((dst_port - 0xf0b0) as u8);
            }
            (0xf000..=0xf0ff, _) => {
                // We can compress the source port, but not the destination port.
                self.set_ports_field(0b10);
                let data = &mut self.buffer;
                data[idx] = (src_port - 0xf000) as u8;
                idx += 1;

                NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
            }
            (_, 0xf000..=0xf0ff) => {
                // We can compress the destination port, but not the source port.
                self.set_ports_field(0b01);
                let data = &mut self.buffer;
                NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                idx += 2;
                data[idx] = (dst_port - 0xf000) as u8;
            }
            (_, _) => {
                // We cannot compress any port.
                self.set_ports_field(0b00);
                let data = &mut self.buffer;
                NetworkEndian::write_u16(&mut data[idx..idx + 2], src_port);
                idx += 2;
                NetworkEndian::write_u16(&mut data[idx..idx + 2], dst_port);
            }
        };
    }

    /// Write the checksum inline.
    ///
    /// Call this after [`UdpNhcRepr::emit`]: the ports must be set first.
    pub fn set_checksum(&mut self, checksum: u16) {
        self.set_checksum_field(0b0);
        let idx = 1 + self.ports_size();
        NetworkEndian::write_u16(&mut self.buffer[idx..idx + 2], checksum);
    }
}

/// The fields of a 6LoWPAN NHC UDP header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UdpNhcRepr {
    pub src_port: u16,
    pub dst_port: u16,
}

impl UdpNhcRepr {
    /// Parse a 6LoWPAN NHC UDP header.
    ///
    /// The checksum is not verified here. Read it with
    /// [`UdpNhcPacket::checksum`].
    pub fn parse(packet: &UdpNhcPacket<'_>) -> Result<Self> {
        packet.check_len()?;

        if packet.dispatch_field() != DISPATCH_UDP_HEADER {
            return Err(Error);
        }

        Ok(Self {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
        })
    }

    /// Return the length of the header this will emit, with the checksum inline.
    pub fn header_len(&self) -> usize {
        let mut len = 1; // The minimal header size

        len += 2; // The checksum is always carried inline.

        // Check if we can compress the source and destination ports
        match (self.src_port, self.dst_port) {
            (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => len + 1,
            (0xf000..=0xf0ff, _) | (_, 0xf000..=0xf0ff) => len + 3,
            (_, _) => len + 4,
        }
    }

    /// Write the dispatch byte and the ports into a packet.
    ///
    /// The buffer must be zeroed first. Write the checksum after, with
    /// [`UdpNhcPacket::set_checksum`].
    pub fn emit(&self, packet: &mut UdpNhcPacket<'_>) {
        packet.set_dispatch_field();
        packet.set_ports(self.src_port, self.dst_port);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ROUTING_SR_PACKET: [u8; 32] = [
        0xe3, 0x1e, 0x03, 0x03, 0x99, 0x30, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x06, 0x00, 0x06,
        0x00, 0x06, 0x00, 0x06, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_source_routing_deconstruct() {
        let mut bytes = ROUTING_SR_PACKET;
        let header = ExtHeaderPacket::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(header.next_header(), NextHeader::Compressed);
        assert_eq!(header.extension_header_id(), ExtHeaderId::RoutingHeader);
        assert_eq!(header.length(), 30);
        assert_eq!(header.payload(), &ROUTING_SR_PACKET[2..]);
    }

    #[test]
    fn test_source_routing_emit() {
        let ext_hdr = ExtHeaderRepr {
            ext_header_id: ExtHeaderId::RoutingHeader,
            next_header: NextHeader::Compressed,
            length: 30,
        };

        let mut buffer = vec![0u8; ext_hdr.buffer_len() + 30];
        ext_hdr.emit(&mut ExtHeaderPacket::new_unchecked(&mut buffer[..ext_hdr.buffer_len()]));
        buffer[ext_hdr.buffer_len()..].copy_from_slice(&ROUTING_SR_PACKET[2..]);

        assert_eq!(&buffer[..], ROUTING_SR_PACKET);
    }

    #[test]
    fn ext_header_nh_inlined() {
        let mut bytes = [0xe2, 0x3a, 0x6, 0x3, 0x0, 0xff, 0x0, 0x0, 0x0];

        let packet = ExtHeaderPacket::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.next_header_size(), 1);
        assert_eq!(packet.length(), 6);
        assert_eq!(packet.dispatch_field(), DISPATCH_EXT_HEADER);
        assert_eq!(packet.extension_header_id(), ExtHeaderId::RoutingHeader);
        assert_eq!(packet.next_header(), NextHeader::Uncompressed(IpProtocol::Icmpv6));

        assert_eq!(packet.payload(), [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ext_header_nh_elided() {
        let mut bytes = [0xe3, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00];

        let packet = ExtHeaderPacket::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.next_header_size(), 0);
        assert_eq!(packet.length(), 6);
        assert_eq!(packet.dispatch_field(), DISPATCH_EXT_HEADER);
        assert_eq!(packet.extension_header_id(), ExtHeaderId::RoutingHeader);
        assert_eq!(packet.next_header(), NextHeader::Compressed);

        assert_eq!(packet.payload(), [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ext_header_emit() {
        let ext_header = ExtHeaderRepr {
            ext_header_id: ExtHeaderId::RoutingHeader,
            next_header: NextHeader::Compressed,
            length: 6,
        };

        let len = ext_header.buffer_len();
        let mut buffer = [0u8; 127];
        let mut packet = ExtHeaderPacket::new_unchecked(&mut buffer[..len]);
        ext_header.emit(&mut packet);

        assert_eq!(packet.dispatch_field(), DISPATCH_EXT_HEADER);
        assert_eq!(packet.next_header(), NextHeader::Compressed);
        assert_eq!(packet.extension_header_id(), ExtHeaderId::RoutingHeader);
    }

    #[test]
    fn udp_nhc_fields() {
        let mut bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];

        let packet = UdpNhcPacket::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.dispatch_field(), DISPATCH_UDP_HEADER);
        assert_eq!(packet.checksum(), Some(0x28c4));
        assert_eq!(packet.src_port(), 5678);
        assert_eq!(packet.dst_port(), 8765);
    }

    #[test]
    fn udp_emit() {
        let udp = UdpNhcRepr {
            src_port: 0xf0b1,
            dst_port: 0xf001,
        };

        let payload = b"Hello World!";

        let len = udp.header_len() + payload.len();
        let mut buffer = [0u8; 127];
        let mut packet = UdpNhcPacket::new_unchecked(&mut buffer[..len]);
        udp.emit(&mut packet);
        packet.set_checksum(0x1234);
        packet.payload_mut().copy_from_slice(&payload[..]);

        assert_eq!(packet.dispatch_field(), DISPATCH_UDP_HEADER);
        assert_eq!(packet.src_port(), 0xf0b1);
        assert_eq!(packet.dst_port(), 0xf001);
        assert_eq!(packet.checksum(), Some(0x1234));
        assert_eq!(packet.payload(), b"Hello World!");
    }

    /// Every port encoding round-trips, including the 4-bit one for two
    /// `0xf0bX` ports (RFC 6282 §4.3.3).
    #[test]
    fn udp_port_modes() {
        for (src_port, dst_port, header_len) in [
            (0xf0b1, 0xf0b2, 4),
            (0xf0b1, 0xf001, 6),
            (0xf0b1, 1234, 6),
            (1234, 0xf0b1, 6),
            (0xf0ff, 0xf0ff, 6),
            (1234, 5678, 7),
        ] {
            let udp = UdpNhcRepr { src_port, dst_port };
            assert_eq!(udp.header_len(), header_len);
            let mut buffer = [0u8; 8];
            let mut packet = UdpNhcPacket::new_unchecked(&mut buffer[..header_len]);
            udp.emit(&mut packet);
            packet.set_checksum(0xabcd);
            assert_eq!(packet.header_len(), header_len);
            assert_eq!(packet.src_port(), src_port);
            assert_eq!(packet.dst_port(), dst_port);
            assert_eq!(packet.checksum(), Some(0xabcd));
            assert_eq!(UdpNhcRepr::parse(&packet), Ok(udp));
        }
    }
}
