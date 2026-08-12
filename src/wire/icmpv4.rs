use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};
use crate::wire::ip::checksum;

enum_with_unknown! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  3,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::EchoReply => write!(f, "echo reply"),
            Message::DstUnreachable => write!(f, "destination unreachable"),
            Message::Redirect => write!(f, "message redirect"),
            Message::EchoRequest => write!(f, "echo request"),
            Message::RouterAdvert => write!(f, "router advertisement"),
            Message::RouterSolicit => write!(f, "router solicitation"),
            Message::TimeExceeded => write!(f, "time exceeded"),
            Message::ParamProblem => write!(f, "parameter problem"),
            Message::Timestamp => write!(f, "timestamp"),
            Message::TimestampReply => write!(f, "timestamp reply"),
            Message::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

impl fmt::Display for DstUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DstUnreachable::NetUnreachable => write!(f, "destination network unreachable"),
            DstUnreachable::HostUnreachable => write!(f, "destination host unreachable"),
            DstUnreachable::ProtoUnreachable => write!(f, "destination protocol unreachable"),
            DstUnreachable::PortUnreachable => write!(f, "destination port unreachable"),
            DstUnreachable::FragRequired => write!(f, "fragmentation required, and DF flag set"),
            DstUnreachable::SrcRouteFailed => write!(f, "source route failed"),
            DstUnreachable::DstNetUnknown => write!(f, "destination network unknown"),
            DstUnreachable::DstHostUnknown => write!(f, "destination host unknown"),
            DstUnreachable::SrcHostIsolated => write!(f, "source host isolated"),
            DstUnreachable::NetProhibited => write!(f, "network administratively prohibited"),
            DstUnreachable::HostProhibited => write!(f, "host administratively prohibited"),
            DstUnreachable::NetUnreachToS => write!(f, "network unreachable for ToS"),
            DstUnreachable::HostUnreachToS => write!(f, "host unreachable for ToS"),
            DstUnreachable::CommProhibited => {
                write!(f, "communication administratively prohibited")
            }
            DstUnreachable::HostPrecedViol => write!(f, "host precedence violation"),
            DstUnreachable::PrecedCutoff => write!(f, "precedence cutoff in effect"),
            DstUnreachable::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

impl fmt::Display for TimeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TimeExceeded::TtlExpired => write!(f, "time-to-live exceeded in transit"),
            TimeExceeded::FragExpired => write!(f, "fragment reassembly time exceeded"),
            TimeExceeded::Unknown(id) => write!(f, "{id}"),
        }
    }
}

enum_with_unknown! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with ICMPv4 packet structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.len();
        if len < field::HEADER_END { Err(Error) } else { Ok(()) }
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        Message::from(self.buffer[field::TYPE])
    }

    /// Return the message code field.
    #[inline]
    pub fn msg_code(&self) -> u8 {
        self.buffer[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_SEQNO])
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply => field::ECHO_SEQNO.end,
            Message::DstUnreachable => field::UNUSED.end,
            _ => field::UNUSED.end, // make a conservative assumption
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        checksum::data(self.buffer) == !0
    }

    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buffer[self.header_len()..]
    }

    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.buffer[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        self.buffer[field::CODE] = value
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_SEQNO], value)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(self.buffer);
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        &mut self.buffer[range]
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static ECHO_PACKET_BYTES: [u8; 12] = [0x08, 0x00, 0x8e, 0xfe, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff];

    static ECHO_DATA_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_echo_deconstruct() {
        let mut bytes = ECHO_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes);
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x8efe);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.data(), &ECHO_DATA_BYTES[..]);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = [0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.data_mut().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(bytes, ECHO_PACKET_BYTES);
    }

    #[test]
    fn test_check_len() {
        let mut bytes = [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Packet::new_checked(&mut []), Err(Error));
        assert_eq!(Packet::new_checked(&mut bytes[..4]), Err(Error));
        assert!(Packet::new_checked(&mut bytes[..]).is_ok());
    }
}
