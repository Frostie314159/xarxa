//! IPv6 extension headers (RFC 8200 §4): the common (next header, length) prefix,
//! and the TLV option walk shared by the Hop-by-Hop and Destination Options headers.

use super::{Error, Result};
use crate::wire::ip::Protocol;

/// A read wrapper around an IPv6 extension header.
///
/// All IPv6 extension headers (except Fragment) share the same layout: a next
/// header field, a length field in units of 8 octets not counting the first 8,
/// and header-specific data.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct ExtHeader<'a> {
    buffer: &'a [u8],
}

mod field {
    pub const NXT_HDR: usize = 0;
    pub const LENGTH: usize = 1;
    pub const DATA_START: usize = 2;
}

impl<'a> ExtHeader<'a> {
    /// Imbue a raw octet buffer with extension header structure.
    pub const fn new_unchecked(buffer: &'a [u8]) -> ExtHeader<'a> {
        ExtHeader { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a [u8]) -> Result<ExtHeader<'a>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.len() < field::DATA_START || self.buffer.len() < self.header_len() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.buffer[field::NXT_HDR])
    }

    /// Return the length of the whole extension header, in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.buffer[field::LENGTH] as usize + 1) * 8
    }

    /// The header-specific data: for the Hop-by-Hop and Destination Options
    /// headers, the TLV-encoded options.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        &self.buffer[field::DATA_START..self.header_len()]
    }
}

open_enum! {
    /// IPv6 option type, from the Hop-by-Hop or Destination Options TLVs.
    pub enum OptionType(u8) {
        /// 1 byte of padding (this option has no length or data).
        Pad1        = 0,
        /// Multiple bytes of padding.
        PadN        = 1,
        /// Router alert (RFC 2711).
        RouterAlert = 5,
    }
}

open_enum! {
    /// The value of an IPv6 Router Alert Header Option.
    ///
    /// Router Alert options always contain exactly one `u16`; see [RFC 2711 § 2.1].
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub enum RouterAlert(u16) {
        /// The packet contains a Multicast Listener Discovery message.
        MulticastListenerDiscovery = 0,
        /// The packet contains an RSVP message.
        Rsvp = 1,
        /// The packet contains an Active Networks message.
        ActiveNetworks = 2,
    }
}

impl RouterAlert {
    /// Per [RFC 2711 § 2.1], Router Alert options always have 2 bytes of data.
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub const DATA_LEN: u8 = 2;
}

/// The action required of a node that does not recognize an option, from the two
/// highest-order bits of the option type (RFC 8200 §4.2).
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OptionFailureAction {
    /// Skip the option and continue processing the header.
    Skip,
    /// Discard the packet silently.
    Discard,
    /// Discard the packet and send an ICMP Parameter Problem error.
    DiscardSendError,
    /// Discard the packet and send an ICMP Parameter Problem error, but only if
    /// the packet's destination was not a multicast address.
    DiscardSendErrorIfUnicast,
}

impl OptionType {
    /// The action required if this option is not recognized.
    pub fn failure_action(&self) -> OptionFailureAction {
        match self.0 >> 6 {
            0b00 => OptionFailureAction::Skip,
            0b01 => OptionFailureAction::Discard,
            0b10 => OptionFailureAction::DiscardSendError,
            0b11 => OptionFailureAction::DiscardSendErrorIfUnicast,
            _ => unreachable!(),
        }
    }
}

/// An iterator over TLV-encoded IPv6 options, yielding
/// `(offset, option type, option data)`. The offset is of the option's first
/// byte, relative to the start of the options.
///
/// A malformed option (a length overrunning the buffer) yields one `Err` and
/// then ends the iteration.
pub struct OptionsIter<'a> {
    options: &'a [u8],
    offset: usize,
}

impl<'a> OptionsIter<'a> {
    /// Iterate over the options in an [`ExtHeader::data`] slice.
    pub fn new(options: &'a [u8]) -> Self {
        Self { options, offset: 0 }
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<(usize, OptionType, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.options.len() {
            return None;
        }
        let offset = self.offset;
        let option_type = OptionType::from(self.options[offset]);
        if option_type == OptionType::Pad1 {
            // Pad1 is a bare type byte, with no length or data.
            self.offset = offset + 1;
            return Some(Ok((offset, option_type, &[][..])));
        }
        let data = self
            .options
            .get(offset + 1)
            .and_then(|&len| self.options.get(offset + 2..offset + 2 + len as usize));
        match data {
            Some(data) => {
                self.offset = offset + 2 + data.len();
                Some(Ok((offset, option_type, data)))
            }
            None => {
                self.offset = usize::MAX;
                Some(Err(Error))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ext_header() {
        // Hop-by-hop: next header UDP, length 0 (8 bytes total), router alert + Pad2.
        let bytes = [0x11, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
        let header = ExtHeader::new_checked(&bytes).unwrap();
        assert_eq!(header.next_header(), Protocol::Udp);
        assert_eq!(header.header_len(), 8);
        assert_eq!(header.data(), &bytes[2..8]);

        let options: Vec<_> = OptionsIter::new(header.data()).map(Result::unwrap).collect();
        assert_eq!(
            options,
            vec![
                (0, OptionType::RouterAlert, &bytes[4..6]),
                (4, OptionType::PadN, &bytes[8..8]),
            ]
        );

        // Too short for the length it claims.
        assert_eq!(ExtHeader::new_checked(&bytes[..7]), Err(Error));
        assert_eq!(ExtHeader::new_checked(&[0x11]), Err(Error));
    }

    #[test]
    fn test_options_pad1_and_malformed() {
        // Pad1, then an option whose length overruns the buffer.
        let options = [0x00, 0x02, 0x40];
        let mut iter = OptionsIter::new(&options);
        assert_eq!(iter.next(), Some(Ok((0, OptionType::Pad1, &[][..]))));
        assert_eq!(iter.next(), Some(Err(Error)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_failure_action() {
        assert_eq!(OptionType(0x02).failure_action(), OptionFailureAction::Skip);
        assert_eq!(OptionType(0x42).failure_action(), OptionFailureAction::Discard);
        assert_eq!(OptionType(0x82).failure_action(), OptionFailureAction::DiscardSendError);
        assert_eq!(
            OptionType(0xc2).failure_action(),
            OptionFailureAction::DiscardSendErrorIfUnicast
        );
    }
}
