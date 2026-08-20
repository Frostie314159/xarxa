//! Decode a packet and log it, one line per header.
//!
//! [`log_packet`] walks the headers of a packet with the `wire` parsers and logs
//! each one at trace level. Nothing is logged without the `log` or `defmt`
//! feature.
//!
//! With the `packet-log` feature, the stack calls it on every packet it receives
//! and sends.

use crate::PacketBuf;
#[cfg(feature = "udp")]
use crate::wire::UdpPacket;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
use crate::wire::{ArpHardware, ArpPacket, EthernetAddress, Ipv4Address};
#[cfg(feature = "dns")]
use crate::wire::{DnsFlags, DnsPacket, DnsQuestion, DnsRecord, DnsRecordData};
#[cfg(feature = "medium-ethernet")]
use crate::wire::{EthernetFrame, EthernetProtocol};
#[cfg(feature = "ipv4")]
use crate::wire::{
    Icmpv4DstUnreachable, Icmpv4Message, Icmpv4Packet, Icmpv4ParamProblem, Icmpv4Redirect, Icmpv4TimeExceeded,
    Ipv4Packet,
};
#[cfg(feature = "ipv6")]
use crate::wire::{
    Icmpv6DstUnreachable, Icmpv6Message, Icmpv6Packet, Icmpv6ParamProblem, Icmpv6TimeExceeded, Ipv6ExtHeader,
    Ipv6OptionsIter, Ipv6Packet,
};
use crate::wire::{IpProtocol, IpVersion};
#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
use crate::wire::{NdiscOption, NdiscOptionType};
#[cfg(feature = "tcp")]
use crate::wire::{TcpOption, TcpPacket};

/// The outermost header of a packet given to [`log_packet`].
#[allow(unused)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// An Ethernet frame. Requires the `medium-ethernet` feature.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,
    /// An IP packet of either version. The version is read from the first byte.
    Ip,
    /// An IPv4 packet. Requires the `ipv4` feature.
    #[cfg(feature = "ipv4")]
    Ipv4,
    /// An IPv6 packet. Requires the `ipv6` feature.
    #[cfg(feature = "ipv6")]
    Ipv6,
    /// An ARP packet. Requires the `medium-ethernet` and `ipv4` features.
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    Arp,
}

/// Log a packet at trace level, one line per header.
///
/// `layer` says what the first header in the packet is. Headers are decoded
/// from there down to the transport layer. A header that fails to parse ends
/// the walk with a line saying so.
///
/// The packet is not modified. The parsers need a mutable slice, which is the
/// only reason this takes `&mut`.
pub fn log_packet(buf: &mut PacketBuf, layer: Layer) {
    log_layer(&mut buf[..], layer);
}

fn log_layer(buf: &mut [u8], layer: Layer) {
    match layer {
        #[cfg(feature = "medium-ethernet")]
        Layer::Ethernet => log_ethernet(buf),
        Layer::Ip => log_ip(buf),
        #[cfg(feature = "ipv4")]
        Layer::Ipv4 => log_ipv4(buf),
        #[cfg(feature = "ipv6")]
        Layer::Ipv6 => log_ipv6(buf),
        #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
        Layer::Arp => log_arp(buf),
    }
}

#[cfg(feature = "medium-ethernet")]
fn log_ethernet(buf: &mut [u8]) {
    let mut frame = match EthernetFrame::new_checked(buf) {
        Ok(f) => f,
        Err(_) => {
            trace!("Ethernet: malformed");
            return;
        }
    };
    let ethertype = frame.ethertype();
    trace!(
        "Ethernet src={} dst={} type={}",
        frame.src_addr(),
        frame.dst_addr(),
        ethertype
    );
    let payload = frame.payload_mut();
    match ethertype {
        #[cfg(feature = "ipv4")]
        EthernetProtocol::Ipv4 => log_ipv4(payload),
        #[cfg(feature = "ipv6")]
        EthernetProtocol::Ipv6 => log_ipv6(payload),
        #[cfg(feature = "ipv4")]
        EthernetProtocol::Arp => log_arp(payload),
        _ => trace!("payload len={}", payload.len()),
    }
}

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
fn log_arp(buf: &mut [u8]) {
    let packet = match ArpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ARP: malformed");
            return;
        }
    };
    if packet.hardware_type() == ArpHardware::Ethernet
        && packet.protocol_type() == EthernetProtocol::Ipv4
        && packet.hardware_len() == 6
        && packet.protocol_len() == 4
    {
        let ip = |b: &[u8]| Ipv4Address::new(b[0], b[1], b[2], b[3]);
        trace!(
            "ARP op={} sha={} spa={} tha={} tpa={}",
            packet.operation(),
            EthernetAddress::from_bytes(packet.source_hardware_addr()),
            ip(packet.source_protocol_addr()),
            EthernetAddress::from_bytes(packet.target_hardware_addr()),
            ip(packet.target_protocol_addr()),
        );
    } else {
        trace!(
            "ARP op={} hw={} proto={} hlen={} plen={}",
            packet.operation(),
            packet.hardware_type(),
            packet.protocol_type(),
            packet.hardware_len(),
            packet.protocol_len(),
        );
    }
}

fn log_ip(buf: &mut [u8]) {
    if buf.is_empty() {
        trace!("IP: empty");
        return;
    }
    match IpVersion::of_packet(buf) {
        #[cfg(feature = "ipv4")]
        Ok(IpVersion::Ipv4) => log_ipv4(buf),
        #[cfg(feature = "ipv6")]
        Ok(IpVersion::Ipv6) => log_ipv6(buf),
        #[allow(unreachable_patterns)]
        _ => trace!("IP: unknown version, len={}", buf.len()),
    }
}

#[cfg(feature = "ipv4")]
fn log_ipv4(buf: &mut [u8]) {
    let mut packet = match Ipv4Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("IPv4: malformed");
            return;
        }
    };
    let proto = packet.next_header();
    let fragment = packet.more_frags() || packet.frag_offset() != 0;
    trace!(
        "IPv4 src={} dst={} proto={} len={} ttl={} id={} dscp={} ecn={} df={} mf={} off={}",
        packet.src_addr(),
        packet.dst_addr(),
        proto,
        packet.total_len(),
        packet.hop_limit(),
        packet.ident(),
        packet.dscp(),
        packet.ecn(),
        packet.dont_frag(),
        packet.more_frags(),
        packet.frag_offset(),
    );
    let payload = packet.payload_mut();
    if fragment {
        trace!("fragment len={}", payload.len());
        return;
    }
    log_transport(proto, IpVersion::Ipv4, payload);
}

#[cfg(feature = "ipv6")]
fn log_ipv6(buf: &mut [u8]) {
    let mut packet = match Ipv6Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("IPv6: malformed");
            return;
        }
    };
    let mut proto = packet.next_header();
    trace!(
        "IPv6 src={} dst={} nh={} plen={} hlim={} tc={} fl={}",
        packet.src_addr(),
        packet.dst_addr(),
        proto,
        packet.payload_len(),
        packet.hop_limit(),
        packet.traffic_class(),
        packet.flow_label(),
    );
    let mut payload = packet.payload_mut();

    // Walk the extension headers. They all share the (next header, length) prefix,
    // except that only Hop-by-Hop and Destination Options carry TLV options.
    loop {
        let has_options = match proto {
            IpProtocol::HopByHop | IpProtocol::Ipv6Opts => true,
            IpProtocol::Ipv6Route | IpProtocol::Ipv6Frag => false,
            _ => break,
        };
        let ext = match Ipv6ExtHeader::new_checked(payload) {
            Ok(e) => e,
            Err(_) => {
                trace!("{}: malformed", proto);
                return;
            }
        };
        let next = ext.next_header();
        let len = ext.header_len();
        trace!("{} next={} len={}", proto, next, len);
        if has_options {
            for opt in Ipv6OptionsIter::new(ext.data()) {
                match opt {
                    Ok((_, ty, data)) => trace!("  option type={} len={}", ty, data.len()),
                    Err(_) => {
                        trace!("  option: malformed");
                        return;
                    }
                }
            }
        }
        proto = next;
        payload = &mut payload[len..];
    }

    log_transport(proto, IpVersion::Ipv6, payload);
}

fn log_transport(proto: IpProtocol, version: IpVersion, payload: &mut [u8]) {
    match (proto, version) {
        #[cfg(feature = "udp")]
        (IpProtocol::Udp, _) => log_udp(payload),
        #[cfg(feature = "tcp")]
        (IpProtocol::Tcp, _) => log_tcp(payload),
        #[cfg(feature = "ipv4")]
        (IpProtocol::Icmp, IpVersion::Ipv4) => log_icmpv4(payload),
        #[cfg(feature = "ipv6")]
        (IpProtocol::Icmpv6, IpVersion::Ipv6) => log_icmpv6(payload),
        (IpProtocol::Ipv6NoNxt, _) => {}
        _ => trace!("{} payload len={}", proto, payload.len()),
    }
}

#[cfg(feature = "udp")]
fn log_udp(buf: &mut [u8]) {
    #[allow(unused_mut)]
    let mut p = match UdpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("UDP: malformed");
            return;
        }
    };
    trace!(
        "UDP src={} dst={} len={} payload={}",
        p.src_port(),
        p.dst_port(),
        p.len(),
        p.payload().len()
    );
    #[cfg(feature = "dns")]
    if [p.src_port(), p.dst_port()]
        .iter()
        .any(|&port| port == 53 || port == 5353)
    {
        log_dns(p.payload_mut());
    }
}

/// A DNS name in dotted text form, for logging. Labels are copied into a
/// fixed buffer so the name can be printed as one `str`.
#[cfg(feature = "dns")]
struct DnsName {
    buf: [u8; 255],
    len: usize,
}

#[cfg(feature = "dns")]
impl DnsName {
    fn parse(packet: &DnsPacket<'_>, name: &[u8]) -> Option<Self> {
        let mut out = Self { buf: [0; 255], len: 0 };
        for label in packet.parse_name(name) {
            let label = label.ok()?;
            if out.len + label.len() + 1 > out.buf.len() {
                return None;
            }
            out.buf[out.len..out.len + label.len()].copy_from_slice(label);
            out.len += label.len();
            out.buf[out.len] = b'.';
            out.len += 1;
        }
        Some(out)
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<non-utf8>")
    }
}

#[cfg(feature = "dns")]
fn log_dns(buf: &mut [u8]) {
    let packet = match DnsPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("DNS: malformed");
            return;
        }
    };
    trace!(
        "DNS id={:#06x} {} op={} rcode={} flags={:?} qd={} an={} ns={} ar={}",
        packet.transaction_id(),
        if packet.flags().contains(DnsFlags::RESPONSE) {
            "response"
        } else {
            "query"
        },
        packet.opcode(),
        packet.rcode(),
        packet.flags(),
        packet.question_count(),
        packet.answer_record_count(),
        packet.authority_record_count(),
        packet.additional_record_count(),
    );

    let mut payload = packet.payload();
    for _ in 0..packet.question_count() {
        let (rest, q) = match DnsQuestion::parse(payload) {
            Ok(x) => x,
            Err(_) => {
                trace!("  question: malformed");
                return;
            }
        };
        payload = rest;
        match DnsName::parse(&packet, q.name) {
            Some(name) => trace!("  question {} type={}", name.as_str(), q.type_),
            None => trace!("  question <malformed name> type={}", q.type_),
        }
    }

    for (section, count) in [
        ("answer", packet.answer_record_count()),
        ("authority", packet.authority_record_count()),
        ("additional", packet.additional_record_count()),
    ] {
        for _ in 0..count {
            let (rest, r) = match DnsRecord::parse(payload) {
                Ok(x) => x,
                Err(_) => {
                    trace!("  {}: malformed", section);
                    return;
                }
            };
            payload = rest;
            let name = DnsName::parse(&packet, r.name);
            let name = name.as_ref().map(DnsName::as_str).unwrap_or("<malformed name>");
            match r.data {
                #[cfg(feature = "ipv4")]
                DnsRecordData::A(addr) => trace!("  {} {} ttl={} A {}", section, name, r.ttl, addr),
                #[cfg(feature = "ipv6")]
                DnsRecordData::Aaaa(addr) => trace!("  {} {} ttl={} AAAA {}", section, name, r.ttl, addr),
                DnsRecordData::Cname(cname) => match DnsName::parse(&packet, cname) {
                    Some(cname) => trace!("  {} {} ttl={} CNAME {}", section, name, r.ttl, cname.as_str()),
                    None => trace!("  {} {} ttl={} CNAME <malformed name>", section, name, r.ttl),
                },
                DnsRecordData::Other(ty, data) => {
                    trace!("  {} {} ttl={} type={} len={}", section, name, r.ttl, ty, data.len())
                }
            }
        }
    }
}

#[cfg(feature = "tcp")]
fn log_tcp(buf: &mut [u8]) {
    let packet = match TcpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("TCP: malformed");
            return;
        }
    };

    // Flags as a short letter string, e.g. "SA" for SYN|ACK.
    let mut flags = [0u8; 9];
    let mut n = 0;
    for (set, letter) in [
        (packet.fin(), b'F'),
        (packet.syn(), b'S'),
        (packet.rst(), b'R'),
        (packet.psh(), b'P'),
        (packet.ack(), b'A'),
        (packet.urg(), b'U'),
        (packet.ece(), b'E'),
        (packet.cwr(), b'C'),
        (packet.ns(), b'N'),
    ] {
        if set {
            flags[n] = letter;
            n += 1;
        }
    }
    let flags = core::str::from_utf8(&flags[..n]).unwrap_or("");

    trace!(
        "TCP src={} dst={} flags={} seq={} ack={} win={} urg={} payload={}",
        packet.src_port(),
        packet.dst_port(),
        flags,
        packet.seq_number(),
        packet.ack_number(),
        packet.window_len(),
        packet.urgent_at(),
        packet.payload().len(),
    );

    let mut options = packet.options();
    while !options.is_empty() {
        let (rest, option) = match TcpOption::parse(options) {
            Ok(x) => x,
            Err(_) => {
                trace!("  option: malformed");
                return;
            }
        };
        match option {
            TcpOption::EndOfList => break,
            TcpOption::NoOperation => {}
            option => trace!("  option {:?}", option),
        }
        options = rest;
    }
}

#[cfg(feature = "ipv4")]
fn log_icmpv4(buf: &mut [u8]) {
    let mut packet = match Icmpv4Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ICMPv4: malformed");
            return;
        }
    };
    let ty = packet.msg_type();
    let code = packet.msg_code();
    match ty {
        Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply => trace!(
            "ICMPv4 type={} ident={} seq={} payload={}",
            ty,
            packet.echo_ident(),
            packet.echo_seq_no(),
            packet.data().len()
        ),
        Icmpv4Message::DstUnreachable => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4DstUnreachable::from(code))
        }
        Icmpv4Message::Redirect => trace!("ICMPv4 type={} code={}", ty, Icmpv4Redirect::from(code)),
        Icmpv4Message::TimeExceeded => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4TimeExceeded::from(code))
        }
        Icmpv4Message::ParamProblem => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4ParamProblem::from(code))
        }
        _ => trace!("ICMPv4 type={} code={} payload={}", ty, code, packet.data().len()),
    }
    if ty.is_error() {
        log_ipv4(packet.data_mut());
    }
}

#[cfg(feature = "ipv6")]
fn log_icmpv6(buf: &mut [u8]) {
    let mut packet = match Icmpv6Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ICMPv6: malformed");
            return;
        }
    };
    let ty = packet.msg_type();
    let code = packet.msg_code();
    match ty {
        Icmpv6Message::EchoRequest | Icmpv6Message::EchoReply => trace!(
            "ICMPv6 type={} ident={} seq={} payload={}",
            ty,
            packet.echo_ident(),
            packet.echo_seq_no(),
            packet.payload().len()
        ),
        Icmpv6Message::DstUnreachable => {
            trace!("ICMPv6 type={} code={}", ty, Icmpv6DstUnreachable::from(code))
        }
        Icmpv6Message::PktTooBig => trace!("ICMPv6 type={} mtu={}", ty, packet.pkt_too_big_mtu()),
        Icmpv6Message::TimeExceeded => {
            trace!("ICMPv6 type={} code={}", ty, Icmpv6TimeExceeded::from(code))
        }
        Icmpv6Message::ParamProblem => trace!(
            "ICMPv6 type={} code={} ptr={}",
            ty,
            Icmpv6ParamProblem::from(code),
            packet.param_problem_ptr()
        ),
        #[cfg(feature = "medium-ethernet")]
        Icmpv6Message::RouterSolicit => trace!("ICMPv6 type={}", ty),
        #[cfg(feature = "medium-ethernet")]
        Icmpv6Message::RouterAdvert => trace!(
            "ICMPv6 type={} hop_limit={} flags={:?}",
            ty,
            packet.current_hop_limit(),
            packet.router_flags()
        ),
        #[cfg(feature = "medium-ethernet")]
        Icmpv6Message::NeighborSolicit => trace!("ICMPv6 type={} target={}", ty, packet.target_addr()),
        #[cfg(feature = "medium-ethernet")]
        Icmpv6Message::NeighborAdvert => trace!(
            "ICMPv6 type={} target={} flags={:?}",
            ty,
            packet.target_addr(),
            packet.neighbor_flags()
        ),
        #[cfg(feature = "medium-ethernet")]
        Icmpv6Message::Redirect => trace!(
            "ICMPv6 type={} target={} dest={}",
            ty,
            packet.target_addr(),
            packet.dest_addr()
        ),
        _ => trace!("ICMPv6 type={} code={} payload={}", ty, code, packet.payload().len()),
    }

    if ty.is_error() {
        log_ipv6(packet.payload_mut());
        return;
    }

    #[cfg(feature = "medium-ethernet")]
    if matches!(
        ty,
        Icmpv6Message::RouterSolicit
            | Icmpv6Message::RouterAdvert
            | Icmpv6Message::NeighborSolicit
            | Icmpv6Message::NeighborAdvert
            | Icmpv6Message::Redirect
    ) {
        log_ndisc_options(packet.payload_mut());
    }
}

#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
fn log_ndisc_options(mut buf: &mut [u8]) {
    while !buf.is_empty() {
        let opt = match NdiscOption::new_checked(buf) {
            Ok(o) => o,
            Err(_) => {
                trace!("  ndisc option: malformed");
                return;
            }
        };
        let ty = opt.option_type();
        let len = opt.data_len() as usize * 8;
        match ty {
            NdiscOptionType::SourceLinkLayerAddr | NdiscOptionType::TargetLinkLayerAddr => {
                trace!("  ndisc option {} addr={}", ty, opt.link_layer_addr())
            }
            NdiscOptionType::PrefixInformation => trace!(
                "  ndisc option {} prefix={}/{} flags={:?}",
                ty,
                opt.prefix(),
                opt.prefix_len(),
                opt.prefix_flags()
            ),
            NdiscOptionType::Mtu => trace!("  ndisc option {} mtu={}", ty, opt.mtu()),
            _ => trace!("  ndisc option {} len={}", ty, len),
        }
        // `new_checked` guarantees `len <= buf.len()`.
        buf = &mut buf[len..];
    }
}

#[cfg(all(test, feature = "dns", feature = "ipv4"))]
mod test {
    use super::*;

    /// Decoding a CNAME + A response must walk every record without panicking.
    #[test]
    fn test_log_dns() {
        let mut bytes = [
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x08, 0x66,
            0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69,
            0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ];
        log_dns(&mut bytes);
        let packet = DnsPacket::new_checked(&mut bytes).unwrap();
        let name = DnsName::parse(&packet, &[0xc0, 0x2e]).unwrap();
        assert_eq!(name.as_str(), "star-mini.c10r.facebook.com.");
        // Truncated: must report malformed, not panic.
        log_dns(&mut [0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77]);
    }
}
