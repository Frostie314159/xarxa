//! The network stack.

use crate::buf::PacketBuf;
use crate::phy::{Medium, Phy};
use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                net_trace!("iface: malformed ingress packet");
                return Default::default();
            }
        }
    };
}

/// Configuration for a [`Stack`].
pub struct Config {
    /// Hardware (MAC) address of the stack.
    ///
    /// Used on [`Medium::Ethernet`] phys, ignored on [`Medium::Ip`] phys.
    pub hardware_addr: EthernetAddress,

    /// IP addresses of the stack.
    pub ip_addrs: Vec<IpCidr>,
}

/// A network stack.
pub struct Stack {
    inner: StackInner,
    phys: Vec<Box<dyn Phy>>,
}

/// The device-independent part of the stack.
///
/// Separate from `Stack` so that its methods can borrow a phy from `Stack::phys`
/// while taking `&mut self`.
struct StackInner {
    hardware_addr: EthernetAddress,
    ip_addrs: Vec<IpCidr>,
}

impl Stack {
    /// Create a network stack with the given configuration and no phys.
    pub fn new(config: Config) -> Self {
        Self {
            inner: StackInner {
                hardware_addr: config.hardware_addr,
                ip_addrs: config.ip_addrs,
            },
            phys: Vec::new(),
        }
    }

    /// Add a phy to the stack.
    pub fn add_phy(&mut self, phy: Box<dyn Phy>) {
        self.phys.push(phy);
    }

    /// Process all pending ingress packets on all phys.
    ///
    /// Returns `true` if any packets were processed.
    pub fn poll(&mut self) -> bool {
        let mut processed = false;
        for phy in self.phys.iter_mut() {
            while let Some(buf) = phy.receive() {
                processed = true;
                self.inner.process(&mut **phy, buf);
            }
        }
        processed
    }
}

impl StackInner {
    fn process(&mut self, phy: &mut dyn Phy, buf: PacketBuf) {
        match phy.capabilities().medium {
            Medium::Ethernet => self.process_ethernet(phy, buf),
            Medium::Ip => self.process_ip(phy, buf),
        }
    }

    fn process_ethernet(&mut self, phy: &mut dyn Phy, mut buf: PacketBuf) {
        let eth_frame = check!(EthernetFrame::new_checked(buf.payload_mut()));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != self.hardware_addr
        {
            return;
        }

        let src_addr = eth_frame.src_addr();
        let ethertype = eth_frame.ethertype();
        buf.pull_front(ETHERNET_HEADER_LEN);

        match ethertype {
            EthernetProtocol::Arp => self.process_arp(phy, buf),
            EthernetProtocol::Ipv4 => self.process_ipv4(phy, Some(src_addr), buf),
            EthernetProtocol::Ipv6 => self.process_ipv6(phy, Some(src_addr), buf),
            // Drop all other traffic.
            _ => {}
        }
    }

    fn process_ip(&mut self, phy: &mut dyn Phy, buf: PacketBuf) {
        if buf.is_empty() {
            return;
        }
        match IpVersion::of_packet(buf.payload()) {
            Ok(IpVersion::Ipv4) => self.process_ipv4(phy, None, buf),
            Ok(IpVersion::Ipv6) => self.process_ipv6(phy, None, buf),
            Err(_) => {}
        }
    }

    fn process_arp(&mut self, phy: &mut dyn Phy, mut buf: PacketBuf) {
        let arp_packet = check!(ArpPacket::new_checked(buf.payload_mut()));

        if arp_packet.hardware_type() != ArpHardware::Ethernet
            || arp_packet.protocol_type() != EthernetProtocol::Ipv4
            || arp_packet.hardware_len() != 6
            || arp_packet.protocol_len() != 4
        {
            return;
        }

        let operation = arp_packet.operation();
        let source_hardware_addr = EthernetAddress::from_bytes(arp_packet.source_hardware_addr());
        let source_protocol_addr = Ipv4Address::from(<[u8; 4]>::try_from(arp_packet.source_protocol_addr()).unwrap());
        let target_protocol_addr = Ipv4Address::from(<[u8; 4]>::try_from(arp_packet.target_protocol_addr()).unwrap());

        // Only process ARP packets for us.
        if !self.has_ip_addr(target_protocol_addr) {
            return;
        }

        // Only process REQUEST and RESPONSE.
        if let ArpOperation::Unknown(_) = operation {
            net_debug!("arp: unknown operation code");
            return;
        }

        // Discard packets with non-unicast source addresses.
        if !source_protocol_addr.x_is_unicast() || !source_hardware_addr.is_unicast() {
            net_debug!("arp: non-unicast source address");
            return;
        }

        if !self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
            net_debug!("arp: source IP address not in same network as us");
            return;
        }

        if operation == ArpOperation::Request {
            let mut reply = PacketBuf::new();
            reply.reserve(ETHERNET_HEADER_LEN);
            reply.set_len(ARP_BUFFER_LEN);
            {
                let mut arp_reply = ArpPacket::new_unchecked(reply.payload_mut());
                arp_reply.set_hardware_type(ArpHardware::Ethernet);
                arp_reply.set_protocol_type(EthernetProtocol::Ipv4);
                arp_reply.set_hardware_len(6);
                arp_reply.set_protocol_len(4);
                arp_reply.set_operation(ArpOperation::Reply);
                arp_reply.set_source_hardware_addr(self.hardware_addr.as_bytes());
                arp_reply.set_source_protocol_addr(&target_protocol_addr.octets());
                arp_reply.set_target_hardware_addr(source_hardware_addr.as_bytes());
                arp_reply.set_target_protocol_addr(&source_protocol_addr.octets());
            }
            self.transmit_frame(phy, Some(source_hardware_addr), reply, EthernetProtocol::Arp);
        }
    }

    fn process_ipv4(&mut self, phy: &mut dyn Phy, eth_src: Option<EthernetAddress>, mut buf: PacketBuf) {
        let ipv4_packet = check!(Ipv4Packet::new_checked(buf.payload_mut()));

        if ipv4_packet.version() != 4 {
            return;
        }
        if !ipv4_packet.verify_checksum() {
            net_trace!("ipv4: header checksum incorrect");
            return;
        }
        if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
            net_trace!("ipv4: fragmented packets not supported yet");
            return;
        }

        let src_addr = ipv4_packet.src_addr();
        let dst_addr = ipv4_packet.dst_addr();
        let next_header = ipv4_packet.next_header();
        let header_len = ipv4_packet.header_len() as usize;
        let total_len = ipv4_packet.total_len() as usize;

        if !self.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
            // Discard packets with non-unicast source addresses but allow unspecified
            net_debug!("non-unicast or unspecified source address");
            return;
        }

        if !self.has_ip_addr(dst_addr) && !self.is_broadcast_v4(dst_addr) {
            // Ignore IP packets not directed at us, or broadcast.
            net_trace!("Rejecting IPv4 packet; not for us");
            return;
        }

        // Strip the IP header and any trailing padding added by the link layer.
        buf.set_len(total_len);
        buf.pull_front(header_len);

        match next_header {
            IpProtocol::Icmp => self.process_icmpv4(phy, eth_src, src_addr, dst_addr, buf),
            _ => {
                net_trace!("ipv4: protocol {} not supported", next_header);
            }
        }
    }

    fn process_icmpv4(
        &mut self,
        phy: &mut dyn Phy,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        mut buf: PacketBuf,
    ) {
        let icmp_packet = check!(Icmpv4Packet::new_checked(buf.payload_mut()));
        if !icmp_packet.verify_checksum() {
            net_trace!("icmpv4: checksum incorrect");
            return;
        }

        match (icmp_packet.msg_type(), icmp_packet.msg_code()) {
            // Respond to echo requests.
            (Icmpv4Message::EchoRequest, 0) => {
                // Do not send ICMP replies to non-unicast sources.
                if !self.is_unicast_v4(src_addr) {
                    return;
                }
                // Reply as normal when src_addr and dst_addr are both unicast; only
                // reply to broadcasts for echo replies and not other ICMP messages.
                let reply_src = if self.is_unicast_v4(dst_addr) {
                    dst_addr
                } else if self.is_broadcast_v4(dst_addr) {
                    match self.ipv4_addr() {
                        Some(addr) => addr,
                        None => return,
                    }
                } else {
                    return;
                };

                let mut reply = PacketBuf::new();
                reply.reserve(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN);
                reply.set_len(icmp_packet.header_len() + icmp_packet.data().len());
                {
                    let mut reply_icmp = Icmpv4Packet::new_unchecked(reply.payload_mut());
                    reply_icmp.set_msg_type(Icmpv4Message::EchoReply);
                    reply_icmp.set_msg_code(0);
                    reply_icmp.set_echo_ident(icmp_packet.echo_ident());
                    reply_icmp.set_echo_seq_no(icmp_packet.echo_seq_no());
                    reply_icmp.data_mut().copy_from_slice(icmp_packet.data());
                    reply_icmp.fill_checksum();
                }
                self.transmit_ipv4(phy, eth_src, reply, reply_src, src_addr, IpProtocol::Icmp, 64);
            }

            // Ignore any echo replies.
            (Icmpv4Message::EchoReply, _) => {}

            _ => {}
        }
    }

    fn process_ipv6(&mut self, phy: &mut dyn Phy, eth_src: Option<EthernetAddress>, mut buf: PacketBuf) {
        let ipv6_packet = check!(Ipv6Packet::new_checked(buf.payload_mut()));

        if ipv6_packet.version() != 6 {
            return;
        }

        let src_addr = ipv6_packet.src_addr();
        let dst_addr = ipv6_packet.dst_addr();
        let hop_limit = ipv6_packet.hop_limit();
        let next_header = ipv6_packet.next_header();
        let payload_len = ipv6_packet.payload_len() as usize;

        if !src_addr.x_is_unicast() {
            // Discard packets with non-unicast source addresses.
            net_debug!("non-unicast source address");
            return;
        }

        if !self.has_ip_addr(dst_addr) && !self.has_multicast_group(dst_addr) && !dst_addr.is_loopback() {
            net_trace!("Rejecting IPv6 packet; not for us");
            return;
        }

        // Strip the IP header and any trailing padding added by the link layer.
        buf.set_len(IPV6_HEADER_LEN + payload_len);
        buf.pull_front(IPV6_HEADER_LEN);

        match next_header {
            IpProtocol::Icmpv6 => self.process_icmpv6(phy, eth_src, src_addr, dst_addr, hop_limit, buf),
            _ => {
                net_trace!("ipv6: protocol {} not supported", next_header);
            }
        }
    }

    fn process_icmpv6(
        &mut self,
        phy: &mut dyn Phy,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
        mut buf: PacketBuf,
    ) {
        let mut icmp_packet = check!(Icmpv6Packet::new_checked(buf.payload_mut()));
        if !icmp_packet.verify_checksum(&src_addr, &dst_addr) {
            net_trace!("icmpv6: checksum incorrect");
            return;
        }

        match icmp_packet.msg_type() {
            // Respond to echo requests.
            Icmpv6Message::EchoRequest => {
                let reply_src = if dst_addr.x_is_unicast() {
                    dst_addr
                } else {
                    self.get_source_address_ipv6(&src_addr)
                };

                let mut reply = PacketBuf::new();
                reply.reserve(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN);
                reply.set_len(icmp_packet.header_len() + icmp_packet.payload().len());
                {
                    let mut reply_icmp = Icmpv6Packet::new_unchecked(reply.payload_mut());
                    reply_icmp.set_msg_type(Icmpv6Message::EchoReply);
                    reply_icmp.set_msg_code(0);
                    reply_icmp.set_echo_ident(icmp_packet.echo_ident());
                    reply_icmp.set_echo_seq_no(icmp_packet.echo_seq_no());
                    reply_icmp.payload_mut().copy_from_slice(icmp_packet.payload());
                    reply_icmp.fill_checksum(&reply_src, &src_addr);
                }
                self.transmit_ipv6(phy, eth_src, reply, reply_src, src_addr, 64);
            }

            // Ignore any echo replies.
            Icmpv6Message::EchoReply => {}

            // NDISC is only processed if the packet arrived with the un-decremented
            // hop limit, and only on Ethernet mediums.
            Icmpv6Message::NeighborSolicit if hop_limit == 0xff && eth_src.is_some() => {
                self.process_ndisc_solicit(phy, eth_src, src_addr, dst_addr, &mut icmp_packet)
            }

            _ => {}
        }
    }

    fn process_ndisc_solicit(
        &mut self,
        phy: &mut dyn Phy,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let target_addr = icmp_packet.target_addr();

        // Parse the NDISC options, looking for the source link-layer address.
        let mut lladdr = None;
        let options = icmp_packet.payload_mut();
        let mut offset = 0;
        while offset < options.len() {
            let opt = check!(NdiscOption::new_checked(&mut options[offset..]));
            let opt_len = opt.data_len() as usize * 8;
            if opt_len == 0 {
                net_trace!("ndisc: option with zero length");
                return;
            }
            if opt.option_type() == NdiscOptionType::SourceLinkLayerAddr {
                lladdr = Some(opt.link_layer_addr());
            }
            offset += opt_len;
        }

        if let Some(lladdr) = lladdr {
            let lladdr = check!(lladdr.parse_ethernet());
            if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
                return;
            }
        }

        if self.has_solicited_node(dst_addr) && self.has_ip_addr(target_addr) {
            // Neighbor advert: NA header (24 bytes) plus the target link-layer
            // address option (8 bytes).
            let mut reply = PacketBuf::new();
            reply.reserve(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN);
            reply.set_len(24 + 8);
            {
                let mut na = Icmpv6Packet::new_unchecked(reply.payload_mut());
                na.set_msg_type(Icmpv6Message::NeighborAdvert);
                na.set_msg_code(0);
                na.clear_reserved();
                na.set_neighbor_flags(NdiscNeighborFlags::SOLICITED);
                na.set_target_addr(target_addr);
                {
                    let mut opt = NdiscOption::new_unchecked(na.payload_mut());
                    opt.set_option_type(NdiscOptionType::TargetLinkLayerAddr);
                    opt.set_data_len(1);
                    opt.set_link_layer_addr(RawHardwareAddress::from(self.hardware_addr));
                }
                na.fill_checksum(&target_addr, &src_addr);
            }
            self.transmit_ipv6(phy, eth_src, reply, target_addr, src_addr, 0xff);
        }
    }

    fn transmit_ipv4(
        &self,
        phy: &mut dyn Phy,
        dst_hw: Option<EthernetAddress>,
        mut buf: PacketBuf,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let payload_len = buf.len();
        buf.push_front(IPV4_HEADER_LEN);
        {
            let mut packet = Ipv4Packet::new_unchecked(buf.payload_mut());
            packet.set_version(4);
            packet.set_header_len(IPV4_HEADER_LEN as u8);
            packet.set_dscp(0);
            packet.set_ecn(0);
            packet.set_total_len((IPV4_HEADER_LEN + payload_len) as u16);
            packet.set_ident(0);
            packet.clear_flags();
            packet.set_more_frags(false);
            packet.set_dont_frag(true);
            packet.set_frag_offset(0);
            packet.set_hop_limit(hop_limit);
            packet.set_next_header(next_header);
            packet.set_src_addr(src_addr);
            packet.set_dst_addr(dst_addr);
            packet.fill_checksum();
        }
        self.transmit_frame(phy, dst_hw, buf, EthernetProtocol::Ipv4);
    }

    fn transmit_ipv6(
        &self,
        phy: &mut dyn Phy,
        dst_hw: Option<EthernetAddress>,
        mut buf: PacketBuf,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
    ) {
        let payload_len = buf.len();
        buf.push_front(IPV6_HEADER_LEN);
        {
            let mut packet = Ipv6Packet::new_unchecked(buf.payload_mut());
            packet.set_version(6);
            packet.set_traffic_class(0);
            packet.set_flow_label(0);
            packet.set_payload_len(payload_len as u16);
            packet.set_next_header(IpProtocol::Icmpv6);
            packet.set_hop_limit(hop_limit);
            packet.set_src_addr(src_addr);
            packet.set_dst_addr(dst_addr);
        }
        self.transmit_frame(phy, dst_hw, buf, EthernetProtocol::Ipv6);
    }

    fn transmit_frame(
        &self,
        phy: &mut dyn Phy,
        dst_hw: Option<EthernetAddress>,
        mut buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        match phy.capabilities().medium {
            Medium::Ethernet => {
                let Some(dst_hw) = dst_hw else {
                    net_debug!("no destination hardware address");
                    return;
                };
                buf.push_front(ETHERNET_HEADER_LEN);
                let mut frame = EthernetFrame::new_unchecked(buf.payload_mut());
                frame.set_dst_addr(dst_hw);
                frame.set_src_addr(self.hardware_addr);
                frame.set_ethertype(ethertype);
            }
            Medium::Ip => {}
        }
        if phy.transmit(buf).is_err() {
            net_debug!("phy: cannot transmit, dropping packet");
        }
    }

    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    /// Get the first IPv4 address of the interface.
    fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            _ => None,
        })
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.ip_addrs.iter().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOCALHOST => {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.is_solicited_node_multicast() && addr.octets()[13..] == cidr.address().octets()[13..]
                }
                _ => false,
            }
        })
    }

    /// Check whether the given address is a multicast group the stack has joined.
    ///
    /// The stack implicitly joins the all-nodes multicast group and the solicited
    /// node multicast group of each of its addresses.
    fn has_multicast_group(&self, addr: Ipv6Address) -> bool {
        addr == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(addr)
    }

    /// Return the IPv6 address that is a candidate source address for the given destination
    /// address, based on RFC 6724.
    ///
    /// # Panics
    /// This function panics if the destination address is unspecified.
    fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        assert!(!dst_addr.is_unspecified());

        // See RFC 6724 Section 4: Candidate source address
        fn is_candidate_source_address(dst_addr: &Ipv6Address, src_addr: &Ipv6Address) -> bool {
            // For all multicast and link-local destination addresses, the candidate address MUST
            // only be an address from the same link.
            if dst_addr.is_link_local() && !src_addr.is_link_local() {
                return false;
            }

            if dst_addr.is_multicast()
                && matches!(dst_addr.x_multicast_scope(), Ipv6MulticastScope::LinkLocal)
                && src_addr.is_multicast()
                && !matches!(src_addr.x_multicast_scope(), Ipv6MulticastScope::LinkLocal)
            {
                return false;
            }

            // Unspecified addresses and multicast address can not be in the candidate source address
            // list. Except when the destination multicast address has a link-local scope, then the
            // source address can also be link-local multicast.
            if src_addr.is_unspecified() || src_addr.is_multicast() {
                return false;
            }

            true
        }

        // See RFC 6724 Section 2.2: Common Prefix Length
        fn common_prefix_length(dst_addr: &Ipv6Cidr, src_addr: &Ipv6Address) -> usize {
            let addr = dst_addr.address();
            let mut bits = 0;
            for (l, r) in addr.octets().iter().zip(src_addr.octets().iter()) {
                if l == r {
                    bits += 8;
                } else {
                    bits += (l ^ r).leading_zeros();
                    break;
                }
            }

            bits = bits.min(dst_addr.prefix_len() as u32);

            bits as usize
        }

        // If the destination address is a loopback address, or when there are no IPv6 addresses in
        // the interface, then the loopback address is the only candidate source address.
        if dst_addr.is_loopback() || self.ip_addrs.iter().filter(|a| matches!(a, IpCidr::Ipv6(_))).count() == 0 {
            return Ipv6Address::LOCALHOST;
        }

        let mut candidate = self
            .ip_addrs
            .iter()
            .find_map(|a| match a {
                IpCidr::Ipv4(_) => None,
                IpCidr::Ipv6(a) => Some(a),
            })
            .unwrap(); // NOTE: we check above that there is at least one IPv6 address.

        for addr in self.ip_addrs.iter().filter_map(|a| match a {
            IpCidr::Ipv4(_) => None,
            IpCidr::Ipv6(a) => Some(a),
        }) {
            if !is_candidate_source_address(dst_addr, &addr.address()) {
                continue;
            }

            // Rule 1: prefer the address that is the same as the output destination address.
            if candidate.address() != *dst_addr && addr.address() == *dst_addr {
                candidate = addr;
            }

            // Rule 2: prefer appropriate scope.
            if (candidate.address().x_multicast_scope() as u8) < (addr.address().x_multicast_scope() as u8) {
                if (candidate.address().x_multicast_scope() as u8) < (dst_addr.x_multicast_scope() as u8) {
                    candidate = addr;
                }
            } else if (addr.address().x_multicast_scope() as u8) > (dst_addr.x_multicast_scope() as u8) {
                candidate = addr;
            }

            // Rule 3: avoid deprecated addresses (TODO)
            // Rule 4: prefer home addresses (TODO)
            // Rule 5: prefer outgoing interfaces (TODO)
            // Rule 5.5: prefer addresses in a prefix advertises by the next-hop (TODO).
            // Rule 6: prefer matching label (TODO)
            // Rule 7: prefer temporary addresses (TODO)
            // Rule 8: use longest matching prefix
            if common_prefix_length(candidate, dst_addr) < common_prefix_length(addr, dst_addr) {
                candidate = addr;
            }
        }

        candidate.address()
    }
}
