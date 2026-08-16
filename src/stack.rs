//! The network stack.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::buf::PacketBuf;
use crate::iface::{Interface, Medium};
use crate::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache, PendingQueue, ProbeEvent};
use crate::rand::Rand;
use crate::raw::{RawHandle, RawSocket, RawSocketState};
use crate::route::Routes;
use crate::slab::Slab;
use crate::tcp::{
    PollAt, SocketBuffer, TcpHandle, TcpListener, TcpListenerHandle, TcpListenerState, TcpRepr, TcpSocket,
    TcpSocketState,
};
use crate::time::Instant;
use crate::udp::{UdpHandle, UdpSocket, UdpSocketState};
use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                trace!("iface: malformed ingress packet");
                return Default::default();
            }
        }
    };
}

/// Configuration for an interface added to a [`Stack`].
pub struct Config {
    /// Hardware (MAC) address of the interface.
    ///
    /// Used on [`Medium::Ethernet`] interfaces, ignored on [`Medium::Ip`] interfaces.
    pub hardware_addr: EthernetAddress,

    /// IP addresses of the interface.
    pub ip_addrs: Vec<IpCidr>,
}

/// A handle to an interface added to a [`Stack`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfaceHandle(pub(crate) usize);

/// A network stack.
pub struct Stack {
    pub(crate) inner: StackInner,
    pub(crate) ifaces: Slab<Iface>,
    pub(crate) sockets: Sockets,
}

/// The stack's socket storage, one slab per socket type.
pub(crate) struct Sockets {
    pub(crate) udp: Slab<UdpSocketState>,
    pub(crate) raw: Slab<RawSocketState>,
    pub(crate) tcp: Slab<TcpSocketState>,
    pub(crate) tcp_listeners: Slab<TcpListenerState>,
}

/// An interface added to the stack, with its configuration.
pub(crate) struct Iface {
    handle: IfaceHandle,
    dev: Box<dyn Interface>,
    hardware_addr: EthernetAddress,
    pub(crate) ip_addrs: Vec<IpCidr>,
}

/// The device-independent part of the stack.
///
/// Separate from `Stack` so that its methods can borrow an interface from `Stack::ifaces`
/// while taking `&mut self`.
pub(crate) struct StackInner {
    pub(crate) now: Instant,
    pub(crate) rand: Rand,
    neighbor_cache: NeighborCache,
    pending: PendingQueue,
    routes: Routes,
}

/// Borrowed stack context for socket egress.
///
/// Sockets hand fully-built L4 packets to [`TxContext::transmit_ip`]. Picking the
/// egress interface, building the IP header and resolving the neighbor all happen
/// in here, so socket code doesn't have to care about any of it.
pub(crate) struct TxContext<'a> {
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<Iface>,
}

impl TxContext<'_> {
    /// The current time, as last set by [`Stack::poll`].
    pub(crate) fn now(&self) -> Instant {
        self.inner.now
    }

    /// The stack's PRNG.
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.inner.rand
    }

    /// Check whether any interface has the given IP address assigned.
    pub(crate) fn has_ip_addr(&self, addr: IpAddress) -> bool {
        self.ifaces.iter().any(|(_, iface)| iface.has_ip_addr(addr))
    }

    /// Get a source address for sending to the given destination, selected from the
    /// interface the packet would go out of.
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        let handle = self.egress_iface(dst_addr)?;
        self.ifaces.get(handle.0).get_source_address(dst_addr)
    }

    /// Pick the egress interface for a destination: the interface the destination is
    /// on-link for, else the interface named by the matching route.
    fn egress_iface(&self, dst_addr: &IpAddress) -> Option<IfaceHandle> {
        if !dst_addr.is_unicast() {
            // Broadcast and multicast destinations carry nothing to route on, so
            // they go out the first interface.
            // TODO: let the send API pick the interface.
            return self.ifaces.iter().next().map(|(_, iface)| iface.handle);
        }

        self.ifaces
            .iter()
            .find(|(_, iface)| iface.in_same_network(dst_addr))
            .map(|(_, iface)| iface.handle)
            .or_else(|| {
                self.inner
                    .routes
                    .lookup(dst_addr, self.inner.now)
                    .map(|route| route.iface)
            })
    }

    /// Transmit a fully-built IP payload, with the L4 header but not the IP header.
    ///
    /// `src_addr` and `dst_addr` must belong to the same address family, the packet
    /// is dropped otherwise.
    pub(crate) fn transmit_ip(
        &mut self,
        buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let Some(handle) = self.egress_iface(&dst_addr) else {
            debug!("no route to {}, dropping packet", dst_addr);
            return;
        };
        let iface = self.ifaces.get_mut(handle.0);
        match (src_addr, dst_addr) {
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                self.inner.transmit_ipv4(iface, buf, src, dst, next_header, hop_limit)
            }
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                self.inner.transmit_ipv6(iface, buf, src, dst, next_header, hop_limit)
            }
            _ => {
                debug!("cannot transmit, address family mismatch");
            }
        }
    }

    /// Transmit a fully-built Ethernet frame on the given interface, as-is.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    pub(crate) fn transmit_ethernet_frame(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        let iface = self.ifaces.get_mut(iface.0);
        self.inner.transmit_raw(iface, buf);
    }

    /// Transmit a fully-built IP packet (IP header included, emitted as-is): pick
    /// the egress interface from the destination address, resolve the neighbor, and
    /// hand the frame to the device.
    ///
    /// Returns `false` if there is no route to the destination.
    pub(crate) fn transmit_raw_ip(&mut self, buf: PacketBuf, dst_addr: IpAddress) -> bool {
        let Some(handle) = self.egress_iface(&dst_addr) else {
            debug!("no route to {}, dropping packet", dst_addr);
            return false;
        };
        let iface = self.ifaces.get_mut(handle.0);
        let ethertype = match dst_addr {
            IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
            IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
        };
        self.inner.transmit_ip_frame(iface, dst_addr, buf, ethertype);
        true
    }
}

/// Score `addr` against a bind's address filter, the way ingress demux ranks
/// candidate sockets: `None` if it does not match, else how specific the filter
/// that matched it is. No address matches anything (0), an unspecified one
/// matches its own IP version (1), and a concrete one matches only itself (2).
pub(crate) fn addr_score(filter: &IpListenEndpoint, addr: &IpAddress) -> Option<u8> {
    match filter.addr {
        None => Some(0),
        Some(a) if a.is_unspecified() => (a.version() == addr.version()).then_some(1),
        Some(a) => (a == *addr).then_some(2),
    }
}

/// The bottom of the ephemeral (dynamic) local port range, per IANA. The range
/// runs to the top of the port space, 65535.
pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;

/// Allocate an ephemeral local port: start at a random point in the range and
/// linearly probe upward (wrapping) for the first port `in_use` doesn't claim.
///
/// The random start makes local ports hard to predict for off-path attackers
/// (RFC 6056 §3.3). `None` is returned only when every port in the range is in use.
pub(crate) fn alloc_ephemeral_port(rand: &mut Rand, mut in_use: impl FnMut(u16) -> bool) -> Option<u16> {
    const RANGE: u32 = (u16::MAX - EPHEMERAL_PORT_MIN) as u32 + 1;
    let start = rand.rand_u32() % RANGE;
    (0..RANGE)
        .map(|i| EPHEMERAL_PORT_MIN + ((start + i) % RANGE) as u16)
        .find(|&port| !in_use(port))
}

/// The result of a neighbor lookup.
enum NeighborLookup {
    /// The destination hardware address.
    Found(EthernetAddress),
    /// The neighbor is being resolved; the packet should be queued as pending.
    Pending { next_hop: IpAddress },
    /// There is no route to the destination.
    NoRoute,
}

impl Stack {
    /// Create a network stack.
    pub fn new() -> Self {
        Self {
            inner: StackInner {
                now: Instant::ZERO,
                // TODO: let the user seed this. Predictable TCP initial sequence
                // numbers make connections easier to spoof.
                rand: Rand::new(0x1234_5678_dead_beef),
                neighbor_cache: NeighborCache::new(),
                pending: PendingQueue::new(),
                routes: Routes::new(),
            },
            ifaces: Slab::new(),
            sockets: Sockets {
                udp: Slab::new(),
                raw: Slab::new(),
                tcp: Slab::new(),
                tcp_listeners: Slab::new(),
            },
        }
    }

    /// Add an interface to the stack with the given configuration, returning a
    /// handle to it.
    pub fn add_iface(&mut self, dev: Box<dyn Interface>, config: Config) -> IfaceHandle {
        let index = self.ifaces.add_with(|index| Iface {
            handle: IfaceHandle(index),
            dev,
            hardware_addr: config.hardware_addr,
            ip_addrs: config.ip_addrs,
        });
        IfaceHandle(index)
    }

    /// Remove an interface from the stack, returning the device.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was already removed).
    pub fn remove_iface(&mut self, handle: IfaceHandle) -> Box<dyn Interface> {
        let iface = self.ifaces.remove(handle.0);
        self.inner.neighbor_cache.purge_iface(handle);
        self.inner.pending.purge_iface(handle);
        self.inner.routes.purge_iface(handle);
        iface.dev
    }

    /// Access the routing table.
    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    /// Access the routing table for modification.
    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Add a UDP socket to the stack, returning a handle to it.
    pub fn add_udp_socket(&mut self) -> UdpHandle {
        UdpHandle(self.sockets.udp.add_with(|_| UdpSocketState::new()))
    }

    /// Remove a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn remove_udp_socket(&mut self, handle: UdpHandle) {
        self.sockets.udp.remove(handle.0);
    }

    /// Borrow a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn udp(&mut self, handle: UdpHandle) -> UdpSocket<'_> {
        self.sockets.udp.get(handle.0); // Stale handles panic here, not on first use.
        UdpSocket {
            sockets: &mut self.sockets.udp,
            index: handle.0,
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a raw socket to the stack, returning a handle to it.
    pub fn add_raw_socket(&mut self) -> RawHandle {
        RawHandle(self.sockets.raw.add_with(|_| RawSocketState::new()))
    }

    /// Remove a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn remove_raw_socket(&mut self, handle: RawHandle) {
        self.sockets.raw.remove(handle.0);
    }

    /// Borrow a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn raw(&mut self, handle: RawHandle) -> RawSocket<'_> {
        RawSocket {
            state: self.sockets.raw.get_mut(handle.0),
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a TCP socket to the stack, with the given receive and transmit buffer
    /// capacities, returning a handle to it.
    pub fn add_tcp_socket(&mut self, rx_capacity: usize, tx_capacity: usize) -> TcpHandle {
        TcpHandle(self.sockets.tcp.add_with(|_| {
            TcpSocketState::new(
                SocketBuffer::new(vec![0; rx_capacity]),
                SocketBuffer::new(vec![0; tx_capacity]),
            )
        }))
    }

    /// Remove a TCP socket from the stack.
    ///
    /// No RST is sent, and any buffered data is lost. To close a connection cleanly,
    /// [`TcpSocket::close`] it first and poll until it is fully closed.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn remove_tcp_socket(&mut self, handle: TcpHandle) {
        self.sockets.tcp.remove(handle.0);
    }

    /// Borrow a TCP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    pub fn tcp(&mut self, handle: TcpHandle) -> TcpSocket<'_> {
        self.sockets.tcp.get(handle.0); // Stale handles panic here, not on first use.
        TcpSocket {
            sockets: &mut self.sockets.tcp,
            index: handle.0,
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a TCP listener to the stack, returning a handle to it.
    pub fn add_tcp_listener(&mut self) -> TcpListenerHandle {
        TcpListenerHandle(self.sockets.tcp_listeners.add_with(|_| TcpListenerState::new()))
    }

    /// Remove a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    pub fn remove_tcp_listener(&mut self, handle: TcpListenerHandle) {
        self.sockets.tcp_listeners.remove(handle.0);
    }

    /// Borrow a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    pub fn tcp_listener(&mut self, handle: TcpListenerHandle) -> TcpListener<'_> {
        self.sockets.tcp_listeners.get(handle.0); // Stale handles panic here, not on first use.
        TcpListener {
            listeners: &mut self.sockets.tcp_listeners,
            index: handle.0,
            tcp: &mut self.sockets.tcp,
            rand: &mut self.inner.rand,
        }
    }

    /// Borrow the stack context for socket egress (used by socket unit tests).
    #[cfg(test)]
    pub(crate) fn tx_context(&mut self) -> TxContext<'_> {
        TxContext {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
        }
    }

    /// Process all pending ingress packets on all ifaces, advance the stack's
    /// internal timers, and transmit everything the TCP sockets have made due.
    ///
    /// `timestamp` is the current time.
    ///
    /// Returns the earliest instant at which `poll` should be called again to advance
    /// the timers, or `None` if no timers are pending. In that case it is enough to
    /// call `poll` again when a packet is received, or after operating on a socket.
    pub fn poll(&mut self, timestamp: Instant) -> Option<Instant> {
        self.inner.now = timestamp;

        // Drop queued packets whose neighbor resolution timed out.
        self.inner.pending.purge_expired(timestamp);

        for (_, iface) in self.ifaces.iter_mut() {
            self.inner.poll_neighbor_timers(iface);

            while let Some(buf) = iface.dev.receive() {
                self.inner.process(iface, &mut self.sockets, buf);
            }
        }

        // Drive TCP egress: this both acknowledges what ingress just delivered and
        // advances the TCP timers (retransmissions, delayed ACKs, keep-alives,
        // zero-window probes, ...).
        let mut cx = TxContext {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
        };
        for (_, socket) in self.sockets.tcp.iter_mut() {
            crate::tcp::flush(socket, &mut cx);
        }

        let tcp_poll_at = self
            .sockets
            .tcp
            .iter()
            .filter_map(|(_, socket)| match socket.poll_at() {
                PollAt::Now => Some(timestamp),
                PollAt::Time(t) => Some(t),
                PollAt::Ingress => None,
            });

        [self.inner.neighbor_cache.poll_at(), self.inner.pending.poll_at()]
            .into_iter()
            .flatten()
            .chain(tcp_poll_at)
            .min()
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl StackInner {
    fn process(&mut self, iface: &mut Iface, sockets: &mut Sockets, buf: PacketBuf) {
        match iface.dev.capabilities().medium {
            Medium::Ethernet => self.process_ethernet(iface, sockets, buf),
            Medium::Ip => self.process_ip(iface, sockets, buf),
        }
    }

    fn process_ethernet(&mut self, iface: &mut Iface, sockets: &mut Sockets, mut buf: PacketBuf) {
        let eth_frame = check!(EthernetFrame::new_checked(&mut buf));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != iface.hardware_addr
        {
            return;
        }

        let src_addr = eth_frame.src_addr();
        let ethertype = eth_frame.ethertype();

        // Offer the whole frame to Ethernet-mode raw sockets. Ethertypes the stack
        // itself processes are copied to the socket, everything else is consumed
        // by it.
        let stack_wants = matches!(
            ethertype,
            EthernetProtocol::Arp | EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6
        );
        let Some(mut buf) = self.process_raw_ethernet(iface, &mut sockets.raw, ethertype, stack_wants, buf) else {
            return;
        };

        buf.pull_front(ETHERNET_HEADER_LEN);

        match ethertype {
            EthernetProtocol::Arp => self.process_arp(iface, buf),
            EthernetProtocol::Ipv4 => self.process_ipv4(iface, sockets, Some(src_addr), buf),
            EthernetProtocol::Ipv6 => self.process_ipv6(iface, sockets, Some(src_addr), buf),
            // Drop all other traffic.
            _ => {}
        }
    }

    fn process_ip(&mut self, iface: &mut Iface, sockets: &mut Sockets, buf: PacketBuf) {
        if buf.is_empty() {
            return;
        }
        match IpVersion::of_packet(&buf) {
            Ok(IpVersion::Ipv4) => self.process_ipv4(iface, sockets, None, buf),
            Ok(IpVersion::Ipv6) => self.process_ipv6(iface, sockets, None, buf),
            Err(_) => {}
        }
    }

    fn process_arp(&mut self, iface: &mut Iface, mut buf: PacketBuf) {
        let arp_packet = check!(ArpPacket::new_checked(&mut buf));

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
        if !iface.has_ip_addr(target_protocol_addr) {
            return;
        }

        // Only process REQUEST and RESPONSE.
        if !matches!(operation, ArpOperation::Request | ArpOperation::Reply) {
            debug!("arp: unknown operation code");
            return;
        }

        // Discard packets with non-unicast source addresses.
        if !source_protocol_addr.x_is_unicast() || !source_hardware_addr.is_unicast() {
            debug!("arp: non-unicast source address");
            return;
        }

        if !iface.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
            debug!("arp: source IP address not in same network as us");
            return;
        }

        // Fill the ARP cache from any ARP packet aimed at us (both request or response).
        // We fill from requests too because if someone is requesting our address they
        // are probably going to talk to us, so we avoid having to request their address
        // when we later reply to them.
        self.fill_neighbor(iface, IpAddress::Ipv4(source_protocol_addr), source_hardware_addr);

        if operation == ArpOperation::Request {
            let mut reply = PacketBuf::new();
            reply.reserve(ETHERNET_HEADER_LEN);
            reply.set_len(ARP_BUFFER_LEN);
            {
                let mut arp_reply = ArpPacket::new_unchecked(&mut reply);
                arp_reply.set_hardware_type(ArpHardware::Ethernet);
                arp_reply.set_protocol_type(EthernetProtocol::Ipv4);
                arp_reply.set_hardware_len(6);
                arp_reply.set_protocol_len(4);
                arp_reply.set_operation(ArpOperation::Reply);
                arp_reply.set_source_hardware_addr(iface.hardware_addr.as_bytes());
                arp_reply.set_source_protocol_addr(&target_protocol_addr.octets());
                arp_reply.set_target_hardware_addr(source_hardware_addr.as_bytes());
                arp_reply.set_target_protocol_addr(&source_protocol_addr.octets());
            }
            self.transmit_ethernet(iface, source_hardware_addr, reply, EthernetProtocol::Arp);
        }
    }

    fn process_ipv4(
        &mut self,
        iface: &mut Iface,
        sockets: &mut Sockets,
        eth_src: Option<EthernetAddress>,
        mut buf: PacketBuf,
    ) {
        let ipv4_packet = check!(Ipv4Packet::new_checked(&mut buf));

        if ipv4_packet.version() != 4 {
            return;
        }
        if !ipv4_packet.verify_checksum() {
            trace!("ipv4: header checksum incorrect");
            return;
        }
        if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
            trace!("ipv4: fragmented packets not supported yet");
            return;
        }

        let src_addr = ipv4_packet.src_addr();
        let dst_addr = ipv4_packet.dst_addr();
        let next_header = ipv4_packet.next_header();
        let header_len = ipv4_packet.header_len() as usize;
        let total_len = ipv4_packet.total_len() as usize;

        if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
            // Discard packets with non-unicast source addresses but allow unspecified
            debug!("non-unicast or unspecified source address");
            return;
        }

        if !iface.has_ip_addr(dst_addr) && !iface.is_broadcast_v4(dst_addr) {
            // Ignore IP packets not directed at us, or broadcast.
            trace!("Rejecting IPv4 packet; not for us");
            return;
        }

        if let Some(eth_src) = eth_src
            && iface.is_unicast_v4(dst_addr)
        {
            self.neighbor_cache
                .reset_expiry_if_existing((iface.handle, IpAddress::Ipv4(src_addr)), eth_src, self.now);
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(total_len);

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        let stack_wants = matches!(next_header, IpProtocol::Icmp | IpProtocol::Udp | IpProtocol::Tcp);
        let Some(mut buf) = self.process_raw_ip(&mut sockets.raw, IpVersion::Ipv4, next_header, stack_wants, buf)
        else {
            return;
        };

        // Strip the IP header.
        buf.pull_front(header_len);

        match next_header {
            IpProtocol::Icmp => self.process_icmpv4(iface, src_addr, dst_addr, buf),
            IpProtocol::Udp => self.process_udp(
                iface,
                &mut sockets.udp,
                IpAddress::Ipv4(src_addr),
                IpAddress::Ipv4(dst_addr),
                header_len,
                buf,
            ),
            IpProtocol::Tcp => self.process_tcp(
                iface,
                &mut sockets.tcp,
                &mut sockets.tcp_listeners,
                IpAddress::Ipv4(src_addr),
                IpAddress::Ipv4(dst_addr),
                buf,
            ),
            _ => {
                trace!("ipv4: protocol {} not supported", next_header);
            }
        }
    }

    /// Process an ingress TCP segment: validate it and hand it to the matching
    /// socket, transmitting whatever immediate reply the socket state machine
    /// produces (RST, challenge ACK). Connected sockets match first, by full
    /// 4-tuple, then the listeners, which record SYNs to a listened endpoint in
    /// their accept queues and transmit nothing (the SYN|ACK is sent by the
    /// socket that `accept` creates). Unmatched segments are answered with an
    /// RST.
    ///
    /// The socket's own transmissions (data, ACKs of received data) are not sent
    /// here. [`Stack::poll`] drives them right after ingress processing.
    fn process_tcp(
        &mut self,
        iface: &mut Iface,
        sockets: &mut Slab<TcpSocketState>,
        listeners: &mut Slab<TcpListenerState>,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        mut buf: PacketBuf,
    ) {
        // Per RFC 1122 §3.2.1.3, the unspecified address must never appear as a source
        // or destination in any IP datagram. Drop such TCP segments early to avoid
        // creating sockets with unspecified peers (which would later panic on egress).
        if src_addr.is_unspecified() || dst_addr.is_unspecified() {
            return;
        }

        let Ok(tcp_packet) = TcpPacket::new_checked(&mut buf) else {
            trace!("tcp: malformed packet");
            return;
        };
        if !tcp_packet.verify_checksum(&src_addr, &dst_addr) {
            trace!("tcp: checksum incorrect");
            return;
        }
        let Ok(tcp_repr) = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr) else {
            trace!("tcp: malformed packet");
            return;
        };

        // Connected sockets: exact 4-tuple match.
        for (_, socket) in sockets.iter_mut() {
            if socket.accepts(&src_addr, &dst_addr, &tcp_repr) {
                if let Some(reply) = socket.process(self.now, &src_addr, &dst_addr, &tcp_repr) {
                    // Replies go back the way the segment came in.
                    self.transmit_tcp(iface, dst_addr, src_addr, 64, &reply);
                }
                return;
            }
        }

        // Listeners: a SYN to a listened endpoint is recorded in the accept
        // queue of the most specific matching listener (exact local address
        // beats wildcard), and an RST aimed at a recorded SYN cancels it.
        // Nothing is replied, the handshake starts when the connection is
        // accepted.
        if crate::tcp::process_listeners(listeners, &src_addr, &dst_addr, &tcp_repr) {
            return;
        }

        // The packet wasn't handled by a socket: send a TCP RST packet.
        // Never reply to a TCP RST packet with another TCP RST packet.
        if tcp_repr.control != TcpControl::Rst {
            let reply = TcpSocketState::rst_reply(&tcp_repr);
            self.transmit_tcp(iface, dst_addr, src_addr, 64, &reply);
        }
    }

    /// Serialize a TCP segment and transmit it on the given interface.
    fn transmit_tcp(
        &mut self,
        iface: &mut Iface,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        hop_limit: u8,
        repr: &TcpRepr<'_>,
    ) {
        let buf = crate::tcp::build_tcp_packet(repr, &src_addr, &dst_addr);
        match (src_addr, dst_addr) {
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                self.transmit_ipv4(iface, buf, src, dst, IpProtocol::Tcp, hop_limit)
            }
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                self.transmit_ipv6(iface, buf, src, dst, IpProtocol::Tcp, hop_limit)
            }
            _ => unreachable!(),
        }
    }

    fn process_icmpv4(&mut self, iface: &mut Iface, src_addr: Ipv4Address, dst_addr: Ipv4Address, mut buf: PacketBuf) {
        let icmp_packet = check!(Icmpv4Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum() {
            trace!("icmpv4: checksum incorrect");
            return;
        }

        match (icmp_packet.msg_type(), icmp_packet.msg_code()) {
            // Respond to echo requests.
            (Icmpv4Message::EchoRequest, 0) => {
                // Do not send ICMP replies to non-unicast sources.
                if !iface.is_unicast_v4(src_addr) {
                    return;
                }
                // Reply as normal when src_addr and dst_addr are both unicast; only
                // reply to broadcasts for echo replies and not other ICMP messages.
                let reply_src = if iface.is_unicast_v4(dst_addr) {
                    dst_addr
                } else if iface.is_broadcast_v4(dst_addr) {
                    match iface.ipv4_addr() {
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
                    let mut reply_icmp = Icmpv4Packet::new_unchecked(&mut reply);
                    reply_icmp.set_msg_type(Icmpv4Message::EchoReply);
                    reply_icmp.set_msg_code(0);
                    reply_icmp.set_echo_ident(icmp_packet.echo_ident());
                    reply_icmp.set_echo_seq_no(icmp_packet.echo_seq_no());
                    reply_icmp.data_mut().copy_from_slice(icmp_packet.data());
                    reply_icmp.fill_checksum();
                }
                self.transmit_ipv4(iface, reply, reply_src, src_addr, IpProtocol::Icmp, 64);
            }

            // Ignore any echo replies.
            (Icmpv4Message::EchoReply, _) => {}

            _ => {}
        }
    }

    fn process_ipv6(
        &mut self,
        iface: &mut Iface,
        sockets: &mut Sockets,
        eth_src: Option<EthernetAddress>,
        mut buf: PacketBuf,
    ) {
        let ipv6_packet = check!(Ipv6Packet::new_checked(&mut buf));

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
            debug!("non-unicast source address");
            return;
        }

        if !iface.has_ip_addr(dst_addr) && !iface.has_multicast_group(dst_addr) && !dst_addr.is_loopback() {
            trace!("Rejecting IPv6 packet; not for us");
            return;
        }

        if let Some(eth_src) = eth_src
            && dst_addr.x_is_unicast()
        {
            self.neighbor_cache
                .reset_expiry_if_existing((iface.handle, IpAddress::Ipv6(src_addr)), eth_src, self.now);
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(IPV6_HEADER_LEN + payload_len);

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        let stack_wants = matches!(next_header, IpProtocol::Icmpv6 | IpProtocol::Udp | IpProtocol::Tcp);
        let Some(mut buf) = self.process_raw_ip(&mut sockets.raw, IpVersion::Ipv6, next_header, stack_wants, buf)
        else {
            return;
        };

        // Strip the IP header.
        buf.pull_front(IPV6_HEADER_LEN);

        match next_header {
            IpProtocol::Icmpv6 => self.process_icmpv6(iface, eth_src, src_addr, dst_addr, hop_limit, buf),
            IpProtocol::Udp => self.process_udp(
                iface,
                &mut sockets.udp,
                IpAddress::Ipv6(src_addr),
                IpAddress::Ipv6(dst_addr),
                IPV6_HEADER_LEN,
                buf,
            ),
            IpProtocol::Tcp => self.process_tcp(
                iface,
                &mut sockets.tcp,
                &mut sockets.tcp_listeners,
                IpAddress::Ipv6(src_addr),
                IpAddress::Ipv6(dst_addr),
                buf,
            ),
            _ => {
                trace!("ipv6: protocol {} not supported", next_header);
            }
        }
    }

    fn process_icmpv6(
        &mut self,
        iface: &mut Iface,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
        mut buf: PacketBuf,
    ) {
        let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum(&src_addr, &dst_addr) {
            trace!("icmpv6: checksum incorrect");
            return;
        }

        match icmp_packet.msg_type() {
            // Respond to echo requests.
            Icmpv6Message::EchoRequest => {
                let reply_src = if dst_addr.x_is_unicast() {
                    dst_addr
                } else {
                    iface.get_source_address_ipv6(&src_addr)
                };

                let mut reply = PacketBuf::new();
                reply.reserve(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN);
                reply.set_len(icmp_packet.header_len() + icmp_packet.payload().len());
                {
                    let mut reply_icmp = Icmpv6Packet::new_unchecked(&mut reply);
                    reply_icmp.set_msg_type(Icmpv6Message::EchoReply);
                    reply_icmp.set_msg_code(0);
                    reply_icmp.set_echo_ident(icmp_packet.echo_ident());
                    reply_icmp.set_echo_seq_no(icmp_packet.echo_seq_no());
                    reply_icmp.payload_mut().copy_from_slice(icmp_packet.payload());
                    reply_icmp.fill_checksum(&reply_src, &src_addr);
                }
                self.transmit_ipv6(iface, reply, reply_src, src_addr, IpProtocol::Icmpv6, 64);
            }

            // Ignore any echo replies.
            Icmpv6Message::EchoReply => {}

            // NDISC is only processed if the packet arrived with the un-decremented
            // hop limit, and only on Ethernet mediums.
            Icmpv6Message::NeighborSolicit if hop_limit == 0xff && eth_src.is_some() => {
                self.process_ndisc_solicit(iface, src_addr, dst_addr, &mut icmp_packet)
            }

            Icmpv6Message::NeighborAdvert if hop_limit == 0xff && eth_src.is_some() => {
                self.process_ndisc_advert(iface, src_addr, &mut icmp_packet)
            }

            _ => {}
        }
    }

    fn process_ndisc_solicit(
        &mut self,
        iface: &mut Iface,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let target_addr = icmp_packet.target_addr();
        let lladdr = check!(ndisc_lladdr_option(icmp_packet, NdiscOptionType::SourceLinkLayerAddr));

        if let Some(lladdr) = lladdr {
            let lladdr = check!(lladdr.parse_ethernet());
            if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
                return;
            }
            self.fill_neighbor(iface, IpAddress::Ipv6(src_addr), lladdr);
        }

        if iface.has_solicited_node(dst_addr) && iface.has_ip_addr(target_addr) {
            // Neighbor advert: NA header (24 bytes) plus the target link-layer
            // address option (8 bytes).
            let mut reply = PacketBuf::new();
            reply.reserve(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN);
            reply.set_len(24 + 8);
            {
                let mut na = Icmpv6Packet::new_unchecked(&mut reply);
                na.set_msg_type(Icmpv6Message::NeighborAdvert);
                na.set_msg_code(0);
                na.clear_reserved();
                na.set_neighbor_flags(NdiscNeighborFlags::SOLICITED);
                na.set_target_addr(target_addr);
                {
                    let mut opt = NdiscOption::new_unchecked(na.payload_mut());
                    opt.set_option_type(NdiscOptionType::TargetLinkLayerAddr);
                    opt.set_data_len(1);
                    opt.set_link_layer_addr(RawHardwareAddress::from(iface.hardware_addr));
                }
                na.fill_checksum(&target_addr, &src_addr);
            }
            self.transmit_ipv6(iface, reply, target_addr, src_addr, IpProtocol::Icmpv6, 0xff);
        }
    }

    fn process_ndisc_advert(&mut self, iface: &mut Iface, src_addr: Ipv6Address, icmp_packet: &mut Icmpv6Packet<'_>) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let flags = icmp_packet.neighbor_flags();
        let target_addr = icmp_packet.target_addr();
        let lladdr = check!(ndisc_lladdr_option(icmp_packet, NdiscOptionType::TargetLinkLayerAddr));

        let ip_addr = IpAddress::Ipv6(src_addr);
        if let Some(lladdr) = lladdr {
            let lladdr = check!(lladdr.parse_ethernet());
            if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
                return;
            }
            if flags.contains(NdiscNeighborFlags::OVERRIDE)
                || !self.neighbor_cache.lookup(&(iface.handle, ip_addr), self.now).found()
            {
                self.fill_neighbor(iface, ip_addr, lladdr)
            }
        }
    }

    /// Advance the solicitation retransmission timers of the neighbors being resolved
    /// on this interface, retransmitting solicitations and failing resolutions that
    /// exhausted their probes.
    fn poll_neighbor_timers(&mut self, iface: &mut Iface) {
        for event in self.neighbor_cache.poll_retransmit(iface.handle, self.now) {
            match event {
                ProbeEvent::Retransmit(addr) => {
                    debug!("neighbor {} still unresolved, retransmitting solicitation", addr);
                    self.solicit_neighbor(iface, addr);
                }
                ProbeEvent::Failed(addr) => {
                    debug!("neighbor {} resolution failed, dropping queued packets", addr);
                    // Dropping the queued packets is all there is to do.
                    // TODO: RFC 4861 says to send an ICMP destination unreachable
                    // error for each of them.
                    drop(self.pending.take_matching(&(iface.handle, addr)));
                }
            }
        }
    }

    /// Send a solicitation (ARP request / NDISC neighbor solicit) for the given address.
    fn solicit_neighbor(&mut self, iface: &mut Iface, addr: IpAddress) {
        match addr {
            IpAddress::Ipv4(addr) => self.transmit_arp_request(iface, addr),
            IpAddress::Ipv6(addr) => self.transmit_ndisc_solicit(iface, addr),
        }
    }

    /// Fill the neighbor cache, and flush any packets that were queued waiting for
    /// this neighbor to resolve.
    fn fill_neighbor(&mut self, iface: &mut Iface, addr: IpAddress, hardware_addr: EthernetAddress) {
        let key = (iface.handle, addr);
        self.neighbor_cache.fill(key, hardware_addr, self.now);

        for packet in self.pending.take_matching(&key) {
            trace!("neighbor: {} resolved, flushing queued packet", addr);
            let ethertype = match packet.key.1 {
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
            };
            self.transmit_ethernet(iface, hardware_addr, packet.buf, ethertype);
        }
    }

    /// Look up the destination hardware address for an egress packet, sending a
    /// solicitation (ARP request / NDISC neighbor solicit) if it is not resolved yet.
    fn lookup_hardware_addr(&mut self, iface: &mut Iface, dst_addr: &IpAddress) -> NeighborLookup {
        if iface.is_broadcast(dst_addr) {
            return NeighborLookup::Found(EthernetAddress::BROADCAST);
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                IpAddress::Ipv4(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x01, 0x00, 0x5e, b[1] & 0x7F, b[2], b[3]])
                }
                IpAddress::Ipv6(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x33, 0x33, b[12], b[13], b[14], b[15]])
                }
            };

            return NeighborLookup::Found(hardware_addr);
        }

        let Some(next_hop) = self.route(iface, dst_addr) else {
            return NeighborLookup::NoRoute;
        };

        match self.neighbor_cache.lookup(&(iface.handle, next_hop), self.now) {
            NeighborAnswer::Found(hardware_addr) => return NeighborLookup::Found(hardware_addr),
            // Resolution is already in progress; the retransmission timer owns
            // any further solicitations.
            NeighborAnswer::Pending => return NeighborLookup::Pending { next_hop },
            NeighborAnswer::NotFound => {}
        }

        // Start resolving: create the INCOMPLETE entry and send the first solicitation.
        debug!("address {} not in neighbor cache, sending solicitation", next_hop);
        self.neighbor_cache.start_resolution((iface.handle, next_hop), self.now);
        self.solicit_neighbor(iface, next_hop);

        NeighborLookup::Pending { next_hop }
    }

    fn transmit_arp_request(&mut self, iface: &mut Iface, target_addr: Ipv4Address) {
        let Some(source_protocol_addr) = iface.get_source_address_ipv4(&target_addr) else {
            debug!("arp: no source address for request");
            return;
        };

        let mut buf = PacketBuf::new();
        buf.reserve(ETHERNET_HEADER_LEN);
        buf.set_len(ARP_BUFFER_LEN);
        {
            let mut arp_packet = ArpPacket::new_unchecked(&mut buf);
            arp_packet.set_hardware_type(ArpHardware::Ethernet);
            arp_packet.set_protocol_type(EthernetProtocol::Ipv4);
            arp_packet.set_hardware_len(6);
            arp_packet.set_protocol_len(4);
            arp_packet.set_operation(ArpOperation::Request);
            arp_packet.set_source_hardware_addr(iface.hardware_addr.as_bytes());
            arp_packet.set_source_protocol_addr(&source_protocol_addr.octets());
            arp_packet.set_target_hardware_addr(EthernetAddress::BROADCAST.as_bytes());
            arp_packet.set_target_protocol_addr(&target_addr.octets());
        }
        self.transmit_ethernet(iface, EthernetAddress::BROADCAST, buf, EthernetProtocol::Arp);
    }

    fn transmit_ndisc_solicit(&mut self, iface: &mut Iface, target_addr: Ipv6Address) {
        let src_addr = iface.get_source_address_ipv6(&target_addr);
        let dst_addr = target_addr.solicited_node();

        // Neighbor solicit: NS header (24 bytes) plus the source link-layer
        // address option (8 bytes).
        let mut buf = PacketBuf::new();
        buf.reserve(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN);
        buf.set_len(24 + 8);
        {
            let mut ns = Icmpv6Packet::new_unchecked(&mut buf);
            ns.set_msg_type(Icmpv6Message::NeighborSolicit);
            ns.set_msg_code(0);
            ns.clear_reserved();
            ns.set_target_addr(target_addr);
            {
                let mut opt = NdiscOption::new_unchecked(ns.payload_mut());
                opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
                opt.set_data_len(1);
                opt.set_link_layer_addr(RawHardwareAddress::from(iface.hardware_addr));
            }
            ns.fill_checksum(&src_addr, &dst_addr);
        }
        // The solicited-node destination is multicast, so this never recurses back
        // into neighbor resolution.
        self.transmit_ipv6(iface, buf, src_addr, dst_addr, IpProtocol::Icmpv6, 0xff);
    }

    fn transmit_ipv4(
        &mut self,
        iface: &mut Iface,
        mut buf: PacketBuf,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let payload_len = buf.len();
        buf.push_front(IPV4_HEADER_LEN);
        {
            let mut packet = Ipv4Packet::new_unchecked(&mut buf);
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
        self.transmit_ip_frame(iface, IpAddress::Ipv4(dst_addr), buf, EthernetProtocol::Ipv4);
    }

    fn transmit_ipv6(
        &mut self,
        iface: &mut Iface,
        mut buf: PacketBuf,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let payload_len = buf.len();
        buf.push_front(IPV6_HEADER_LEN);
        {
            let mut packet = Ipv6Packet::new_unchecked(&mut buf);
            packet.set_version(6);
            packet.set_traffic_class(0);
            packet.set_flow_label(0);
            packet.set_payload_len(payload_len as u16);
            packet.set_next_header(next_header);
            packet.set_hop_limit(hop_limit);
            packet.set_src_addr(src_addr);
            packet.set_dst_addr(dst_addr);
        }
        self.transmit_ip_frame(iface, IpAddress::Ipv6(dst_addr), buf, EthernetProtocol::Ipv6);
    }

    /// Transmit a fully-built IP packet, resolving the destination hardware address
    /// on Ethernet mediums.
    ///
    /// If the neighbor is not resolved yet, the packet is queued in the interface's
    /// pending queue and flushed when resolution completes.
    fn transmit_ip_frame(
        &mut self,
        iface: &mut Iface,
        dst_addr: IpAddress,
        buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        match iface.dev.capabilities().medium {
            Medium::Ip => self.transmit_raw(iface, buf),
            Medium::Ethernet => match self.lookup_hardware_addr(iface, &dst_addr) {
                NeighborLookup::Found(hardware_addr) => self.transmit_ethernet(iface, hardware_addr, buf, ethertype),
                NeighborLookup::Pending { next_hop } => {
                    debug!("neighbor {} pending, queing packet", next_hop);
                    self.pending.push((iface.handle, next_hop), buf, self.now);
                }
                NeighborLookup::NoRoute => {
                    debug!("no route to {}, dropping packet", dst_addr);
                }
            },
        }
    }

    fn transmit_ethernet(
        &mut self,
        iface: &mut Iface,
        dst_hw: EthernetAddress,
        mut buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        buf.push_front(ETHERNET_HEADER_LEN);
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_hw);
        frame.set_src_addr(iface.hardware_addr);
        frame.set_ethertype(ethertype);
        self.transmit_raw(iface, buf);
    }

    fn transmit_raw(&mut self, iface: &mut Iface, buf: PacketBuf) {
        if iface.dev.transmit(buf).is_err() {
            debug!("iface: cannot transmit, dropping packet");
        }
    }

    /// Route an address to the next hop on the given interface.
    ///
    /// On-link destinations resolve to themselves. Off-link destinations resolve to a
    /// router from the routing table, but only if the route goes out this interface.
    fn route(&self, iface: &Iface, addr: &IpAddress) -> Option<IpAddress> {
        if iface.in_same_network(addr) {
            Some(*addr)
        } else {
            self.routes
                .lookup(addr, self.now)
                .filter(|route| route.iface == iface.handle)
                .map(|route| route.via_router)
        }
    }
}

impl Iface {
    /// The handle this interface is identified by in the stack.
    pub(crate) fn handle(&self) -> IfaceHandle {
        self.handle
    }

    /// The interface's medium.
    pub(crate) fn medium(&self) -> Medium {
        self.dev.capabilities().medium
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

    /// Get an IPv4 source address based on a destination address.
    ///
    /// This function tries to find the first IPv4 address from the interface
    /// that is in the same subnet as the destination address. If no such
    /// address is found, the first IPv4 address from the interface is returned.
    fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.ip_addrs.iter() {
            if let IpCidr::Ipv4(cidr) = cidr {
                // Return immediately if we find an address in the same subnet
                if cidr.contains_addr(dst_addr) {
                    return Some(cidr.address());
                }

                // Remember the first IPv4 address as fallback
                if first_ipv4.is_none() {
                    first_ipv4 = Some(cidr.address());
                }
            }
        }
        first_ipv4
    }

    /// Get a source address for the given destination address.
    fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(IpAddress::Ipv4),
            IpAddress::Ipv6(addr) => Some(IpAddress::Ipv6(self.get_source_address_ipv6(addr))),
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            IpAddress::Ipv6(_) => false,
        }
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

/// Scan the NDISC options of a neighbor solicitation/advertisement for the (source or
/// target) link-layer address option.
fn ndisc_lladdr_option(
    icmp_packet: &mut Icmpv6Packet<'_>,
    option_type: NdiscOptionType,
) -> crate::wire::Result<Option<RawHardwareAddress>> {
    let mut lladdr = None;
    let options = icmp_packet.payload_mut();
    let mut offset = 0;
    while offset < options.len() {
        let opt = NdiscOption::new_checked(&mut options[offset..])?;
        let opt_len = opt.data_len() as usize * 8;
        if opt_len == 0 {
            trace!("ndisc: option with zero length");
            return Err(crate::wire::Error);
        }
        if opt.option_type() == option_type {
            lladdr = Some(opt.link_layer_addr());
        }
        offset += opt_len;
    }
    Ok(lladdr)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_alloc_ephemeral_port() {
        let mut rand = Rand::new(42);

        // Unconstrained: any port in the ephemeral range.
        let port = alloc_ephemeral_port(&mut rand, |_| false).unwrap();
        assert!(port >= EPHEMERAL_PORT_MIN);

        // The probe walks past used ports (wrapping) to the single free one.
        let free = EPHEMERAL_PORT_MIN + 1234;
        assert_eq!(alloc_ephemeral_port(&mut rand, |p| p != free), Some(free));

        // Every port in use: allocation fails.
        assert_eq!(alloc_ephemeral_port(&mut rand, |_| true), None);
    }
}
