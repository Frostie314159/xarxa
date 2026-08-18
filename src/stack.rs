//! The network stack.

use alloc::boxed::Box;
#[cfg(feature = "socket-tcp")]
use alloc::vec;
use alloc::vec::Vec;

use crate::buf::{PACKET_BUF_SIZE, PacketBuf};
#[cfg(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp")))]
use crate::icmp_error::{IcmpError, parse_quoted_packet};
use crate::iface::{IfaceCapabilities, Interface, Medium};
#[cfg(feature = "medium-ethernet")]
use crate::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache, PendingQueue, ProbeEvent};
use crate::rand::Rand;
#[cfg(feature = "socket-raw")]
use crate::raw::{RawHandle, RawSocket, RawSocketState};
use crate::route::Routes;
use crate::slab::Slab;
#[cfg(feature = "socket-tcp")]
use crate::tcp::{
    PollAt, SocketBuffer, TcpHandle, TcpListener, TcpListenerHandle, TcpListenerState, TcpRepr, TcpSocket,
    TcpSocketState,
};
use crate::time::Instant;
#[cfg(feature = "socket-udp")]
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

/// A handle to an interface added to a [`Stack`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfaceHandle(pub(crate) usize);

/// A network stack.
pub struct Stack {
    pub(crate) inner: StackInner,
    pub(crate) ifaces: Slab<IfaceState>,
    pub(crate) sockets: Sockets,
}

/// The stack's socket storage, one slab per socket type.
pub(crate) struct Sockets {
    #[cfg(feature = "socket-udp")]
    pub(crate) udp: Slab<UdpSocketState>,
    #[cfg(feature = "socket-raw")]
    pub(crate) raw: Slab<RawSocketState>,
    #[cfg(feature = "socket-tcp")]
    pub(crate) tcp: Slab<TcpSocketState>,
    #[cfg(feature = "socket-tcp")]
    pub(crate) tcp_listeners: Slab<TcpListenerState>,
}

/// An interface added to the stack, with its configuration.
pub(crate) struct IfaceState {
    #[cfg_attr(not(any(feature = "socket", feature = "medium-ethernet")), allow(dead_code))]
    handle: IfaceHandle,
    dev: Box<dyn Interface>,
    hardware_addr: HardwareAddress,
    pub(crate) ip_addrs: Vec<IpCidr>,
}

/// An interface borrowed from a [`Stack`], returned by [`Stack::iface`].
pub struct Iface<'a> {
    #[cfg_attr(not(feature = "medium-ethernet"), allow(dead_code))]
    inner: &'a mut StackInner,
    ifaces: &'a mut Slab<IfaceState>,
    index: usize,
}

impl Iface<'_> {
    #[inline]
    fn state(&self) -> &IfaceState {
        self.ifaces.get(self.index)
    }

    #[inline]
    fn state_mut(&mut self) -> &mut IfaceState {
        self.ifaces.get_mut(self.index)
    }

    /// The capabilities reported by the device.
    pub fn capabilities(&self) -> IfaceCapabilities {
        self.state().dev.capabilities()
    }

    /// The interface's IP-layer MTU: the device MTU minus the link-layer header,
    /// clamped to what a [`PacketBuf`] can carry.
    pub fn ip_mtu(&self) -> usize {
        self.state().ip_mtu()
    }

    /// Poll the device for the timestamp of an already-transmitted packet, sent with
    /// [`PacketMeta::request_timestamp`](crate::PacketMeta::request_timestamp) set.
    ///
    /// Returns `None` if no timestamp is available right now, which is also all a
    /// device without transmit timestamping support ever returns. See
    /// [`Interface::poll_tx_timestamp`] for what a caller must tolerate: timestamps
    /// arrive an arbitrary time after the packet was sent, possibly out of order, and
    /// possibly never.
    #[cfg(feature = "packetmeta-timestamp")]
    pub fn poll_tx_timestamp(&mut self) -> Option<crate::meta::TxTimestamp> {
        self.state_mut().dev.poll_tx_timestamp()
    }

    /// The hardware address of the interface.
    pub fn hardware_addr(&self) -> HardwareAddress {
        self.state().hardware_addr
    }

    /// Set the hardware address of the interface.
    ///
    /// The stack starts using it for the frames it sends and for ingress filtering
    /// immediately. It does not announce the change on the link, so peers keep the
    /// old address in their neighbor caches until it expires. Send a gratuitous ARP
    /// or unsolicited neighbor advertisement from a raw socket if that matters.
    ///
    /// # Panics
    /// Panics if the address is not of the kind the device's medium uses.
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        let medium = self.state().dev.capabilities().medium;
        assert_eq!(
            addr.medium(),
            medium,
            "hardware address does not match the interface's medium"
        );
        self.state_mut().hardware_addr = addr;
    }

    /// The IP addresses assigned to the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        &self.state().ip_addrs
    }

    /// Check whether the given address is assigned to the interface.
    pub fn has_ip_addr(&self, addr: impl Into<IpAddress>) -> bool {
        self.state().has_ip_addr(addr)
    }

    /// Assign an IP address to the interface.
    ///
    /// If the same address is already assigned, its prefix is updated and the
    /// previous CIDR returned. Otherwise the address is appended and `None` is
    /// returned. Source address selection prefers the first address matching the
    /// destination's subnet, so ordering only matters between addresses of the same
    /// subnet.
    ///
    /// # Panics
    /// Panics if the address is not unicast.
    pub fn add_ip_addr(&mut self, cidr: IpCidr) -> Option<IpCidr> {
        assert!(
            cidr.address().is_unicast(),
            "only unicast addresses can be assigned to an interface"
        );

        let ip_addrs = &mut self.state_mut().ip_addrs;
        match ip_addrs.iter().position(|old| old.address() == cidr.address()) {
            Some(index) if ip_addrs[index] == cidr => Some(cidr),
            Some(index) => {
                let old = core::mem::replace(&mut ip_addrs[index], cidr);
                self.invalidate();
                Some(old)
            }
            None => {
                ip_addrs.push(cidr);
                None
            }
        }
    }

    /// Unassign an IP address from the interface, returning the CIDR it was
    /// assigned with, or `None` if it was not assigned.
    pub fn remove_ip_addr(&mut self, addr: impl Into<IpAddress>) -> Option<IpCidr> {
        let addr = addr.into();
        let ip_addrs = &mut self.state_mut().ip_addrs;
        let index = ip_addrs.iter().position(|cidr| cidr.address() == addr)?;
        let removed = ip_addrs.remove(index);
        self.invalidate();
        Some(removed)
    }

    /// Replace the interface's entire set of IP addresses.
    ///
    /// Equivalent to removing every address and adding the given ones.
    ///
    /// # Panics
    /// Panics if any of the addresses is not unicast.
    pub fn set_ip_addrs(&mut self, addrs: impl IntoIterator<Item = IpCidr>) {
        let addrs: Vec<IpCidr> = addrs.into_iter().collect();
        assert!(
            addrs.iter().all(|cidr| cidr.address().is_unicast()),
            "only unicast addresses can be assigned to an interface"
        );

        let ip_addrs = &mut self.state_mut().ip_addrs;
        if *ip_addrs == addrs {
            return;
        }
        *ip_addrs = addrs;
        self.invalidate();
    }

    /// Purge state associated to this interface.
    fn invalidate(&mut self) {
        #[cfg(feature = "medium-ethernet")]
        {
            let handle = IfaceHandle(self.index);
            self.inner.neighbor_cache.purge_iface(handle);
            self.inner.pending.purge_iface(handle);
        }
    }
}

/// The device-independent part of the stack.
///
/// Separate from `Stack` so that its methods can borrow an interface from `Stack::ifaces`
/// while taking `&mut self`.
pub(crate) struct StackInner {
    pub(crate) now: Instant,
    #[cfg_attr(not(any(feature = "socket-udp", feature = "socket-tcp")), allow(dead_code))]
    pub(crate) rand: Rand,
    #[cfg(feature = "medium-ethernet")]
    neighbor_cache: NeighborCache,
    #[cfg(feature = "medium-ethernet")]
    pending: PendingQueue,
    routes: Routes,
}

/// Borrowed stack context for socket egress.
///
/// Sockets hand fully-built L4 packets to [`TxContext::transmit_ip`]. Picking the
/// egress interface, building the IP header and resolving the neighbor all happen
/// in here, so socket code doesn't have to care about any of it.
#[cfg(feature = "socket")]
pub(crate) struct TxContext<'a> {
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<IfaceState>,
}

/// A complete egress routing decision for one destination, produced by
/// [`TxContext::route`]: the interface the packet goes out of, the next hop to
/// resolve on that link, and the interface's IP MTU.
///
/// Made once per packet: callers that need routing information before building
/// the packet (TCP sizes segments by the egress MTU) route first and then
/// transmit via [`TxContext::transmit_ip_routed`], so the packet is never routed
/// twice.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
#[cfg(feature = "socket")]
pub(crate) struct EgressRoute {
    pub(crate) iface: IfaceHandle,
    /// The address to resolve on the link: the destination itself when on-link
    /// (or broadcast/multicast), else the gateway from the routing table.
    pub(crate) next_hop: IpAddress,
    /// The egress interface's IP-layer MTU.
    #[cfg_attr(not(feature = "socket-tcp"), allow(dead_code))]
    pub(crate) ip_mtu: usize,
}

#[cfg(feature = "socket")]
impl TxContext<'_> {
    /// The current time, as last set by [`Stack::poll`].
    #[cfg(feature = "socket-tcp")]
    pub(crate) fn now(&self) -> Instant {
        self.inner.now
    }

    /// The stack's PRNG.
    #[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.inner.rand
    }

    /// Check whether any interface has the given IP address assigned.
    #[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
    pub(crate) fn has_ip_addr(&self, addr: IpAddress) -> bool {
        self.ifaces.iter().any(|(_, iface)| iface.has_ip_addr(addr))
    }

    /// Get a source address for sending to the given destination, selected from the
    /// interface the packet would go out of.
    #[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        let route = self.route(dst_addr)?;
        self.ifaces.get(route.iface.0).get_source_address(dst_addr)
    }

    /// Make the egress routing decision for a destination: the interface the
    /// destination is on-link for (next hop: the destination itself), else the
    /// interface and gateway named by the matching route.
    pub(crate) fn route(&self, dst_addr: &IpAddress) -> Option<EgressRoute> {
        if !dst_addr.is_unicast() {
            // Broadcast and multicast destinations carry nothing to route on, so
            // they go out the first interface. The next hop is the destination
            // itself, resolved to a broadcast/multicast hardware address.
            // TODO: let the send API pick the interface.
            return self.ifaces.iter().next().map(|(_, iface)| EgressRoute {
                iface: iface.handle,
                next_hop: *dst_addr,
                ip_mtu: iface.ip_mtu(),
            });
        }

        if let Some((_, iface)) = self.ifaces.iter().find(|(_, iface)| iface.in_same_network(dst_addr)) {
            return Some(EgressRoute {
                iface: iface.handle,
                next_hop: *dst_addr,
                ip_mtu: iface.ip_mtu(),
            });
        }

        let route = self.inner.routes.lookup(dst_addr, self.inner.now)?;
        Some(EgressRoute {
            iface: route.iface,
            next_hop: route.via_router,
            ip_mtu: self.ifaces.get(route.iface.0).ip_mtu(),
        })
    }

    /// Transmit a fully-built IP payload, with the L4 header but not the IP header.
    ///
    /// `src_addr` and `dst_addr` must belong to the same address family, the packet
    /// is dropped otherwise.
    #[cfg(feature = "socket-udp")]
    pub(crate) fn transmit_ip(
        &mut self,
        buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let Some(route) = self.route(&dst_addr) else {
            debug!("no route to {}, dropping packet", dst_addr);
            return;
        };
        self.transmit_ip_routed(&route, buf, src_addr, dst_addr, next_header, hop_limit);
    }

    /// [`transmit_ip`](Self::transmit_ip) for a destination the caller already
    /// routed: transmit on the decided interface, resolving `route.next_hop`
    /// instead of routing again.
    #[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
    pub(crate) fn transmit_ip_routed(
        &mut self,
        route: &EgressRoute,
        mut buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let iface = self.ifaces.get_mut(route.iface.0);
        let ethertype = match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                push_ipv4_header(&mut buf, src, dst, next_header, hop_limit);
                EthernetProtocol::Ipv4
            }
            #[cfg(feature = "proto-ipv6")]
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                push_ipv6_header(&mut buf, src, dst, next_header, hop_limit);
                EthernetProtocol::Ipv6
            }
            #[allow(unreachable_patterns)]
            _ => {
                debug!("cannot transmit, address family mismatch");
                return;
            }
        };
        self.inner
            .transmit_ip_frame(iface, dst_addr, Some(route.next_hop), buf, ethertype);
    }

    /// Transmit a fully-built Ethernet frame on the given interface, as-is.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    #[cfg(all(feature = "socket-raw", feature = "medium-ethernet"))]
    pub(crate) fn transmit_ethernet_frame(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        let iface = self.ifaces.get_mut(iface.0);
        self.inner.transmit_raw(iface, buf);
    }

    /// Transmit a fully-built IP packet (IP header included, emitted as-is): pick
    /// the egress interface from the destination address, resolve the neighbor, and
    /// hand the frame to the device.
    ///
    /// Returns `false` if there is no route to the destination.
    #[cfg(feature = "socket-raw")]
    pub(crate) fn transmit_raw_ip(&mut self, buf: PacketBuf, dst_addr: IpAddress) -> bool {
        let Some(route) = self.route(&dst_addr) else {
            debug!("no route to {}, dropping packet", dst_addr);
            return false;
        };
        let iface = self.ifaces.get_mut(route.iface.0);
        let ethertype = match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
        };
        self.inner
            .transmit_ip_frame(iface, dst_addr, Some(route.next_hop), buf, ethertype);
        true
    }
}

/// Score `addr` against a bind's address filter, the way ingress demux ranks
/// candidate sockets: `None` if it does not match, else how specific the filter
/// that matched it is. No address matches anything (0), an unspecified one
/// matches its own IP version (1), and a concrete one matches only itself (2).
#[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
pub(crate) fn addr_score(filter: &IpListenEndpoint, addr: &IpAddress) -> Option<u8> {
    match filter.addr {
        None => Some(0),
        Some(a) if a.is_unspecified() => (a.version() == addr.version()).then_some(1),
        Some(a) => (a == *addr).then_some(2),
    }
}

/// The bottom of the ephemeral (dynamic) local port range, per IANA. The range
/// runs to the top of the port space, 65535.
#[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;

/// Allocate an ephemeral local port: start at a random point in the range and
/// linearly probe upward (wrapping) for the first port `in_use` doesn't claim.
///
/// The random start makes local ports hard to predict for off-path attackers
/// (RFC 6056 §3.3). `None` is returned only when every port in the range is in use.
#[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
pub(crate) fn alloc_ephemeral_port(rand: &mut Rand, mut in_use: impl FnMut(u16) -> bool) -> Option<u16> {
    const RANGE: u32 = (u16::MAX - EPHEMERAL_PORT_MIN) as u32 + 1;
    let start = rand.rand_u32() % RANGE;
    (0..RANGE)
        .map(|i| EPHEMERAL_PORT_MIN + ((start + i) % RANGE) as u16)
        .find(|&port| !in_use(port))
}

/// The result of a neighbor lookup.
#[cfg(feature = "medium-ethernet")]
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
    ///
    /// `random_seed` seeds the stack's PRNG, which picks TCP initial sequence
    /// numbers and ephemeral ports. This should be random, or at least different
    /// at every boot.
    pub fn new(random_seed: u64) -> Self {
        Self {
            inner: StackInner {
                now: Instant::ZERO,
                rand: Rand::new(random_seed),
                #[cfg(feature = "medium-ethernet")]
                neighbor_cache: NeighborCache::new(),
                #[cfg(feature = "medium-ethernet")]
                pending: PendingQueue::new(),
                routes: Routes::new(),
            },
            ifaces: Slab::new(),
            sockets: Sockets {
                #[cfg(feature = "socket-udp")]
                udp: Slab::new(),
                #[cfg(feature = "socket-raw")]
                raw: Slab::new(),
                #[cfg(feature = "socket-tcp")]
                tcp: Slab::new(),
                #[cfg(feature = "socket-tcp")]
                tcp_listeners: Slab::new(),
            },
        }
    }

    /// Add an interface to the stack, returning a handle to it.
    ///
    /// Configure the interface after adding it. At minimum, you will want to
    /// add an IP address to it.
    ///
    /// ```no_run
    /// # use xarxa::{Stack, iface::Interface, wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address}};
    /// # fn configure(stack: &mut Stack, dev: Box<dyn Interface>) {
    /// let handle = stack.add_iface(
    ///     dev,
    ///     HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01])),
    /// );
    /// stack
    ///     .iface(handle)
    ///     .add_ip_addr(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 24));
    /// # }
    /// ```
    ///
    /// # Panics
    /// Panics if the hardware address is not of the kind the device's medium uses.
    pub fn add_iface(&mut self, dev: Box<dyn Interface>, hardware_addr: HardwareAddress) -> IfaceHandle {
        assert_eq!(
            hardware_addr.medium(),
            dev.capabilities().medium,
            "hardware address does not match the interface's medium"
        );
        let index = self.ifaces.add_with(|index| IfaceState {
            handle: IfaceHandle(index),
            dev,
            hardware_addr,
            ip_addrs: Vec::new(),
        });
        IfaceHandle(index)
    }

    /// Borrow an interface from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    pub fn iface(&mut self, handle: IfaceHandle) -> Iface<'_> {
        self.ifaces.get(handle.0); // Stale handles panic here, not on first use.
        Iface {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
            index: handle.0,
        }
    }

    /// Remove an interface from the stack, returning the device.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was already removed).
    pub fn remove_iface(&mut self, handle: IfaceHandle) -> Box<dyn Interface> {
        let iface = self.ifaces.remove(handle.0);
        #[cfg(feature = "medium-ethernet")]
        {
            self.inner.neighbor_cache.purge_iface(handle);
            self.inner.pending.purge_iface(handle);
        }
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
    #[cfg(feature = "socket-udp")]
    pub fn add_udp_socket(&mut self) -> UdpHandle {
        UdpHandle(self.sockets.udp.add_with(|_| UdpSocketState::new()))
    }

    /// Remove a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "socket-udp")]
    pub fn remove_udp_socket(&mut self, handle: UdpHandle) {
        self.sockets.udp.remove(handle.0);
    }

    /// Borrow a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "socket-udp")]
    pub fn udp_socket(&mut self, handle: UdpHandle) -> UdpSocket<'_> {
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
    #[cfg(feature = "socket-raw")]
    pub fn add_raw_socket(&mut self) -> RawHandle {
        RawHandle(self.sockets.raw.add_with(|_| RawSocketState::new()))
    }

    /// Remove a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "socket-raw")]
    pub fn remove_raw_socket(&mut self, handle: RawHandle) {
        self.sockets.raw.remove(handle.0);
    }

    /// Borrow a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "socket-raw")]
    pub fn raw_socket(&mut self, handle: RawHandle) -> RawSocket<'_> {
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
    #[cfg(feature = "socket-tcp")]
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
    #[cfg(feature = "socket-tcp")]
    pub fn remove_tcp_socket(&mut self, handle: TcpHandle) {
        self.sockets.tcp.remove(handle.0);
    }

    /// Borrow a TCP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "socket-tcp")]
    pub fn tcp_socket(&mut self, handle: TcpHandle) -> TcpSocket<'_> {
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
    #[cfg(feature = "socket-tcp")]
    pub fn add_tcp_listener(&mut self) -> TcpListenerHandle {
        TcpListenerHandle(self.sockets.tcp_listeners.add_with(|_| TcpListenerState::new()))
    }

    /// Remove a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "socket-tcp")]
    pub fn remove_tcp_listener(&mut self, handle: TcpListenerHandle) {
        self.sockets.tcp_listeners.remove(handle.0);
    }

    /// Borrow a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "socket-tcp")]
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
    #[cfg(all(
        test,
        feature = "socket-tcp",
        feature = "medium-ip",
        feature = "proto-ipv4",
        feature = "proto-ipv6"
    ))]
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
        #[cfg(feature = "medium-ethernet")]
        self.inner.pending.purge_expired(timestamp);

        for (_, iface) in self.ifaces.iter_mut() {
            #[cfg(feature = "medium-ethernet")]
            self.inner.poll_neighbor_timers(iface, &mut self.sockets);

            while let Some(buf) = iface.dev.receive() {
                self.inner.process(iface, &mut self.sockets, buf);
            }
        }

        // Drive TCP egress: this both acknowledges what ingress just delivered and
        // advances the TCP timers (retransmissions, delayed ACKs, keep-alives,
        // zero-window probes, ...).
        #[cfg(feature = "socket-tcp")]
        let tcp_poll_at = {
            let mut cx = TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            };
            for (_, socket) in self.sockets.tcp.iter_mut() {
                crate::tcp::flush(socket, &mut cx);
            }

            self.sockets
                .tcp
                .iter()
                .filter_map(|(_, socket)| match socket.poll_at() {
                    PollAt::Now => Some(timestamp),
                    PollAt::Time(t) => Some(t),
                    PollAt::Ingress => None,
                })
        };
        #[cfg(not(feature = "socket-tcp"))]
        let tcp_poll_at = core::iter::empty();

        #[cfg(feature = "medium-ethernet")]
        let timers = [self.inner.neighbor_cache.poll_at(), self.inner.pending.poll_at()];
        #[cfg(not(feature = "medium-ethernet"))]
        let timers: [Option<Instant>; 0] = [];

        timers.into_iter().flatten().chain(tcp_poll_at).min()
    }
}

impl StackInner {
    fn process(&mut self, iface: &mut IfaceState, sockets: &mut Sockets, buf: PacketBuf) {
        match iface.dev.capabilities().medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => self.process_ethernet(iface, sockets, buf),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.process_ip(iface, sockets, buf),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet(&mut self, iface: &mut IfaceState, sockets: &mut Sockets, mut buf: PacketBuf) {
        let eth_frame = check!(EthernetFrame::new_checked(&mut buf));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != iface.ethernet_addr()
        {
            return;
        }

        let src_addr = eth_frame.src_addr();
        let ethertype = eth_frame.ethertype();

        // Offer the whole frame to Ethernet-mode raw sockets. Ethertypes the stack
        // itself processes are copied to the socket, everything else is consumed
        // by it.
        #[cfg(feature = "socket-raw")]
        let Some(mut buf) = ({
            let stack_wants = matches!(
                ethertype,
                EthernetProtocol::Arp | EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6
            );
            self.process_raw_ethernet(iface, &mut sockets.raw, ethertype, stack_wants, buf)
        }) else {
            return;
        };

        buf.pull_front(ETHERNET_HEADER_LEN);

        match ethertype {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp(iface, buf),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => self.process_ipv4(iface, sockets, Some(src_addr), buf),
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => self.process_ipv6(iface, sockets, Some(src_addr), buf),
            // Drop all other traffic.
            _ => {}
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip(&mut self, iface: &mut IfaceState, sockets: &mut Sockets, buf: PacketBuf) {
        if buf.is_empty() {
            return;
        }
        match IpVersion::of_packet(&buf) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => self.process_ipv4(iface, sockets, None, buf),
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => self.process_ipv6(iface, sockets, None, buf),
            Err(_) => {}
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn process_arp(&mut self, iface: &mut IfaceState, mut buf: PacketBuf) {
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
                arp_reply.set_source_hardware_addr(iface.ethernet_addr().as_bytes());
                arp_reply.set_source_protocol_addr(&target_protocol_addr.octets());
                arp_reply.set_target_hardware_addr(source_hardware_addr.as_bytes());
                arp_reply.set_target_protocol_addr(&source_protocol_addr.octets());
            }
            self.transmit_ethernet(iface, source_hardware_addr, reply, EthernetProtocol::Arp);
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_ipv4(
        &mut self,
        iface: &mut IfaceState,
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

        #[cfg(feature = "medium-ethernet")]
        if let Some(eth_src) = eth_src
            && iface.is_unicast_v4(dst_addr)
        {
            self.neighbor_cache
                .reset_expiry_if_existing((iface.handle, IpAddress::Ipv4(src_addr)), eth_src, self.now);
        }
        #[cfg(not(feature = "medium-ethernet"))]
        let _ = eth_src;

        // Strip any trailing padding added by the link layer.
        buf.set_len(total_len);

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        #[cfg_attr(not(feature = "socket-udp"), allow(unused_variables))]
        #[cfg(feature = "socket-raw")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmp | IpProtocol::Udp | IpProtocol::Tcp);
            self.process_raw_ip(&mut sockets.raw, IpVersion::Ipv4, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "socket-udp"), allow(unused_variables))]
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw = false;

        // Strip the IP header.
        buf.pull_front(header_len);

        match next_header {
            IpProtocol::Icmp => self.process_icmpv4(iface, sockets, src_addr, dst_addr, buf),
            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                &mut sockets.udp,
                IpAddress::Ipv4(src_addr),
                IpAddress::Ipv4(dst_addr),
                header_len,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "socket-tcp")]
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
                // ICMP protocol unreachable (RFC 792): restore the IP header so the
                // whole offending packet can be quoted.
                buf.push_front(header_len);
                self.transmit_icmpv4_error(
                    iface,
                    &mut buf,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::ProtoUnreachable.into(),
                );
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
    #[cfg(feature = "socket-tcp")]
    fn process_tcp(
        &mut self,
        iface: &mut IfaceState,
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
    #[cfg(feature = "socket-tcp")]
    fn transmit_tcp(
        &mut self,
        iface: &mut IfaceState,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        hop_limit: u8,
        repr: &TcpRepr<'_>,
    ) {
        let buf = crate::tcp::build_tcp_packet(repr, &src_addr, &dst_addr);
        match (src_addr, dst_addr) {
            #[cfg(feature = "proto-ipv4")]
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                self.transmit_ipv4(iface, buf, src, dst, IpProtocol::Tcp, hop_limit)
            }
            #[cfg(feature = "proto-ipv6")]
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                self.transmit_ipv6(iface, buf, src, dst, IpProtocol::Tcp, hop_limit)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    fn process_icmpv4(
        &mut self,
        iface: &mut IfaceState,
        sockets: &mut Sockets,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        mut buf: PacketBuf,
    ) {
        let mut icmp_packet = check!(Icmpv4Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum() {
            trace!("icmpv4: checksum incorrect");
            return;
        }

        #[cfg(not(feature = "auto-icmp-echo-reply"))]
        let _ = (&iface, src_addr, dst_addr);
        #[cfg(not(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp"))))]
        let _ = (&mut icmp_packet, &sockets);

        match (icmp_packet.msg_type(), icmp_packet.msg_code()) {
            // Respond to echo requests.
            #[cfg(feature = "auto-icmp-echo-reply")]
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
                reply.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
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

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp")))]
            (msg_type, msg_code) if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
                    self.deliver_icmp_error(sockets, error, icmp_packet.data_mut());
                }
            }

            _ => {}
        }
    }

    /// Deliver an ICMP error message to the socket whose packet provoked it.
    ///
    /// `quote` is the offending packet quoted in the error, a packet *we sent*, so
    /// its source identifies the socket's local endpoint and its destination the
    /// remote. UDP demux scores the sockets like ordinary ingress (most specific
    /// match wins). TCP demux is by exact 4-tuple, and the socket additionally
    /// validates the quoted sequence number against its send window, so blindly
    /// spoofed errors cannot reset connections (RFC 5927).
    #[cfg(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp")))]
    fn deliver_icmp_error(&mut self, sockets: &mut Sockets, error: IcmpError, quote: &mut [u8]) {
        let Some(quoted) = parse_quoted_packet(quote) else {
            trace!("icmp error: quote too short to identify a flow, ignoring");
            return;
        };
        let local = IpEndpoint::new(quoted.src_addr, quoted.src_port);
        let remote = IpEndpoint::new(quoted.dst_addr, quoted.dst_port);
        match quoted.protocol {
            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp => crate::udp::process_icmp_error(&mut sockets.udp, error, local, remote),
            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => crate::tcp::process_icmp_error(&mut sockets.tcp, error, local, remote, quoted.tcp_seq),
            _ => {}
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_ipv6(
        &mut self,
        iface: &mut IfaceState,
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

        #[cfg(feature = "medium-ethernet")]
        if let Some(eth_src) = eth_src
            && dst_addr.x_is_unicast()
        {
            self.neighbor_cache
                .reset_expiry_if_existing((iface.handle, IpAddress::Ipv6(src_addr)), eth_src, self.now);
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(IPV6_HEADER_LEN + payload_len);

        // Hop-by-hop options (RFC 8200 §4.3): walk the options, then continue at the
        // upper-layer header behind the extension header. `l4_offset` is where that
        // header starts, `nh_offset` is the offset of the field naming it, quoted in
        // the "unrecognized next header" error pointer.
        let (next_header, l4_offset, nh_offset) = if next_header == IpProtocol::HopByHop {
            match check!(process_hop_by_hop(&buf[IPV6_HEADER_LEN..])) {
                HopByHopAction::Continue { next_header, ext_len } => {
                    (next_header, IPV6_HEADER_LEN + ext_len, IPV6_HEADER_LEN)
                }
                HopByHopAction::Discard => return,
                HopByHopAction::DiscardSendError {
                    pointer,
                    allow_multicast_dst,
                } => {
                    self.transmit_icmpv6_error(
                        iface,
                        &mut buf,
                        Icmpv6Message::ParamProblem,
                        Icmpv6ParamProblem::UnrecognizedOption.into(),
                        pointer,
                        allow_multicast_dst,
                    );
                    return;
                }
            }
        } else {
            // 6 is the offset of the fixed header's next header field.
            (next_header, IPV6_HEADER_LEN, 6)
        };

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        #[cfg_attr(not(feature = "socket-udp"), allow(unused_variables))]
        #[cfg(feature = "socket-raw")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmpv6 | IpProtocol::Udp | IpProtocol::Tcp);
            self.process_raw_ip(&mut sockets.raw, IpVersion::Ipv6, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "socket-udp"), allow(unused_variables))]
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw = false;

        // Strip the IP header (and any extension headers).
        buf.pull_front(l4_offset);

        match next_header {
            IpProtocol::Icmpv6 => self.process_icmpv6(iface, sockets, eth_src, src_addr, dst_addr, hop_limit, buf),
            #[cfg(feature = "socket-udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                &mut sockets.udp,
                IpAddress::Ipv6(src_addr),
                IpAddress::Ipv6(dst_addr),
                l4_offset,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "socket-tcp")]
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
                // ICMPv6 parameter problem, unrecognized next header (RFC 4443
                // §3.4): restore the headers so the whole offending packet can be
                // quoted. The pointer names the next header field that held the
                // unrecognized value.
                buf.push_front(l4_offset);
                self.transmit_icmpv6_error(
                    iface,
                    &mut buf,
                    Icmpv6Message::ParamProblem,
                    Icmpv6ParamProblem::UnrecognizedNxtHdr.into(),
                    nh_offset as u32,
                    false,
                );
            }
        }
    }

    #[cfg(feature = "proto-ipv6")]
    fn process_icmpv6(
        &mut self,
        iface: &mut IfaceState,
        sockets: &mut Sockets,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
        mut buf: PacketBuf,
    ) {
        #[cfg(not(all(feature = "medium-ethernet", feature = "proto-ipv6")))]
        let _ = (eth_src, hop_limit);
        #[cfg(not(feature = "auto-icmp-echo-reply"))]
        let _ = &iface;

        let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum(&src_addr, &dst_addr) {
            trace!("icmpv6: checksum incorrect");
            return;
        }

        #[cfg(not(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp"))))]
        let _ = (&mut icmp_packet, &sockets);

        match icmp_packet.msg_type() {
            // Respond to echo requests.
            #[cfg(feature = "auto-icmp-echo-reply")]
            Icmpv6Message::EchoRequest => {
                let reply_src = if dst_addr.x_is_unicast() {
                    dst_addr
                } else {
                    iface.get_source_address_ipv6(&src_addr)
                };

                let mut reply = PacketBuf::new();
                reply.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
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

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-error-handling", any(feature = "socket-udp", feature = "socket-tcp")))]
            msg_type if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv6(msg_type, icmp_packet.msg_code()) {
                    self.deliver_icmp_error(sockets, error, icmp_packet.payload_mut());
                }
            }

            // NDISC is only processed if the packet arrived with the un-decremented
            // hop limit, and only on Ethernet mediums.
            #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
            Icmpv6Message::NeighborSolicit if hop_limit == 0xff && eth_src.is_some() => {
                self.process_ndisc_solicit(iface, src_addr, dst_addr, &mut icmp_packet)
            }

            #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
            Icmpv6Message::NeighborAdvert if hop_limit == 0xff && eth_src.is_some() => {
                self.process_ndisc_advert(iface, src_addr, &mut icmp_packet)
            }

            _ => {}
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn process_ndisc_solicit(
        &mut self,
        iface: &mut IfaceState,
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
                    opt.set_link_layer_addr(RawHardwareAddress::from(iface.ethernet_addr()));
                }
                na.fill_checksum(&target_addr, &src_addr);
            }
            self.transmit_ipv6(iface, reply, target_addr, src_addr, IpProtocol::Icmpv6, 0xff);
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn process_ndisc_advert(
        &mut self,
        iface: &mut IfaceState,
        src_addr: Ipv6Address,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
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
    #[cfg(feature = "medium-ethernet")]
    fn poll_neighbor_timers(&mut self, iface: &mut IfaceState, sockets: &mut Sockets) {
        #[cfg(not(feature = "icmp-error-handling"))]
        let _ = &sockets;

        for event in self.neighbor_cache.poll_retransmit(iface.handle, self.now) {
            match event {
                ProbeEvent::Retransmit(addr) => {
                    debug!("neighbor {} still unresolved, retransmitting solicitation", addr);
                    self.solicit_neighbor(iface, addr);
                }
                ProbeEvent::Failed(addr) => {
                    debug!("neighbor {} resolution failed, dropping queued packets", addr);
                    // RFC 4861 §7.3.3: answer each packet queued on the failed
                    // resolution with an ICMP destination unreachable error.
                    #[cfg(feature = "icmp-error-handling")]
                    for packet in self.pending.take_matching(&(iface.handle, addr)) {
                        self.deliver_neighbor_failure_error(iface, sockets, packet.buf);
                    }
                    #[cfg(not(feature = "icmp-error-handling"))]
                    drop(self.pending.take_matching(&(iface.handle, addr)));
                }
            }
        }
    }

    /// Build an ICMP destination unreachable error for a packet whose neighbor
    /// resolution failed, and deliver it back through local ingress processing.
    ///
    /// Queued packets are locally generated (nothing is forwarded), so the sender
    /// the error must reach is a local socket. The error is fed into ingress,
    /// where the erring TCP/UDP socket, or a raw-socket ping application,
    /// receives it, rather than transmitted to the wire. `orig` is the queued
    /// packet, a whole IP frame.
    #[cfg(all(feature = "medium-ethernet", feature = "icmp-error-handling"))]
    fn deliver_neighbor_failure_error(&mut self, iface: &mut IfaceState, sockets: &mut Sockets, mut orig: PacketBuf) {
        match IpVersion::of_packet(&orig) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let (src_addr, header_len, next_header) = {
                    let packet = Ipv4Packet::new_unchecked(&mut orig);
                    (packet.src_addr(), packet.header_len() as usize, packet.next_header())
                };
                // Never generate an ICMP error about an ICMP error (RFC 1122 §3.2.2).
                if next_header == IpProtocol::Icmp
                    && orig.get(header_len).is_some_and(|&t| Icmpv4Message::from(t).is_error())
                {
                    return;
                }
                if !iface.is_unicast_v4(src_addr) {
                    return;
                }
                let Some(reply_src) = iface.get_source_address_ipv4(&src_addr) else {
                    return;
                };
                let mut reply = build_icmpv4_error(
                    &orig,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::HostUnreachable.into(),
                );
                push_ipv4_header(&mut reply, reply_src, src_addr, IpProtocol::Icmp, 64);
                self.process_ipv4(iface, sockets, None, reply);
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let (src_addr, next_header) = {
                    let packet = Ipv6Packet::new_unchecked(&mut orig);
                    (packet.src_addr(), packet.next_header())
                };
                // Never generate an ICMP error about an ICMP error (RFC 4443 §2.4).
                if next_header == IpProtocol::Icmpv6
                    && orig
                        .get(IPV6_HEADER_LEN)
                        .is_some_and(|&t| Icmpv6Message::from(t).is_error())
                {
                    return;
                }
                if !src_addr.x_is_unicast() {
                    return;
                }
                let reply_src = iface.get_source_address_ipv6(&src_addr);
                let mut reply = build_icmpv6_error(
                    &orig,
                    &reply_src,
                    &src_addr,
                    Icmpv6Message::DstUnreachable,
                    Icmpv6DstUnreachable::AddrUnreachable.into(),
                    0,
                );
                push_ipv6_header(&mut reply, reply_src, src_addr, IpProtocol::Icmpv6, 64);
                self.process_ipv6(iface, sockets, None, reply);
            }
            Err(_) => {}
        }
    }

    /// Send a solicitation (ARP request / NDISC neighbor solicit) for the given address.
    #[cfg(feature = "medium-ethernet")]
    fn solicit_neighbor(&mut self, iface: &mut IfaceState, addr: IpAddress) {
        match addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.transmit_arp_request(iface, addr),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => self.transmit_ndisc_solicit(iface, addr),
        }
    }

    /// Fill the neighbor cache, and flush any packets that were queued waiting for
    /// this neighbor to resolve.
    #[cfg(feature = "medium-ethernet")]
    fn fill_neighbor(&mut self, iface: &mut IfaceState, addr: IpAddress, hardware_addr: EthernetAddress) {
        let key = (iface.handle, addr);
        self.neighbor_cache.fill(key, hardware_addr, self.now);

        for packet in self.pending.take_matching(&key) {
            trace!("neighbor: {} resolved, flushing queued packet", addr);
            let ethertype = match packet.key.1 {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
            };
            self.transmit_ethernet(iface, hardware_addr, packet.buf, ethertype);
        }
    }

    /// Look up the destination hardware address for an egress packet, sending a
    /// solicitation (ARP request / NDISC neighbor solicit) if it is not resolved yet.
    ///
    /// `next_hop` is the pre-routed address to resolve, if the caller already made
    /// the routing decision. `None` routes here.
    #[cfg(feature = "medium-ethernet")]
    fn lookup_hardware_addr(
        &mut self,
        iface: &mut IfaceState,
        dst_addr: &IpAddress,
        next_hop: Option<IpAddress>,
    ) -> NeighborLookup {
        if iface.is_broadcast(dst_addr) {
            return NeighborLookup::Found(EthernetAddress::BROADCAST);
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x01, 0x00, 0x5e, b[1] & 0x7F, b[2], b[3]])
                }
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x33, 0x33, b[12], b[13], b[14], b[15]])
                }
            };

            return NeighborLookup::Found(hardware_addr);
        }

        let next_hop = match next_hop {
            Some(next_hop) => next_hop,
            None => match self.route(iface, dst_addr) {
                Some(next_hop) => next_hop,
                None => return NeighborLookup::NoRoute,
            },
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

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
    fn transmit_arp_request(&mut self, iface: &mut IfaceState, target_addr: Ipv4Address) {
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
            arp_packet.set_source_hardware_addr(iface.ethernet_addr().as_bytes());
            arp_packet.set_source_protocol_addr(&source_protocol_addr.octets());
            arp_packet.set_target_hardware_addr(EthernetAddress::BROADCAST.as_bytes());
            arp_packet.set_target_protocol_addr(&target_addr.octets());
        }
        self.transmit_ethernet(iface, EthernetAddress::BROADCAST, buf, EthernetProtocol::Arp);
    }

    #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
    fn transmit_ndisc_solicit(&mut self, iface: &mut IfaceState, target_addr: Ipv6Address) {
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
                opt.set_link_layer_addr(RawHardwareAddress::from(iface.ethernet_addr()));
            }
            ns.fill_checksum(&src_addr, &dst_addr);
        }
        // The solicited-node destination is multicast, so this never recurses back
        // into neighbor resolution.
        self.transmit_ipv6(iface, buf, src_addr, dst_addr, IpProtocol::Icmpv6, 0xff);
    }

    /// Transmit an ICMPv4 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are only sent when both the source and the destination of the
    /// offending packet are unicast (RFC 1122 §3.2.2): none about broadcast or
    /// multicast traffic, and none to non-unicast senders.
    #[cfg(feature = "proto-ipv4")]
    pub(crate) fn transmit_icmpv4_error(
        &mut self,
        iface: &mut IfaceState,
        orig: &mut PacketBuf,
        msg_type: Icmpv4Message,
        msg_code: u8,
    ) {
        let (src_addr, dst_addr) = {
            let packet = Ipv4Packet::new_unchecked(orig);
            (packet.src_addr(), packet.dst_addr())
        };
        if !iface.is_unicast_v4(src_addr) || !iface.is_unicast_v4(dst_addr) {
            return;
        }
        let reply = build_icmpv4_error(orig, msg_type, msg_code);
        self.transmit_ipv4(iface, reply, dst_addr, src_addr, IpProtocol::Icmp, 64);
    }

    /// Transmit an ICMPv6 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are never sent to non-unicast sources, nor about multicast-destined
    /// packets (RFC 4443 §2.4). The exception is an unrecognized hop-by-hop option
    /// whose type demands the error even then (`allow_multicast_dst`).
    #[cfg(feature = "proto-ipv6")]
    pub(crate) fn transmit_icmpv6_error(
        &mut self,
        iface: &mut IfaceState,
        orig: &mut PacketBuf,
        msg_type: Icmpv6Message,
        msg_code: u8,
        pointer: u32,
        allow_multicast_dst: bool,
    ) {
        let (src_addr, dst_addr) = {
            let packet = Ipv6Packet::new_unchecked(orig);
            (packet.src_addr(), packet.dst_addr())
        };
        if !src_addr.x_is_unicast() {
            return;
        }
        if dst_addr.is_multicast() && !allow_multicast_dst {
            return;
        }
        let reply_src = if dst_addr.x_is_unicast() {
            dst_addr
        } else {
            iface.get_source_address_ipv6(&src_addr)
        };
        let reply = build_icmpv6_error(orig, &reply_src, &src_addr, msg_type, msg_code, pointer);
        self.transmit_ipv6(iface, reply, reply_src, src_addr, IpProtocol::Icmpv6, 64);
    }

    #[cfg(feature = "proto-ipv4")]
    fn transmit_ipv4(
        &mut self,
        iface: &mut IfaceState,
        mut buf: PacketBuf,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        push_ipv4_header(&mut buf, src_addr, dst_addr, next_header, hop_limit);
        self.transmit_ip_frame(iface, IpAddress::Ipv4(dst_addr), None, buf, EthernetProtocol::Ipv4);
    }

    #[cfg(feature = "proto-ipv6")]
    fn transmit_ipv6(
        &mut self,
        iface: &mut IfaceState,
        mut buf: PacketBuf,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        push_ipv6_header(&mut buf, src_addr, dst_addr, next_header, hop_limit);
        self.transmit_ip_frame(iface, IpAddress::Ipv6(dst_addr), None, buf, EthernetProtocol::Ipv6);
    }

    /// Transmit a fully-built IP packet, resolving the destination hardware address
    /// on Ethernet mediums.
    ///
    /// `next_hop` is the pre-routed address to resolve on the link, from an
    /// [`EgressRoute`]. `None` means "route here", for the ingress reply paths,
    /// which transmit on the arrival interface without routing first.
    ///
    /// If the neighbor is not resolved yet, the packet is queued in the interface's
    /// pending queue and flushed when resolution completes.
    fn transmit_ip_frame(
        &mut self,
        iface: &mut IfaceState,
        dst_addr: IpAddress,
        next_hop: Option<IpAddress>,
        buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        #[cfg(not(feature = "medium-ethernet"))]
        let _ = (dst_addr, next_hop, ethertype);

        match iface.dev.capabilities().medium {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.transmit_raw(iface, buf),
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => match self.lookup_hardware_addr(iface, &dst_addr, next_hop) {
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

    #[cfg(feature = "medium-ethernet")]
    fn transmit_ethernet(
        &mut self,
        iface: &mut IfaceState,
        dst_hw: EthernetAddress,
        mut buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        buf.push_front(ETHERNET_HEADER_LEN);
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_hw);
        frame.set_src_addr(iface.ethernet_addr());
        frame.set_ethertype(ethertype);
        self.transmit_raw(iface, buf);
    }

    fn transmit_raw(&mut self, iface: &mut IfaceState, buf: PacketBuf) {
        if iface.dev.transmit(buf).is_err() {
            debug!("iface: cannot transmit, dropping packet");
        }
    }

    /// Route an address to the next hop on the given interface.
    ///
    /// On-link destinations resolve to themselves. Off-link destinations resolve to a
    /// router from the routing table, but only if the route goes out this interface.
    #[cfg(feature = "medium-ethernet")]
    fn route(&self, iface: &IfaceState, addr: &IpAddress) -> Option<IpAddress> {
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

/// Prepend an IPv4 header to a fully-built L4 payload.
#[cfg(feature = "proto-ipv4")]
fn push_ipv4_header(
    buf: &mut PacketBuf,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    next_header: IpProtocol,
    hop_limit: u8,
) {
    let payload_len = buf.len();
    buf.push_front(IPV4_HEADER_LEN);
    let mut packet = Ipv4Packet::new_unchecked(buf);
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

/// Prepend an IPv6 header to a fully-built L4 payload.
#[cfg(feature = "proto-ipv6")]
fn push_ipv6_header(
    buf: &mut PacketBuf,
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    next_header: IpProtocol,
    hop_limit: u8,
) {
    let payload_len = buf.len();
    buf.push_front(IPV6_HEADER_LEN);
    let mut packet = Ipv6Packet::new_unchecked(buf);
    packet.set_version(6);
    packet.set_traffic_class(0);
    packet.set_flow_label(0);
    packet.set_payload_len(payload_len as u16);
    packet.set_next_header(next_header);
    packet.set_hop_limit(hop_limit);
    packet.set_src_addr(src_addr);
    packet.set_dst_addr(dst_addr);
}

/// ICMP error messages have a fixed 8-byte header (type, code, checksum, and a
/// 4-byte type-specific field), followed by the quoted packet.
const ICMP_ERROR_HEADER_LEN: usize = 8;

/// Build an ICMPv4 error message, quoting as much of `orig` (a whole IP packet)
/// as fits within the minimum MTU (RFC 1812 §4.3.2.3).
#[cfg(feature = "proto-ipv4")]
fn build_icmpv4_error(orig: &[u8], msg_type: Icmpv4Message, msg_code: u8) -> PacketBuf {
    let quote_len = orig.len().min(IPV4_MIN_MTU - IPV4_HEADER_LEN - ICMP_ERROR_HEADER_LEN);
    let mut reply = PacketBuf::new();
    reply.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
    reply.set_len(ICMP_ERROR_HEADER_LEN + quote_len);
    {
        let mut icmp = Icmpv4Packet::new_unchecked(&mut reply);
        icmp.set_msg_type(msg_type);
        icmp.set_msg_code(msg_code);
        icmp.clear_unused();
        icmp.data_mut().copy_from_slice(&orig[..quote_len]);
        icmp.fill_checksum();
    }
    reply
}

/// Build an ICMPv6 error message, quoting as much of `orig` (a whole IP packet)
/// as fits within the minimum MTU (RFC 4443 §2.4). `src_addr` and `dst_addr` are
/// the addresses the error will be sent between, for the checksum. `pointer` is
/// written for parameter problem messages.
#[cfg(feature = "proto-ipv6")]
fn build_icmpv6_error(
    orig: &[u8],
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    msg_type: Icmpv6Message,
    msg_code: u8,
    pointer: u32,
) -> PacketBuf {
    let quote_len = orig.len().min(IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_ERROR_HEADER_LEN);
    let mut reply = PacketBuf::new();
    reply.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
    reply.set_len(ICMP_ERROR_HEADER_LEN + quote_len);
    {
        let mut icmp = Icmpv6Packet::new_unchecked(&mut reply);
        icmp.set_msg_type(msg_type);
        icmp.set_msg_code(msg_code);
        if msg_type == Icmpv6Message::ParamProblem {
            icmp.set_param_problem_ptr(pointer);
        } else {
            icmp.clear_reserved();
        }
        icmp.payload_mut().copy_from_slice(&orig[..quote_len]);
        icmp.fill_checksum(src_addr, dst_addr);
    }
    reply
}

/// The outcome of processing a hop-by-hop options header.
#[cfg(feature = "proto-ipv6")]
enum HopByHopAction {
    /// All options accepted, continue at the upper-layer header.
    Continue { next_header: IpProtocol, ext_len: usize },
    /// An unrecognized option requires the packet to be discarded silently.
    Discard,
    /// An unrecognized option requires the packet to be discarded and a parameter
    /// problem error sent, pointing at the offending option.
    DiscardSendError { pointer: u32, allow_multicast_dst: bool },
}

/// Walk a hop-by-hop options header (`payload` starts at the extension header).
///
/// Recognized options (padding, router alert) are skipped. Unrecognized ones are
/// acted on per the two high bits of their type (RFC 8200 §4.2).
#[cfg(feature = "proto-ipv6")]
fn process_hop_by_hop(payload: &[u8]) -> crate::wire::Result<HopByHopAction> {
    let ext = Ipv6ExtHeader::new_checked(payload)?;
    for option in Ipv6OptionsIter::new(ext.data()) {
        let (offset, option_type, _data) = option?;
        match option_type {
            Ipv6OptionType::Pad1 | Ipv6OptionType::PadN | Ipv6OptionType::RouterAlert => {}
            unrecognized => {
                // The option sits 2 bytes into the extension header, which itself
                // starts right after the fixed IPv6 header.
                let pointer = (IPV6_HEADER_LEN + 2 + offset) as u32;
                match unrecognized.failure_action() {
                    Ipv6OptionFailureAction::Skip => {}
                    Ipv6OptionFailureAction::Discard => return Ok(HopByHopAction::Discard),
                    Ipv6OptionFailureAction::DiscardSendError => {
                        return Ok(HopByHopAction::DiscardSendError {
                            pointer,
                            allow_multicast_dst: true,
                        });
                    }
                    Ipv6OptionFailureAction::DiscardSendErrorIfUnicast => {
                        return Ok(HopByHopAction::DiscardSendError {
                            pointer,
                            allow_multicast_dst: false,
                        });
                    }
                }
            }
        }
    }
    Ok(HopByHopAction::Continue {
        next_header: ext.next_header(),
        ext_len: ext.header_len(),
    })
}

impl IfaceState {
    /// The handle this interface is identified by in the stack.
    #[cfg(all(feature = "socket-raw", feature = "medium-ethernet"))]
    pub(crate) fn handle(&self) -> IfaceHandle {
        self.handle
    }

    /// The interface's medium.
    #[cfg(all(feature = "socket-raw", feature = "medium-ethernet"))]
    pub(crate) fn medium(&self) -> Medium {
        self.dev.capabilities().medium
    }

    /// The interface's Ethernet address.
    ///
    /// Panics on a non-Ethernet interface; only the Ethernet paths call it, and
    /// `add_iface` checks the address matches the medium.
    #[cfg(feature = "medium-ethernet")]
    fn ethernet_addr(&self) -> EthernetAddress {
        self.hardware_addr.ethernet_or_panic()
    }

    /// The interface's IP-layer MTU: the device MTU minus the Ethernet header on
    /// Ethernet mediums, clamped to what a `PacketBuf` can carry once the
    /// link-layer headroom egress reserves ([`LINK_HEADER_LEN`]) is taken out.
    pub(crate) fn ip_mtu(&self) -> usize {
        let caps = self.dev.capabilities();
        let mtu = match caps.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => caps.max_transmission_unit - ETHERNET_HEADER_LEN,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => caps.max_transmission_unit,
        };
        mtu.min(PACKET_BUF_SIZE - LINK_HEADER_LEN)
    }

    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    #[cfg(any(feature = "socket", feature = "medium-ethernet"))]
    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(all(feature = "proto-ipv4", feature = "auto-icmp-echo-reply"))]
    fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    /// Get an IPv4 source address based on a destination address.
    ///
    /// This function tries to find the first IPv4 address from the interface
    /// that is in the same subnet as the destination address. If no such
    /// address is found, the first IPv4 address from the interface is returned.
    #[cfg(all(
        feature = "proto-ipv4",
        any(feature = "medium-ethernet", feature = "socket-udp", feature = "socket-tcp")
    ))]
    fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.ip_addrs.iter() {
            #[allow(irrefutable_let_patterns)]
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
    #[cfg(any(feature = "socket-udp", feature = "socket-tcp"))]
    fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(IpAddress::Ipv4),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => Some(IpAddress::Ipv6(self.get_source_address_ipv6(addr))),
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(any(feature = "medium-ethernet", feature = "socket-udp"))]
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(feature = "proto-ipv4")]
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "proto-ipv4")]
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "proto-ipv6")]
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
    #[cfg(feature = "proto-ipv6")]
    fn has_multicast_group(&self, addr: Ipv6Address) -> bool {
        addr == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(addr)
    }

    /// Return the IPv6 address that is a candidate source address for the given destination
    /// address, based on RFC 6724.
    ///
    /// # Panics
    /// This function panics if the destination address is unspecified.
    #[cfg(feature = "proto-ipv6")]
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
                #[cfg(feature = "proto-ipv4")]
                IpCidr::Ipv4(_) => None,
                IpCidr::Ipv6(a) => Some(a),
            })
            .unwrap(); // NOTE: we check above that there is at least one IPv6 address.

        for addr in self.ip_addrs.iter().filter_map(|a| match a {
            #[cfg(feature = "proto-ipv4")]
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
#[cfg(all(feature = "medium-ethernet", feature = "proto-ipv6"))]
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

#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "proto-ipv4",
    feature = "proto-ipv6",
    feature = "socket-raw",
    feature = "socket-udp",
    feature = "socket-tcp"
))]
mod test {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::iface::IfaceCapabilities;
    use crate::neighbor::MAX_MULTICAST_SOLICIT;
    use crate::raw::RawMode;
    use crate::tcp::State as TcpState;
    use crate::time::Duration;
    use crate::udp::RecvError as UdpRecvError;

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

    /// A mock device: receives injected packets, records transmitted frames.
    struct TestDevice {
        medium: Medium,
        rx: Rc<RefCell<VecDeque<Vec<u8>>>>,
        tx: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl Interface for TestDevice {
        fn capabilities(&self) -> IfaceCapabilities {
            IfaceCapabilities {
                medium: self.medium,
                max_transmission_unit: 1500,
            }
        }
        fn receive(&mut self) -> Option<PacketBuf> {
            let bytes = self.rx.borrow_mut().pop_front()?;
            let mut buf = PacketBuf::new();
            buf.set_len(bytes.len());
            buf.copy_from_slice(&bytes);
            Some(buf)
        }
        fn transmit(&mut self, buf: PacketBuf) -> core::result::Result<(), PacketBuf> {
            self.tx.borrow_mut().push(buf.to_vec());
            Ok(())
        }
    }

    const OUR_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const OUR_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const OUR_V6: Ipv6Address = Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1);
    const REMOTE_V6: Ipv6Address = Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2);

    type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
    type Sent = Rc<RefCell<Vec<Vec<u8>>>>;

    /// A stack with one interface of the given medium, owning [`OUR_V4`]/24 and
    /// [`OUR_V6`]/64.
    fn test_stack(medium: Medium) -> (Stack, Queue, Sent) {
        let rx = Rc::new(RefCell::new(VecDeque::new()));
        let tx = Rc::new(RefCell::new(Vec::new()));
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_iface(
            Box::new(TestDevice {
                medium,
                rx: rx.clone(),
                tx: tx.clone(),
            }),
            match medium {
                Medium::Ethernet => HardwareAddress::Ethernet(OUR_HW),
                Medium::Ip => HardwareAddress::Ip,
            },
        );
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)]);
        (stack, rx, tx)
    }

    /// Inject a packet into the device and poll the stack to process it.
    fn inject(stack: &mut Stack, rx: &Queue, bytes: Vec<u8>) {
        rx.borrow_mut().push_back(bytes);
        stack.poll(Instant::ZERO);
    }

    /// A whole IPv4 packet, header checksum filled in.
    fn ipv4_packet(src_addr: Ipv4Address, dst_addr: Ipv4Address, protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV4_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + payload.len()) as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
            ip.fill_checksum();
        }
        bytes[IPV4_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    /// A whole IPv6 packet.
    fn ipv6_packet(src_addr: Ipv6Address, dst_addr: Ipv6Address, protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV6_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len(payload.len() as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
        }
        bytes[IPV6_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    /// A UDP datagram (UDP header + payload), checksum filled in.
    fn udp_datagram(src_addr: IpAddress, src_port: u16, dst_addr: IpAddress, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; UDP_HEADER_LEN + payload.len()];
        {
            let mut udp = UdpPacket::new_unchecked(&mut bytes[..]);
            udp.set_src_port(src_port);
            udp.set_dst_port(dst_port);
            udp.set_len((UDP_HEADER_LEN + payload.len()) as u16);
            udp.payload_mut().copy_from_slice(payload);
            udp.fill_checksum(&src_addr, &dst_addr);
        }
        bytes
    }

    /// Parse a transmitted IPv4 frame as an ICMPv4 message, verifying addresses and
    /// both checksums, and return `(type, code, quoted packet)`.
    fn parse_icmpv4_reply(frame: &[u8], src_addr: Ipv4Address, dst_addr: Ipv4Address) -> (Icmpv4Message, u8, Vec<u8>) {
        let mut bytes = frame.to_vec();
        let ip = Ipv4Packet::new_checked(&mut bytes[..]).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.src_addr(), src_addr);
        assert_eq!(ip.dst_addr(), dst_addr);
        assert_eq!(ip.next_header(), IpProtocol::Icmp);
        let header_len = ip.header_len() as usize;
        let mut icmp_bytes = bytes[header_len..].to_vec();
        let icmp = Icmpv4Packet::new_checked(&mut icmp_bytes[..]).unwrap();
        assert!(icmp.verify_checksum());
        (icmp.msg_type(), icmp.msg_code(), icmp.data().to_vec())
    }

    /// Parse a transmitted IPv6 frame as an ICMPv6 message, verifying addresses and
    /// the checksum, and return `(type, code, pointer, quoted packet)`.
    fn parse_icmpv6_reply(
        frame: &[u8],
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) -> (Icmpv6Message, u8, u32, Vec<u8>) {
        let mut bytes = frame.to_vec();
        let ip = Ipv6Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(ip.src_addr(), src_addr);
        assert_eq!(ip.dst_addr(), dst_addr);
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
        let mut icmp_bytes = bytes[IPV6_HEADER_LEN..].to_vec();
        let icmp = Icmpv6Packet::new_checked(&mut icmp_bytes[..]).unwrap();
        assert!(icmp.verify_checksum(&src_addr, &dst_addr));
        (
            icmp.msg_type(),
            icmp.msg_code(),
            icmp.param_problem_ptr(),
            icmp.payload().to_vec(),
        )
    }

    #[test]
    fn test_icmpv4_proto_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::ProtoUnreachable.into());
        assert_eq!(quote, packet);
    }

    #[test]
    fn test_icmpv4_no_error_to_broadcast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // Unknown protocol on a broadcast-destined packet: no error may be sent.
        let bcast = Ipv4Address::new(192, 168, 1, 255);
        let packet = ipv4_packet(REMOTE_V4, bcast, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    #[test]
    fn test_icmpv4_port_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let datagram = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), 7, b"echo?");
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        {
            let tx = tx.borrow();
            assert_eq!(tx.len(), 1);
            let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
            assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
            assert_eq!(msg_code, Icmpv4DstUnreachable::PortUnreachable.into());
            assert_eq!(quote, packet);
        }

        // With a socket bound to the port, the datagram is delivered instead.
        let handle = stack.add_udp_socket();
        stack.udp_socket(handle).bind(7, IpListenEndpoint::UNSPECIFIED).unwrap();
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"echo?");
    }

    #[test]
    fn test_icmpv4_port_unreachable_suppressed_by_raw_socket() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // An application handling UDP through a raw socket suppresses the error.
        let handle = stack.add_raw_socket();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol::Udp),
            })
            .unwrap();

        let datagram = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), 7, b"echo?");
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        assert!(tx.borrow().is_empty());
        assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &packet[..]);
    }

    #[test]
    fn test_icmpv6_unknown_next_header() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, pointer, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::ParamProblem);
        assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedNxtHdr.into());
        // The pointer names the fixed header's next header field.
        assert_eq!(pointer, 6);
        assert_eq!(quote, packet);
    }

    #[test]
    fn test_icmpv6_no_error_to_multicast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // Unknown protocol on a multicast-destined packet: no error may be sent.
        let packet = ipv6_packet(REMOTE_V6, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    #[test]
    fn test_icmpv6_port_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let datagram = udp_datagram(REMOTE_V6.into(), 4000, OUR_V6.into(), 7, b"echo?");
        let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, _, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv6DstUnreachable::PortUnreachable.into());
        assert_eq!(quote, packet);
    }

    /// A hop-by-hop options header carrying the given options (padded to a
    /// multiple of 8 by the caller), followed by the given payload.
    fn hbh_payload(next_header: IpProtocol, options: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!((options.len() + 2) % 8, 0);
        let mut bytes = vec![u8::from(next_header), ((options.len() + 2) / 8 - 1) as u8];
        bytes.extend_from_slice(options);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn test_icmpv6_hop_by_hop_passthrough() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket();
        stack.udp_socket(handle).bind(7, IpListenEndpoint::UNSPECIFIED).unwrap();

        // PadN + an unknown option whose action is "skip" (high bits 00): the
        // packet continues to UDP and is delivered, headers intact.
        let datagram = udp_datagram(REMOTE_V6.into(), 4000, OUR_V6.into(), 7, b"echo?");
        let options = [0x01, 0x01, 0x00, 0x02, 0x01, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, &datagram),
        );
        inject(&mut stack, &rx, packet);

        let mut socket = stack.udp_socket(handle);
        let recv = socket.recv().unwrap();
        assert_eq!(&*recv, b"echo?");
        assert_eq!(recv.meta().endpoint, IpEndpoint::new(REMOTE_V6.into(), 4000));
    }

    #[test]
    fn test_icmpv6_hop_by_hop_unrecognized_option() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);

        // High bits 01: discard silently.
        let options = [0x41, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());

        // High bits 10: discard and send a parameter problem, pointing at the
        // offending option (40-byte header + 2 bytes into the extension header).
        let options = [0x81, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet.clone());
        {
            let tx = tx.borrow();
            assert_eq!(tx.len(), 1);
            let (msg_type, msg_code, pointer, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
            assert_eq!(msg_type, Icmpv6Message::ParamProblem);
            assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedOption.into());
            assert_eq!(pointer, 42);
            assert_eq!(quote, packet);
        }
    }

    #[test]
    fn test_icmpv6_hop_by_hop_unrecognized_option_multicast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);

        // High bits 11: discard, and send the error only if the destination was
        // not multicast, which it is here, so nothing may be sent.
        let options = [0xc1, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            IPV6_LINK_LOCAL_ALL_NODES,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());

        // High bits 10: the error is sent even for a multicast destination, with
        // the source picked from the interface.
        let options = [0x81, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            IPV6_LINK_LOCAL_ALL_NODES,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet.clone());
        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, _, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::ParamProblem);
        assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedOption.into());
        assert_eq!(quote, packet);
    }

    #[test]
    fn test_icmp_error_quote_truncated() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // A big offending packet: the quote is capped so the error fits the
        // minimum MTU (576 for IPv4: 20-byte header + 8-byte ICMP header + quote).
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol(99), &[0xab; 1000]);
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        let (_, _, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
        assert_eq!(quote.len(), IPV4_MIN_MTU - IPV4_HEADER_LEN - 8);
        assert_eq!(quote, packet[..quote.len()]);
    }

    #[test]
    fn test_neighbor_failure_dst_unreachable() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);

        // A raw socket listening for ICMPv4, the erring application.
        let raw_handle = stack.add_raw_socket();
        stack
            .raw_socket(raw_handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol::Icmp),
            })
            .unwrap();

        // Send a datagram to an on-link address that will never resolve: the
        // packet is queued and an ARP request goes out.
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let udp_handle = stack.add_udp_socket();
        stack
            .udp_socket(udp_handle)
            .bind(5555, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        stack
            .udp_socket(udp_handle)
            .send_slice(b"anyone?", (dead, 1000))
            .unwrap();
        assert_eq!(tx.borrow().len(), 1); // the first ARP request

        // Let the resolution run out of probes.
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        // Every transmission was an ARP request: the error is not sent to the
        // wire, it is delivered back through local ingress...
        assert_eq!(tx.borrow().len(), MAX_MULTICAST_SOLICIT as usize);

        // ...where the raw socket receives it: host unreachable, from us to us,
        // quoting the queued UDP packet.
        let error = stack.raw_socket(raw_handle).recv().unwrap();
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&error, OUR_V4, OUR_V4);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::HostUnreachable.into());

        let mut quoted = quote.clone();
        let ip = Ipv4Packet::new_checked(&mut quoted[..]).unwrap();
        assert_eq!(ip.src_addr(), OUR_V4);
        assert_eq!(ip.dst_addr(), dead);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
    }

    /// A whole IPv4 packet carrying an ICMPv4 error message quoting `quote`.
    fn icmpv4_error_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        msg_type: Icmpv4Message,
        msg_code: u8,
        quote: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + quote.len()];
        {
            let mut packet = Icmpv4Packet::new_unchecked(&mut icmp[..]);
            packet.set_msg_type(msg_type);
            packet.set_msg_code(msg_code);
            packet.clear_unused();
            packet.data_mut().copy_from_slice(quote);
            packet.fill_checksum();
        }
        ipv4_packet(src_addr, dst_addr, IpProtocol::Icmp, &icmp)
    }

    /// A whole IPv6 packet carrying an ICMPv6 error message quoting `quote`.
    fn icmpv6_error_packet(
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        msg_type: Icmpv6Message,
        msg_code: u8,
        quote: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + quote.len()];
        {
            let mut packet = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            packet.set_msg_type(msg_type);
            packet.set_msg_code(msg_code);
            packet.clear_reserved();
            packet.payload_mut().copy_from_slice(quote);
            packet.fill_checksum(&src_addr, &dst_addr);
        }
        ipv6_packet(src_addr, dst_addr, IpProtocol::Icmpv6, &icmp)
    }

    /// End to end: the driver stamps a received frame and the metadata travels up the
    /// stack into the socket that receives it. A socket's send metadata travels back
    /// down into the driver, and the transmit timestamp it asked for comes back out of
    /// band, tagged with the packet's id.
    #[cfg(feature = "packetmeta-timestamp")]
    #[test]
    fn test_packet_meta_end_to_end() {
        use crate::meta::{PacketMeta, Timestamp, TxTimestamp};

        const RX_STAMP: Timestamp = Timestamp::from_seconds_and_nanos(4, 500);
        const TX_STAMP: Timestamp = Timestamp::from_seconds_and_nanos(9, 250);

        /// A device that timestamps everything it receives and everything it is asked
        /// to timestamp on transmit.
        struct PtpDevice {
            rx: Queue,
            sent: Rc<RefCell<Vec<PacketMeta>>>,
            tx_stamps: Rc<RefCell<VecDeque<TxTimestamp>>>,
        }

        impl Interface for PtpDevice {
            fn capabilities(&self) -> IfaceCapabilities {
                IfaceCapabilities {
                    medium: Medium::Ip,
                    max_transmission_unit: 1500,
                }
            }
            fn receive(&mut self) -> Option<PacketBuf> {
                let bytes = self.rx.borrow_mut().pop_front()?;
                let mut buf = PacketBuf::new();
                buf.set_len(bytes.len());
                buf.copy_from_slice(&bytes);
                buf.meta_mut().id = 0x1111;
                buf.meta_mut().timestamp = Some(RX_STAMP);
                Some(buf)
            }
            fn transmit(&mut self, buf: PacketBuf) -> core::result::Result<(), PacketBuf> {
                let meta = buf.meta();
                self.sent.borrow_mut().push(meta);
                if meta.request_timestamp {
                    self.tx_stamps.borrow_mut().push_back(TxTimestamp {
                        id: meta.id,
                        timestamp: TX_STAMP,
                    });
                }
                Ok(())
            }
            fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
                self.tx_stamps.borrow_mut().pop_front()
            }
        }

        let rx = Rc::new(RefCell::new(VecDeque::new()));
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let iface = stack.add_iface(
            Box::new(PtpDevice {
                rx: rx.clone(),
                sent: sent.clone(),
                tx_stamps: Rc::new(RefCell::new(VecDeque::new())),
            }),
            HardwareAddress::Ip,
        );
        stack.iface(iface).add_ip_addr(IpCidr::new(OUR_V4.into(), 24));

        let handle = stack.add_udp_socket();
        stack
            .udp_socket(handle)
            .bind(319, IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        // Ingress: driver → ethernet/IP/UDP demux → socket queue → recv.
        let datagram = udp_datagram(REMOTE_V4.into(), 319, OUR_V4.into(), 319, b"sync");
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram),
        );
        let packet = stack.udp_socket(handle).recv().unwrap();
        assert_eq!(&*packet, b"sync");
        assert_eq!(packet.meta().meta.id, 0x1111);
        assert_eq!(packet.meta().meta.timestamp, Some(RX_STAMP));

        // Egress: socket → driver, with a transmit timestamp requested.
        let mut meta: crate::udp::UdpMetadata = IpEndpoint::new(REMOTE_V4.into(), 319).into();
        meta.meta.id = 0x2222;
        meta.meta.request_timestamp = true;
        stack.udp_socket(handle).send_slice(b"delay_req", meta).unwrap();
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(sent.borrow()[0].id, 0x2222);
        assert!(sent.borrow()[0].request_timestamp);

        // ... and the timestamp comes back out of band, tagged with the id.
        assert_eq!(
            stack.iface(iface).poll_tx_timestamp(),
            Some(TxTimestamp {
                id: 0x2222,
                timestamp: TX_STAMP,
            })
        );
        assert_eq!(stack.iface(iface).poll_tx_timestamp(), None);
    }

    #[test]
    fn test_udp_icmp_error_delivery() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket();
        stack.udp_socket(handle).bind(5000, (REMOTE_V4, 53)).unwrap();
        stack.udp_socket(handle).send_slice(b"query", (REMOTE_V4, 53)).unwrap();
        let sent = tx.borrow().last().unwrap().clone();

        // A port unreachable arrives, quoting the datagram we sent.
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::PortUnreachable.into(),
            &sent,
        );
        inject(&mut stack, &rx, error);

        // recv reports it once, clearing it.
        match stack.udp_socket(handle).recv() {
            Err(UdpRecvError::IcmpError { error, remote }) => {
                assert_eq!(error, IcmpError::PortUnreachable);
                assert_eq!(remote, IpEndpoint::new(REMOTE_V4.into(), 53));
            }
            other => panic!("expected icmp error, got {:?}", other),
        }
        assert_eq!(stack.udp_socket(handle).take_icmp_error(), None);
        assert!(matches!(stack.udp_socket(handle).recv(), Err(UdpRecvError::Exhausted)));
    }

    #[test]
    fn test_udp_icmp_error_no_match() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket();
        stack
            .udp_socket(handle)
            .bind(5000, IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        // An error quoting a flow from another local port: not for this socket.
        let quote = ipv4_packet(
            OUR_V4,
            REMOTE_V4,
            IpProtocol::Udp,
            &udp_datagram(OUR_V4.into(), 6000, REMOTE_V4.into(), 53, b"x"),
        );
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::PortUnreachable.into(),
            &quote,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.udp_socket(handle).take_icmp_error(), None);
    }

    #[test]
    fn test_udp_icmp_error_delivery_v6() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket();
        stack.udp_socket(handle).bind(5000, (REMOTE_V6, 53)).unwrap();
        stack.udp_socket(handle).send_slice(b"query", (REMOTE_V6, 53)).unwrap();
        let sent = tx.borrow().last().unwrap().clone();

        let error = icmpv6_error_packet(
            REMOTE_V6,
            OUR_V6,
            Icmpv6Message::DstUnreachable,
            Icmpv6DstUnreachable::PortUnreachable.into(),
            &sent,
        );
        inject(&mut stack, &rx, error);

        assert_eq!(
            stack.udp_socket(handle).take_icmp_error(),
            Some((IcmpError::PortUnreachable, IpEndpoint::new(REMOTE_V6.into(), 53)))
        );
    }

    #[test]
    fn test_neighbor_failure_reported_to_udp_socket() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let handle = stack.add_udp_socket();
        stack
            .udp_socket(handle)
            .bind(5555, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        stack.udp_socket(handle).send_slice(b"anyone?", (dead, 1000)).unwrap();

        // Let the ARP resolution run out of probes. The local destination
        // unreachable error lands on the socket, and nothing but the ARP
        // requests ever reaches the wire.
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(
            stack.udp_socket(handle).take_icmp_error(),
            Some((IcmpError::HostUnreachable, IpEndpoint::new(dead.into(), 1000)))
        );
        assert_eq!(tx.borrow().len(), MAX_MULTICAST_SOLICIT as usize);
    }

    #[test]
    fn test_tcp_connect_aborted_by_icmp_error() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_tcp_socket(4096, 4096);
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
        stack.poll(Instant::ZERO);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);
        let syn = tx.borrow().last().unwrap().clone();

        // A host unreachable quoting our SYN aborts the nascent connection.
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &syn,
        );
        inject(&mut stack, &rx, error);

        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Closed);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );
    }

    #[test]
    fn test_tcp_established_icmp_error_is_soft() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_tcp_socket(4096, 4096);
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
        stack.poll(Instant::ZERO);
        let syn = tx.borrow().last().unwrap().clone();

        // Complete the handshake with a crafted SYN|ACK.
        let (local_port, syn_seq) = {
            let mut bytes = syn.clone();
            let tcp = TcpPacket::new_checked(&mut bytes[IPV4_HEADER_LEN..]).unwrap();
            (tcp.src_port(), tcp.seq_number())
        };
        let mut segment = vec![0u8; TCP_HEADER_LEN];
        {
            let mut tcp = TcpPacket::new_unchecked(&mut segment[..]);
            tcp.set_src_port(80);
            tcp.set_dst_port(local_port);
            tcp.set_seq_number(TcpSeqNumber(10000));
            tcp.set_ack_number(syn_seq + 1);
            tcp.set_header_len(TCP_HEADER_LEN as u8);
            tcp.set_syn(true);
            tcp.set_ack(true);
            tcp.set_window_len(64000);
            tcp.fill_checksum(&REMOTE_V4.into(), &OUR_V4.into());
        }
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Tcp, &segment),
        );
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);

        // An error quoting an in-flight data segment is soft: recorded, not fatal.
        stack.tcp_socket(handle).send_slice(b"hello").unwrap();
        stack.poll(Instant::ZERO);
        let data_segment = tx.borrow().last().unwrap().clone();
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &data_segment,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );

        // An error quoting an out-of-window sequence number is a blind spoof:
        // ignored entirely.
        let mut forged = data_segment.clone();
        {
            let mut tcp = TcpPacket::new_unchecked(&mut forged[IPV4_HEADER_LEN..]);
            tcp.set_seq_number(TcpSeqNumber(999_999_999));
        }
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &forged,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);
        assert_eq!(stack.tcp_socket(handle).take_icmp_error(), None);
    }

    #[test]
    fn test_neighbor_failure_aborts_tcp_connect() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let handle = stack.add_tcp_socket(4096, 4096);
        stack.tcp_socket(handle).connect((dead, 80), 0).unwrap();

        // The SYN is queued on the unresolvable neighbor. When resolution fails, the
        // local destination unreachable error aborts the connect.
        stack.poll(Instant::ZERO);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Closed);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );
        // Nothing but ARP requests ever reached the wire.
        for frame in tx.borrow().iter() {
            let mut bytes = frame.clone();
            let eth = EthernetFrame::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
        }
    }

    /// An ICMPv4 echo request, checksum filled in.
    fn icmpv4_echo_request(ident: u16, seq_no: u16) -> Vec<u8> {
        let mut bytes = vec![0; 8];
        {
            let mut icmp = Icmpv4Packet::new_unchecked(&mut bytes[..]);
            icmp.set_msg_type(Icmpv4Message::EchoRequest);
            icmp.set_msg_code(0);
            icmp.set_echo_ident(ident);
            icmp.set_echo_seq_no(seq_no);
            icmp.fill_checksum();
        }
        bytes
    }

    /// The ethertype of a transmitted Ethernet frame.
    fn ethertype_of(frame: &[u8]) -> EthernetProtocol {
        let mut bytes = frame.to_vec();
        EthernetFrame::new_checked(&mut bytes[..]).unwrap().ethertype()
    }

    #[test]
    fn test_iface_ip_addrs() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let iface = IfaceHandle(0);
        let new_addr = Ipv4Address::new(10, 0, 0, 1);

        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)]
        );
        assert!(stack.iface(iface).has_ip_addr(OUR_V4));
        assert!(!stack.iface(iface).has_ip_addr(new_addr));

        // An echo request to an address we don't have is ignored.
        let echo = ipv4_packet(REMOTE_V4, new_addr, IpProtocol::Icmp, &icmpv4_echo_request(0x1234, 1));
        inject(&mut stack, &rx, echo.clone());
        assert!(tx.borrow().is_empty());

        // A new address is appended, and ingress starts accepting it right away.
        assert_eq!(stack.iface(iface).add_ip_addr(IpCidr::new(new_addr.into(), 8)), None);
        assert!(stack.iface(iface).has_ip_addr(new_addr));
        inject(&mut stack, &rx, echo.clone());
        assert_eq!(tx.borrow().len(), 1);
        let (msg_type, ..) = parse_icmpv4_reply(&tx.borrow()[0], new_addr, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::EchoReply);

        // Re-adding an address already assigned updates its prefix in place,
        // returning the CIDR it had.
        assert_eq!(
            stack.iface(iface).add_ip_addr(IpCidr::new(new_addr.into(), 24)),
            Some(IpCidr::new(new_addr.into(), 8))
        );
        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [
                IpCidr::new(OUR_V4.into(), 24),
                IpCidr::new(OUR_V6.into(), 64),
                IpCidr::new(new_addr.into(), 24),
            ]
        );

        // Removing hands back the CIDR it was assigned with, once.
        assert_eq!(
            stack.iface(iface).remove_ip_addr(new_addr),
            Some(IpCidr::new(new_addr.into(), 24))
        );
        assert_eq!(stack.iface(iface).remove_ip_addr(new_addr), None);
        assert!(!stack.iface(iface).has_ip_addr(new_addr));

        // ...and ingress stops accepting it.
        tx.borrow_mut().clear();
        inject(&mut stack, &rx, echo);
        assert!(tx.borrow().is_empty());

        // Wholesale replacement.
        stack.iface(iface).set_ip_addrs([IpCidr::new(new_addr.into(), 8)]);
        assert_eq!(stack.iface(iface).ip_addrs(), [IpCidr::new(new_addr.into(), 8)]);
        assert!(!stack.iface(iface).has_ip_addr(OUR_V4));
    }

    #[test]
    #[should_panic]
    fn test_iface_reject_non_unicast_ip_addr() {
        let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
        stack
            .iface(IfaceHandle(0))
            .add_ip_addr(IpCidr::new(Ipv4Address::new(224, 0, 0, 1).into(), 24));
    }

    #[test]
    fn test_iface_addr_change_invalidates_link_state() {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle(0);
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);

        // Learn the remote's hardware address from an ARP request for us.
        let mut request = vec![0; ETHERNET_HEADER_LEN + ARP_BUFFER_LEN];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut request[..]);
            eth.set_dst_addr(EthernetAddress::BROADCAST);
            eth.set_src_addr(remote_hw);
            eth.set_ethertype(EthernetProtocol::Arp);
            let mut arp = ArpPacket::new_unchecked(&mut request[ETHERNET_HEADER_LEN..]);
            arp.set_hardware_type(ArpHardware::Ethernet);
            arp.set_protocol_type(EthernetProtocol::Ipv4);
            arp.set_hardware_len(6);
            arp.set_protocol_len(4);
            arp.set_operation(ArpOperation::Request);
            arp.set_source_hardware_addr(remote_hw.as_bytes());
            arp.set_source_protocol_addr(&REMOTE_V4.octets());
            arp.set_target_hardware_addr(&[0; 6]);
            arp.set_target_protocol_addr(&OUR_V4.octets());
        }
        inject(&mut stack, &rx, request);
        assert_eq!(tx.borrow().len(), 1); // the ARP reply
        assert_eq!(ethertype_of(&tx.borrow()[0]), EthernetProtocol::Arp);

        // The neighbor is now resolved: a datagram to it goes out immediately.
        let udp = stack.add_udp_socket();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();
        stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 2);
        assert_eq!(ethertype_of(&tx.borrow()[1]), EthernetProtocol::Ipv4);

        // Queue a packet on a neighbor that will never answer.
        let dead = Ipv4Address::new(192, 168, 1, 99);
        stack.udp_socket(udp).send_slice(b"anyone?", (dead, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 3);
        assert_eq!(ethertype_of(&tx.borrow()[2]), EthernetProtocol::Arp);

        // Changing the interface's addresses invalidates both: the queued packet
        // is dropped (no solicitation is ever retransmitted for it)...
        stack.iface(iface).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]);
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(tx.borrow().len(), 3);

        // ...and the learned mapping is gone, so the next datagram to the remote
        // has to resolve it again.
        stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 4);
        assert_eq!(ethertype_of(&tx.borrow()[3]), EthernetProtocol::Arp);
    }
}
