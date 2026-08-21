//! The network stack.

use crate::buf::{PACKET_BUF_SIZE, PacketBuf};
#[cfg(feature = "raw")]
use crate::config::RAW_SOCKET_COUNT;
#[cfg(feature = "tcp-listener")]
use crate::config::TCP_LISTENER_COUNT;
#[cfg(feature = "tcp")]
use crate::config::TCP_SOCKET_COUNT;
#[cfg(feature = "udp")]
use crate::config::UDP_SOCKET_COUNT;
use crate::config::{IFACE_ADDR_COUNT, IFACE_COUNT};
#[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
use crate::icmp_error::{IcmpError, parse_quoted_packet};
use crate::iface::{IfaceCapabilities, Interface, Medium};
#[cfg(feature = "medium-ethernet")]
use crate::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache, PendingQueue, ProbeEvent};
use crate::rand::Rand;
#[cfg(feature = "raw")]
use crate::raw::{RawHandle, RawSocket, RawSocketState};
use crate::route::Routes;
use crate::storage::{Full, MaybeBox, Slab, Vec};
#[cfg(feature = "tcp")]
use crate::tcp::{SocketBuffer, TcpHandle, TcpRepr, TcpSocket, TcpSocketState};
#[cfg(feature = "tcp-listener")]
use crate::tcp::{TcpListener, TcpListenerHandle, TcpListenerState};
use crate::time::Instant;
#[cfg(feature = "udp")]
use crate::udp::{UdpHandle, UdpSocket, UdpSocketState};
use crate::wire::*;

/// A handle to an interface added to a [`Stack`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfaceHandle(pub(crate) usize);

/// A network stack.
pub struct Stack<'d> {
    pub(crate) inner: StackInner,
    pub(crate) ifaces: Slab<IfaceState<'d>, IFACE_COUNT>,
    #[allow(unused)]
    pub(crate) sockets: Sockets<'d>,
}

/// The stack's socket storage, one slab per socket type.
pub(crate) struct Sockets<'d> {
    #[cfg(feature = "udp")]
    pub(crate) udp: Slab<UdpSocketState, UDP_SOCKET_COUNT>,
    #[cfg(feature = "raw")]
    pub(crate) raw: Slab<RawSocketState, RAW_SOCKET_COUNT>,
    #[cfg(feature = "tcp")]
    pub(crate) tcp: Slab<TcpSocketState<'d>, TCP_SOCKET_COUNT>,
    #[cfg(feature = "tcp-listener")]
    pub(crate) tcp_listeners: Slab<TcpListenerState, TCP_LISTENER_COUNT>,
    /// Only TCP sockets hold lent storage; without them `'d` is unused.
    #[cfg(not(feature = "tcp"))]
    _lent: core::marker::PhantomData<&'d mut ()>,
}

/// Where an interface address came from.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddrOrigin {
    /// Assigned by the application.
    Manual,
    /// Learned from a DHCPv4 lease.
    #[cfg(feature = "dhcpv4")]
    Dhcpv4,
    /// The IPv6 link-local address the stack derives from the hardware address.
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    LinkLocal,
    /// Formed by SLAAC from a router-advertised prefix.
    #[cfg(feature = "slaac")]
    Slaac,
}

/// An IP address assigned to an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaceAddr {
    /// The address and its prefix.
    pub cidr: IpCidr,
    /// Where the address came from.
    pub origin: AddrOrigin,
}

impl IfaceAddr {
    /// An address assigned by the application.
    pub(crate) const fn manual(cidr: IpCidr) -> Self {
        Self {
            cidr,
            origin: AddrOrigin::Manual,
        }
    }
}

/// The IPv6 link-local address derived from an Ethernet address (RFC 4291 §2.5.1,
/// modified EUI-64).
#[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
fn link_local_addr(hardware_addr: HardwareAddress) -> Option<IfaceAddr> {
    let mac = match hardware_addr {
        HardwareAddress::Ethernet(mac) => mac,
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8..].copy_from_slice(&mac.as_eui_64());
    Some(IfaceAddr {
        cidr: IpCidr::new(Ipv6Address::from(bytes).into(), 64),
        origin: AddrOrigin::LinkLocal,
    })
}

/// An interface added to the stack, with its configuration.
pub(crate) struct IfaceState<'d> {
    pub(crate) handle: IfaceHandle,
    dev: MaybeBox<'d, dyn Interface + 'd>,
    pub(crate) hardware_addr: HardwareAddress,
    pub(crate) ip_addrs: Vec<IfaceAddr, IFACE_ADDR_COUNT>,
    /// Bumped whenever the interface's addresses or routes change.
    config_generation: u32,
    #[cfg(feature = "async")]
    config_waker: crate::waker::WakerRegistration,
    #[cfg(feature = "dhcpv4")]
    pub(crate) dhcpv4: Option<crate::dhcpv4::Client>,
    #[cfg(feature = "slaac")]
    pub(crate) slaac: Option<crate::slaac::Slaac>,
    #[cfg(feature = "multicast")]
    pub(crate) multicast: crate::multicast::State,
}

/// An interface borrowed from a [`Stack`], returned by [`Stack::iface`].
pub struct Iface<'a, 'd> {
    #[cfg_attr(not(feature = "medium-ethernet"), allow(dead_code))]
    inner: &'a mut StackInner,
    ifaces: &'a mut Slab<IfaceState<'d>, IFACE_COUNT>,
    index: usize,
}

impl<'d> Iface<'_, 'd> {
    #[inline]
    pub(crate) fn state(&self) -> &IfaceState<'d> {
        self.ifaces.get(self.index)
    }

    #[inline]
    pub(crate) fn state_mut(&mut self) -> &mut IfaceState<'d> {
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
        #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
        {
            let ip_addrs = &mut self.state_mut().ip_addrs;
            let had = ip_addrs.iter().any(|a| a.origin == AddrOrigin::LinkLocal);
            ip_addrs.retain(|a| a.origin != AddrOrigin::LinkLocal);
            if let Some(ll) = link_local_addr(addr) {
                if ip_addrs.push(ll).is_err() {
                    warn!("iface: address table full, link-local address not assigned");
                }
                self.invalidate();
            } else if had {
                self.invalidate();
            }
        }
    }

    /// The IP addresses assigned to the interface, with their origin.
    pub fn ip_addrs(&self) -> &[IfaceAddr] {
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
    ///
    /// Errors:
    /// - `Full` if the interface has no room for another address. Only possible
    ///   without the `alloc` feature, where the `iface-addr-count-N` feature sets the limit.
    pub fn add_ip_addr(&mut self, cidr: IpCidr) -> core::result::Result<Option<IpCidr>, Full> {
        assert!(
            cidr.address().is_unicast(),
            "only unicast addresses can be assigned to an interface"
        );

        let ip_addrs = &mut self.state_mut().ip_addrs;
        match ip_addrs.iter().position(|old| old.cidr.address() == cidr.address()) {
            Some(index) if ip_addrs[index].cidr == cidr => Ok(Some(cidr)),
            Some(index) => {
                let old = core::mem::replace(&mut ip_addrs[index], IfaceAddr::manual(cidr));
                self.invalidate();
                Ok(Some(old.cidr))
            }
            None => {
                ip_addrs.push(IfaceAddr::manual(cidr)).map_err(|_| Full)?;
                self.state_mut().config_changed();
                Ok(None)
            }
        }
    }

    /// Unassign an IP address from the interface, returning the CIDR it was
    /// assigned with, or `None` if it was not assigned.
    pub fn remove_ip_addr(&mut self, addr: impl Into<IpAddress>) -> Option<IpCidr> {
        let addr = addr.into();
        let ip_addrs = &mut self.state_mut().ip_addrs;
        let index = ip_addrs.iter().position(|a| a.cidr.address() == addr)?;
        let removed = ip_addrs.remove(index);
        self.invalidate();
        Some(removed.cidr)
    }

    /// Replace the interface's entire set of IP addresses.
    ///
    /// Equivalent to removing every address and adding the given ones. The
    /// automatic IPv6 link-local address is kept.
    ///
    /// # Panics
    /// Panics if any of the addresses is not unicast.
    ///
    /// Errors:
    /// - `Full` if the addresses do not fit. Only possible without the `alloc`
    ///   feature, where the `iface-addr-count-N` feature sets the limit. The
    ///   interface is left unchanged.
    pub fn set_ip_addrs(&mut self, new_addrs: impl IntoIterator<Item = IpCidr>) -> core::result::Result<(), Full> {
        #[allow(unused_mut)]
        let mut addrs: Vec<IfaceAddr, IFACE_ADDR_COUNT> = Vec::new();
        addrs.try_extend(new_addrs.into_iter().map(IfaceAddr::manual))?;
        assert!(
            addrs.iter().all(|a| a.cidr.address().is_unicast()),
            "only unicast addresses can be assigned to an interface"
        );
        #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
        for a in self.state().ip_addrs.iter() {
            if a.origin == AddrOrigin::LinkLocal && !addrs.iter().any(|n| n.cidr.address() == a.cidr.address()) {
                addrs.push(*a).map_err(|_| Full)?;
            }
        }

        let ip_addrs = &mut self.state_mut().ip_addrs;
        if *ip_addrs == addrs {
            return Ok(());
        }
        *ip_addrs = addrs;
        self.invalidate();
        Ok(())
    }

    /// Purge state associated to this interface.
    fn invalidate(&mut self) {
        let handle = IfaceHandle(self.index);
        self.inner.purge_iface_link_state(handle);
        self.state_mut().config_changed();
    }

    /// A counter that goes up every time the interface's configuration changes
    /// for any reason (manual changes, DHCP, SLAAC)
    ///
    /// Compare it with a saved value to find out whether anything changed since.
    pub fn config_generation(&self) -> u32 {
        self.state().config_generation
    }

    /// Register a waker to be woken when [`config_generation`](Self::config_generation)
    /// changes.
    ///
    /// Only one waker is kept. Registering another replaces it. A woken waker must
    /// be registered again to be woken again.
    #[cfg(feature = "async")]
    pub fn register_config_waker(&mut self, waker: &core::task::Waker) {
        self.state_mut().config_waker.register(waker)
    }

    /// Turn the DHCPv4 client on, with the given configuration, or off with `None`.
    ///
    /// While on, the client runs from [`Stack::poll`]. When it gets a lease the
    /// leased address and the default route via the leased router are installed on
    /// the interface, and removed again when the lease is lost or the client is
    /// turned off. Turning it on when it is already on restarts it with the new
    /// configuration.
    ///
    /// # Panics
    /// Panics if the interface is not an Ethernet interface.
    #[cfg(feature = "dhcpv4")]
    pub fn set_dhcpv4(&mut self, config: Option<crate::dhcpv4::DhcpConfig>) {
        assert!(
            matches!(self.state().hardware_addr, HardwareAddress::Ethernet(_)),
            "the DHCPv4 client needs an Ethernet interface"
        );
        let Iface { inner, ifaces, index } = self;
        let iface = ifaces.get_mut(*index);
        iface.dhcpv4_reset(inner);
        iface.dhcpv4 = config.map(crate::dhcpv4::Client::new);
    }

    /// Turn IPv6 stateless address autoconfiguration on, with the given
    /// configuration, or off with `None`.
    ///
    /// While on, the stack sends router solicitations from [`Stack::poll`]. Every
    /// prefix a router advertises for autoconfiguration becomes an address on the
    /// interface (the prefix plus the EUI-64 of the hardware address), and every
    /// advertising router becomes a default route. Both are removed when their
    /// lifetime runs out or when SLAAC is turned off. Turning it on when it is
    /// already on restarts it.
    ///
    /// # Panics
    /// Panics if the interface is not an Ethernet interface.
    #[cfg(feature = "slaac")]
    pub fn set_slaac(&mut self, config: Option<crate::slaac::SlaacConfig>) {
        assert!(
            matches!(self.state().hardware_addr, HardwareAddress::Ethernet(_)),
            "SLAAC needs an Ethernet interface"
        );
        let Iface { inner, ifaces, index } = self;
        let iface = ifaces.get_mut(*index);
        iface.slaac_reset(inner);
        iface.slaac = config.map(crate::slaac::Slaac::new);
    }

    /// What SLAAC has learned from the routers on the link, or `None` if SLAAC is off.
    #[cfg(feature = "slaac")]
    pub fn slaac(&self) -> Option<&crate::slaac::SlaacState> {
        self.state().slaac.as_ref().map(|s| s.state())
    }

    /// The lease the DHCPv4 client currently holds, if any.
    #[cfg(feature = "dhcpv4")]
    pub fn dhcpv4_lease(&self) -> Option<&crate::dhcpv4::DhcpLease> {
        self.state().dhcpv4.as_ref().and_then(|client| client.lease())
    }

    /// Drop the DHCPv4 lease, if any, and look for a server again.
    ///
    /// Call this when the link went down and came back up, so an address on the
    /// new network is obtained right away. Does nothing if the client is off.
    #[cfg(feature = "dhcpv4")]
    pub fn restart_dhcpv4(&mut self) {
        let Iface { inner, ifaces, index } = self;
        ifaces.get_mut(*index).dhcpv4_reset(inner);
    }
}

/// The device-independent part of the stack.
///
/// Separate from `Stack` so that its methods can borrow an interface from `Stack::ifaces`
/// while taking `&mut self`.
pub(crate) struct StackInner {
    pub(crate) now: Instant,
    #[cfg_attr(not(any(feature = "udp", feature = "tcp")), allow(dead_code))]
    pub(crate) rand: Rand,
    #[cfg(feature = "medium-ethernet")]
    neighbor_cache: NeighborCache,
    #[cfg(feature = "medium-ethernet")]
    pending: PendingQueue,
    pub(crate) routes: Routes,
}

impl StackInner {
    /// Forget everything the link layer learned about an interface: its neighbor
    /// cache entries and the packets parked on them.
    pub(crate) fn purge_iface_link_state(&mut self, handle: IfaceHandle) {
        #[cfg(not(feature = "medium-ethernet"))]
        let _ = handle;
        #[cfg(feature = "medium-ethernet")]
        {
            self.neighbor_cache.purge_iface(handle);
            self.pending.purge_iface(handle);
        }
    }
}

/// Borrowed stack context for socket egress.
///
/// Sockets hand fully-built L4 packets to [`TxContext::transmit_ip`]. Picking the
/// egress interface, building the IP header and resolving the neighbor all happen
/// in here, so socket code doesn't have to care about any of it.
pub(crate) struct TxContext<'a, 'd> {
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<IfaceState<'d>, IFACE_COUNT>,
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
pub(crate) struct EgressRoute {
    pub(crate) iface: IfaceHandle,
    /// The address to resolve on the link: the destination itself when on-link
    /// (or broadcast/multicast), else the gateway from the routing table.
    pub(crate) next_hop: IpAddress,
    /// The egress interface's IP-layer MTU.
    #[cfg_attr(not(feature = "tcp"), allow(dead_code))]
    pub(crate) ip_mtu: usize,
}

impl TxContext<'_, '_> {
    /// The current time, as last set by [`Stack::poll`].
    #[cfg(feature = "tcp")]
    pub(crate) fn now(&self) -> Instant {
        self.inner.now
    }

    /// The stack's PRNG.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.inner.rand
    }

    /// Check whether any interface has the given IP address assigned.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn has_ip_addr(&self, addr: IpAddress) -> bool {
        self.ifaces.iter().any(|(_, iface)| iface.has_ip_addr(addr))
    }

    /// Get a source address for sending to the given destination, selected from the
    /// interface the packet would go out of.
    #[cfg(any(feature = "udp", feature = "tcp"))]
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

    /// [`route`](Self::route) for a locally-generated reply to an ingress packet
    /// that arrived on `arrival`.
    ///
    /// Replies are routed like any other egress, so a reply may leave a different
    /// interface than the packet came in on (asymmetric routing). The
    /// exception is an IPv6 link-local destination: it is meaningful only on the
    /// link the packet came from, so it goes back out the arrival interface, with
    /// the destination itself as the next hop.
    pub(crate) fn route_reply(&self, arrival: IfaceHandle, dst_addr: &IpAddress) -> Option<EgressRoute> {
        #[cfg(not(feature = "ipv6"))]
        let _ = arrival;

        #[cfg(feature = "ipv6")]
        if let IpAddress::Ipv6(dst) = dst_addr
            && dst.is_link_local()
        {
            return Some(EgressRoute {
                iface: arrival,
                next_hop: *dst_addr,
                ip_mtu: self.ifaces.get(arrival.0).ip_mtu(),
            });
        }

        self.route(dst_addr)
    }

    /// Transmit a fully-built IP payload, with the L4 header but not the IP header.
    ///
    /// `src_addr` and `dst_addr` must belong to the same address family, the packet
    /// is dropped otherwise.
    #[cfg(feature = "udp")]
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
            #[cfg(feature = "ipv4")]
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                push_ipv4_header(&mut buf, src, dst, next_header, hop_limit);
                EthernetProtocol::Ipv4
            }
            #[cfg(feature = "ipv6")]
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
            .transmit_ip_frame(iface, dst_addr, route.next_hop, buf, ethertype);
    }

    /// Transmit a fully-built Ethernet frame on the given interface, as-is.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    #[cfg(all(feature = "raw", feature = "medium-ethernet"))]
    pub(crate) fn transmit_ethernet_frame(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        let iface = self.ifaces.get_mut(iface.0);
        self.inner.transmit_raw(iface, buf);
    }

    /// Transmit a fully-built IP packet (IP header included, emitted as-is): pick
    /// the egress interface from the destination address, resolve the neighbor, and
    /// hand the frame to the device.
    ///
    /// Returns `false` if there is no route to the destination.
    #[cfg(feature = "raw")]
    pub(crate) fn transmit_raw_ip(&mut self, buf: PacketBuf, dst_addr: IpAddress) -> bool {
        let Some(route) = self.route(&dst_addr) else {
            debug!("no route to {}, dropping packet", dst_addr);
            return false;
        };
        let iface = self.ifaces.get_mut(route.iface.0);
        let ethertype = match dst_addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
        };
        self.inner
            .transmit_ip_frame(iface, dst_addr, route.next_hop, buf, ethertype);
        true
    }
}

/// Score `addr` against a bind's address filter, the way ingress demux ranks
/// candidate sockets: `None` if it does not match, else how specific the filter
/// that matched it is. No address matches anything (0), an unspecified one
/// matches its own IP version (1), and a concrete one matches only itself (2).
#[cfg(any(feature = "udp", feature = "tcp-listener"))]
pub(crate) fn addr_score(filter: &IpListenEndpoint, addr: &IpAddress) -> Option<u8> {
    match filter.addr {
        None => Some(0),
        Some(a) if a.is_unspecified() => (a.version() == addr.version()).then_some(1),
        Some(a) => (a == *addr).then_some(2),
    }
}

/// The bottom of the ephemeral (dynamic) local port range, per IANA. The range
/// runs to the top of the port space, 65535.
#[cfg(any(feature = "udp", feature = "tcp"))]
pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;

/// Allocate an ephemeral local port: start at a random point in the range and
/// linearly probe upward (wrapping) for the first port `in_use` doesn't claim.
///
/// The random start makes local ports hard to predict for off-path attackers
/// (RFC 6056 §3.3). `None` is returned only when every port in the range is in use.
#[cfg(any(feature = "udp", feature = "tcp"))]
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
}

impl<'d> Stack<'d> {
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
                #[cfg(feature = "udp")]
                udp: Slab::new(),
                #[cfg(feature = "raw")]
                raw: Slab::new(),
                #[cfg(feature = "tcp")]
                tcp: Slab::new(),
                #[cfg(feature = "tcp-listener")]
                tcp_listeners: Slab::new(),
                #[cfg(not(feature = "tcp"))]
                _lent: core::marker::PhantomData,
            },
        }
    }

    /// Add an interface to the stack, returning a handle to it.
    ///
    /// The stack owns the boxed device, so this needs the `alloc` feature.
    /// Without alloc, use [`add_iface_borrowed`](Self::add_iface_borrowed).
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
    /// ).unwrap();
    /// stack
    ///     .iface(handle)
    ///     .add_ip_addr(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 24))
    ///     .unwrap();
    /// # }
    /// ```
    ///
    /// # Panics
    /// Panics if the hardware address is not of the kind the device's medium uses.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another interface. Only possible
    ///   without the `alloc` feature, where the `iface-count-N` feature sets the limit.
    #[cfg(feature = "alloc")]
    pub fn add_iface(
        &mut self,
        dev: alloc::boxed::Box<dyn Interface + 'd>,
        hardware_addr: HardwareAddress,
    ) -> core::result::Result<IfaceHandle, Full> {
        self.add_iface_inner(dev.into(), hardware_addr)
    }

    /// Add an interface to the stack, lending it the device, and returning a
    /// handle to it.
    ///
    /// The stack holds the device until it is dropped or the interface is
    /// removed, so the device must be declared before the stack, or be `'static`.
    /// Otherwise this is [`add_iface`](Self::add_iface).
    ///
    /// # Panics
    /// Panics if the hardware address is not of the kind the device's medium uses.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another interface. Only possible
    ///   without the `alloc` feature, where the `iface-count-N` feature sets the limit.
    pub fn add_iface_borrowed(
        &mut self,
        dev: &'d mut dyn Interface,
        hardware_addr: HardwareAddress,
    ) -> core::result::Result<IfaceHandle, Full> {
        self.add_iface_inner(dev.into(), hardware_addr)
    }

    fn add_iface_inner(
        &mut self,
        dev: MaybeBox<'d, dyn Interface + 'd>,
        hardware_addr: HardwareAddress,
    ) -> core::result::Result<IfaceHandle, Full> {
        assert_eq!(
            hardware_addr.medium(),
            dev.capabilities().medium,
            "hardware address does not match the interface's medium"
        );
        #[allow(unused_mut)]
        let mut ip_addrs = Vec::new();
        #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
        if let Some(ll) = link_local_addr(hardware_addr) {
            // Can't fail: the table is empty and holds at least one address.
            let _ = ip_addrs.push(ll);
        }
        let index = self.ifaces.add_with(|index| IfaceState {
            handle: IfaceHandle(index),
            dev,
            hardware_addr,
            ip_addrs,
            config_generation: 0,
            #[cfg(feature = "async")]
            config_waker: crate::waker::WakerRegistration::new(),
            #[cfg(feature = "dhcpv4")]
            dhcpv4: None,
            #[cfg(feature = "slaac")]
            slaac: None,
            #[cfg(feature = "multicast")]
            multicast: crate::multicast::State::new(),
        })?;
        // The link-local address is already assigned, so its solicited-node
        // group is joined before the first configuration change.
        #[cfg(all(feature = "multicast", feature = "ipv6", feature = "medium-ethernet"))]
        if self.ifaces.get(index).medium() == Medium::Ethernet {
            self.ifaces.get_mut(index).update_solicited_node_groups();
        }
        Ok(IfaceHandle(index))
    }

    /// Borrow an interface from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    pub fn iface(&mut self, handle: IfaceHandle) -> Iface<'_, 'd> {
        self.ifaces.get(handle.0); // Stale handles panic here, not on first use.
        Iface {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
            index: handle.0,
        }
    }

    /// Remove an interface from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was already removed).
    pub fn remove_iface(&mut self, handle: IfaceHandle) {
        self.ifaces.remove(handle.0);
        #[cfg(feature = "medium-ethernet")]
        {
            self.inner.neighbor_cache.purge_iface(handle);
            self.inner.pending.purge_iface(handle);
        }
        self.inner.routes.purge_iface(handle);
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
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another UDP socket. Only possible
    ///   without the `alloc` feature, where the `udp-socket-count-N` feature sets the limit.
    #[cfg(feature = "udp")]
    pub fn add_udp_socket(&mut self) -> core::result::Result<UdpHandle, Full> {
        Ok(UdpHandle(self.sockets.udp.add_with(|_| UdpSocketState::new())?))
    }

    /// Remove a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "udp")]
    pub fn remove_udp_socket(&mut self, handle: UdpHandle) {
        self.sockets.udp.remove(handle.0);
    }

    /// Borrow a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "udp")]
    pub fn udp_socket(&mut self, handle: UdpHandle) -> UdpSocket<'_, 'd> {
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
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another raw socket. Only possible
    ///   without the `alloc` feature, where the `raw-socket-count-N` feature sets the limit.
    #[cfg(feature = "raw")]
    pub fn add_raw_socket(&mut self) -> core::result::Result<RawHandle, Full> {
        Ok(RawHandle(self.sockets.raw.add_with(|_| RawSocketState::new())?))
    }

    /// Remove a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "raw")]
    pub fn remove_raw_socket(&mut self, handle: RawHandle) {
        self.sockets.raw.remove(handle.0);
    }

    /// Borrow a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "raw")]
    pub fn raw_socket(&mut self, handle: RawHandle) -> RawSocket<'_, 'd> {
        RawSocket {
            state: self.sockets.raw.get_mut(handle.0),
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a TCP socket to the stack, with receive and transmit buffers of the
    /// given capacities, returning a handle to it.
    ///
    /// The buffers are allocated on the heap, so this needs the `alloc` feature.
    /// Without it, or to use your own buffers, see
    /// [`add_tcp_socket_with_bufs`](Self::add_tcp_socket_with_bufs).
    ///
    /// # Panics
    /// Panics if the receive buffer is larger than 1 GiB.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another TCP socket. Only possible
    ///   without the `alloc` feature, where the `tcp-socket-count-N` feature sets the limit.
    #[cfg(all(feature = "tcp", feature = "alloc"))]
    pub fn add_tcp_socket(&mut self, rx_capacity: usize, tx_capacity: usize) -> core::result::Result<TcpHandle, Full> {
        self.add_tcp_socket_inner(
            SocketBuffer::new(alloc::vec![0; rx_capacity]),
            SocketBuffer::new(alloc::vec![0; tx_capacity]),
        )
    }

    /// Add a TCP socket to the stack, with borrowed receive and transmit
    /// buffers, and returning a handle to it.
    ///
    /// The stack holds the buffers until it is dropped or the socket is removed,
    /// so they must be declared before the stack, or be `'static`. Otherwise
    /// this is [`add_tcp_socket`](Self::add_tcp_socket).
    ///
    /// ```no_run
    /// # use xarxa::Stack;
    /// # fn add<'d>(stack: &mut Stack<'d>, rx: &'d mut [u8; 4096], tx: &'d mut [u8; 4096]) {
    /// let handle = stack.add_tcp_socket_with_bufs(rx, tx).unwrap();
    /// # }
    /// ```
    ///
    /// # Panics
    /// Panics if the receive buffer is larger than 1 GiB.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another TCP socket. Only possible
    ///   without the `alloc` feature, where the `tcp-socket-count-N` feature sets the limit.
    #[cfg(feature = "tcp")]
    pub fn add_tcp_socket_with_bufs(
        &mut self,
        rx_buffer: &'d mut [u8],
        tx_buffer: &'d mut [u8],
    ) -> core::result::Result<TcpHandle, Full> {
        self.add_tcp_socket_inner(SocketBuffer::new(rx_buffer), SocketBuffer::new(tx_buffer))
    }

    #[cfg(feature = "tcp")]
    fn add_tcp_socket_inner(
        &mut self,
        rx_buffer: SocketBuffer<'d>,
        tx_buffer: SocketBuffer<'d>,
    ) -> core::result::Result<TcpHandle, Full> {
        Ok(TcpHandle(
            self.sockets
                .tcp
                .add_with(|_| TcpSocketState::new(rx_buffer, tx_buffer))?,
        ))
    }

    /// Remove a TCP socket from the stack.
    ///
    /// No RST is sent, and any buffered data is lost. To close a connection cleanly,
    /// [`TcpSocket::close`] it first and poll until it is fully closed.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "tcp")]
    pub fn remove_tcp_socket(&mut self, handle: TcpHandle) {
        self.sockets.tcp.remove(handle.0);
    }

    /// Borrow a TCP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "tcp")]
    pub fn tcp_socket(&mut self, handle: TcpHandle) -> TcpSocket<'_, 'd> {
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
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another listener. Only possible
    ///   without the `alloc` feature, where the `tcp-listener-count-N` feature sets the limit.
    #[cfg(feature = "tcp-listener")]
    pub fn add_tcp_listener(&mut self) -> core::result::Result<TcpListenerHandle, Full> {
        Ok(TcpListenerHandle(
            self.sockets.tcp_listeners.add_with(|_| TcpListenerState::new())?,
        ))
    }

    /// Remove a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "tcp-listener")]
    pub fn remove_tcp_listener(&mut self, handle: TcpListenerHandle) {
        self.sockets.tcp_listeners.remove(handle.0);
    }

    /// Borrow a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "tcp-listener")]
    pub fn tcp_listener(&mut self, handle: TcpListenerHandle) -> TcpListener<'_, 'd> {
        self.sockets.tcp_listeners.get(handle.0); // Stale handles panic here, not on first use.
        TcpListener {
            listeners: &mut self.sockets.tcp_listeners,
            index: handle.0,
            tcp: &mut self.sockets.tcp,
            rand: &mut self.inner.rand,
        }
    }

    /// Borrow the stack context for egress.
    pub(crate) fn tx_context(&mut self) -> TxContext<'_, 'd> {
        TxContext {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
        }
    }

    /// Iterate over the interfaces added to the stack.
    ///
    /// See [`IfaceIter`] for how to use it.
    pub fn ifaces(&mut self) -> IfaceIter<'_, 'd> {
        IfaceIter { stack: self, next: 0 }
    }

    /// Iterate over the UDP sockets added to the stack.
    ///
    /// See [`UdpSocketIter`] for how to use it.
    #[cfg(feature = "udp")]
    pub fn udp_sockets(&mut self) -> UdpSocketIter<'_, 'd> {
        UdpSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the raw sockets added to the stack.
    ///
    /// See [`RawSocketIter`] for how to use it.
    #[cfg(feature = "raw")]
    pub fn raw_sockets(&mut self) -> RawSocketIter<'_, 'd> {
        RawSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the TCP sockets added to the stack.
    ///
    /// See [`TcpSocketIter`] for how to use it.
    #[cfg(feature = "tcp")]
    pub fn tcp_sockets(&mut self) -> TcpSocketIter<'_, 'd> {
        TcpSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the TCP listeners added to the stack.
    ///
    /// See [`TcpListenerIter`] for how to use it.
    #[cfg(feature = "tcp-listener")]
    pub fn tcp_listeners(&mut self) -> TcpListenerIter<'_, 'd> {
        TcpListenerIter { stack: self, next: 0 }
    }

    /// Process all pending ingress packets on all ifaces, advance the stack's
    /// internal timers, and transmit everything the TCP sockets have made due.
    ///
    /// `timestamp` is the current time.
    ///
    /// Returns a "poll deadline" instant. It is the earliest expiring timer. You should call `poll` at that instant to let it advance timers. Special cases:
    /// - If it's [`Instant::MIN`] or in the past, `poll` should be called again immediately.
    /// - If no timer is pending, [`Instant::MAX`] is returned. No need to call `poll` on a timer, only after
    ///   a packet is received or an operation is done on the Stack, a socket or an interface.
    pub fn poll(&mut self, timestamp: Instant) -> Instant {
        self.inner.now = timestamp;

        // Drop queued packets whose neighbor resolution timed out.
        #[cfg(feature = "medium-ethernet")]
        self.inner.pending.purge_expired(timestamp);

        let mut next = 0;
        while let Some(index) = self.ifaces.next_occupied(next) {
            next = index + 1;
            let handle = IfaceHandle(index);

            #[cfg(feature = "medium-ethernet")]
            self.poll_neighbor_timers(handle);

            #[allow(unused_mut)]
            while let Some(mut buf) = self.ifaces.get_mut(index).dev.receive() {
                #[cfg(feature = "packet-log")]
                {
                    trace!("received on iface {}", index);
                    let medium = self.ifaces.get(index).dev.capabilities().medium;
                    crate::packet_log::log_packet(&mut buf, packet_log_layer(medium));
                }
                self.process(handle, buf);
            }

            #[cfg(feature = "dhcpv4")]
            self.ifaces.get_mut(index).dhcpv4_dispatch(&mut self.inner);

            #[cfg(feature = "slaac")]
            {
                let iface = self.ifaces.get_mut(index);
                iface.ndisc_rs_egress(&mut self.inner);
                if iface.slaac.as_ref().is_some_and(|s| s.sync_required(timestamp)) {
                    iface.sync_slaac_state(&mut self.inner);
                }
            }

            #[cfg(feature = "multicast")]
            self.ifaces.get_mut(index).multicast_egress(&mut self.inner);
        }

        #[allow(unused_mut)]
        let mut deadline = Instant::MAX;

        // Drive TCP egress: this both acknowledges what ingress just delivered and
        // advances the TCP timers (retransmissions, delayed ACKs, keep-alives,
        // zero-window probes, ...).
        #[cfg(feature = "tcp")]
        {
            let mut cx = TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            };
            for (_, socket) in self.sockets.tcp.iter_mut() {
                crate::tcp::flush(socket, &mut cx);
            }

            deadline = self
                .sockets
                .tcp
                .iter()
                .map(|(_, socket)| socket.poll_at())
                .fold(deadline, Instant::min);
        }

        #[cfg(feature = "medium-ethernet")]
        {
            deadline = deadline.min(self.inner.neighbor_cache.poll_at());
            deadline = deadline.min(self.inner.pending.poll_at());
        }

        #[cfg(feature = "dhcpv4")]
        {
            deadline = self
                .ifaces
                .iter()
                .filter_map(|(_, iface)| iface.dhcpv4.as_ref().map(|client| client.poll_at()))
                .fold(deadline, Instant::min);
        }

        #[cfg(feature = "slaac")]
        {
            deadline = self
                .ifaces
                .iter()
                .filter_map(|(_, iface)| iface.slaac.as_ref().map(|s| s.poll_at(timestamp)))
                .fold(deadline, Instant::min);
        }

        #[cfg(feature = "multicast")]
        {
            deadline = self
                .ifaces
                .iter()
                .map(|(_, iface)| iface.multicast.poll_at())
                .fold(deadline, Instant::min);
        }

        deadline
    }
}

/// Iterator over the interfaces of a [`Stack`], returned by [`Stack::ifaces`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.ifaces();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.hardware_addr());
/// }
/// # }
/// ```
pub struct IfaceIter<'a, 'd> {
    stack: &'a mut Stack<'d>,
    next: usize,
}

impl<'d> IfaceIter<'_, 'd> {
    /// Get the next interface, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(IfaceHandle, Iface<'_, 'd>)> {
        let index = self.stack.ifaces.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = IfaceHandle(index);
        Some((handle, self.stack.iface(handle)))
    }
}

/// Iterator over the UDP sockets of a [`Stack`], returned by [`Stack::udp_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.udp_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.can_recv());
/// }
/// # }
/// ```
#[cfg(feature = "udp")]
pub struct UdpSocketIter<'a, 'd> {
    stack: &'a mut Stack<'d>,
    next: usize,
}

#[cfg(feature = "udp")]
impl<'d> UdpSocketIter<'_, 'd> {
    /// Get the next UDP socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(UdpHandle, UdpSocket<'_, 'd>)> {
        let index = self.stack.sockets.udp.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = UdpHandle(index);
        Some((handle, self.stack.udp_socket(handle)))
    }
}

/// Iterator over the raw sockets of a [`Stack`], returned by [`Stack::raw_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.raw_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.can_recv());
/// }
/// # }
/// ```
#[cfg(feature = "raw")]
pub struct RawSocketIter<'a, 'd> {
    stack: &'a mut Stack<'d>,
    next: usize,
}

#[cfg(feature = "raw")]
impl<'d> RawSocketIter<'_, 'd> {
    /// Get the next raw socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(RawHandle, RawSocket<'_, 'd>)> {
        let index = self.stack.sockets.raw.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = RawHandle(index);
        Some((handle, self.stack.raw_socket(handle)))
    }
}

/// Iterator over the TCP sockets of a [`Stack`], returned by [`Stack::tcp_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.tcp_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.state());
/// }
/// # }
/// ```
#[cfg(feature = "tcp")]
pub struct TcpSocketIter<'a, 'd> {
    stack: &'a mut Stack<'d>,
    next: usize,
}

#[cfg(feature = "tcp")]
impl<'d> TcpSocketIter<'_, 'd> {
    /// Get the next TCP socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(TcpHandle, TcpSocket<'_, 'd>)> {
        let index = self.stack.sockets.tcp.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = TcpHandle(index);
        Some((handle, self.stack.tcp_socket(handle)))
    }
}

/// Iterator over the TCP listeners of a [`Stack`], returned by [`Stack::tcp_listeners`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.tcp_listeners();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.is_open());
/// }
/// # }
/// ```
#[cfg(feature = "tcp-listener")]
pub struct TcpListenerIter<'a, 'd> {
    stack: &'a mut Stack<'d>,
    next: usize,
}

#[cfg(feature = "tcp-listener")]
impl<'d> TcpListenerIter<'_, 'd> {
    /// Get the next TCP listener, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(TcpListenerHandle, TcpListener<'_, 'd>)> {
        let index = self.stack.sockets.tcp_listeners.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = TcpListenerHandle(index);
        Some((handle, self.stack.tcp_listener(handle)))
    }
}

impl<'d> Stack<'d> {
    fn process(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        match self.ifaces.get(iface.0).dev.capabilities().medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => self.process_ethernet(iface, buf),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.process_ip(iface, buf),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet(&mut self, iface: IfaceHandle, mut buf: PacketBuf) {
        let eth_frame = check!(EthernetFrame::new_checked(&mut buf));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != self.ifaces.get(iface.0).ethernet_addr()
        {
            return;
        }

        let src_addr = eth_frame.src_addr();
        let ethertype = eth_frame.ethertype();

        // Offer the whole frame to Ethernet-mode raw sockets. Ethertypes the stack
        // itself processes are copied to the socket, everything else is consumed
        // by it.
        #[cfg(feature = "raw")]
        let Some(mut buf) = ({
            let stack_wants = matches!(
                ethertype,
                EthernetProtocol::Arp | EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6
            );
            self.process_raw_ethernet(iface, ethertype, stack_wants, buf)
        }) else {
            return;
        };

        buf.pull_front(ETHERNET_HEADER_LEN);

        match ethertype {
            #[cfg(feature = "ipv4")]
            EthernetProtocol::Arp => self.inner.process_arp(self.ifaces.get_mut(iface.0), buf),
            #[cfg(feature = "ipv4")]
            EthernetProtocol::Ipv4 => self.process_ipv4(iface, Some(src_addr), buf),
            #[cfg(feature = "ipv6")]
            EthernetProtocol::Ipv6 => self.process_ipv6(iface, Some(src_addr), buf),
            // Drop all other traffic.
            _ => {}
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        if buf.is_empty() {
            return;
        }
        match IpVersion::of_packet(&buf) {
            #[cfg(feature = "ipv4")]
            Ok(IpVersion::Ipv4) => self.process_ipv4(iface, None, buf),
            #[cfg(feature = "ipv6")]
            Ok(IpVersion::Ipv6) => self.process_ipv6(iface, None, buf),
            Err(_) => {}
        }
    }

    #[cfg(feature = "ipv4")]
    fn process_ipv4(&mut self, iface: IfaceHandle, eth_src: Option<EthernetAddress>, mut buf: PacketBuf) {
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

        // The DHCP client sees its replies before the destination check: they may
        // be addressed to the address being leased, which isn't ours yet, or to
        // broadcast.
        #[cfg(feature = "dhcpv4")]
        if next_header == IpProtocol::Udp && self.ifaces.get(iface.0).dhcpv4.is_some() {
            let udp_len = match buf.get_mut(header_len..total_len).map(UdpPacket::new_checked) {
                Some(Ok(udp)) if udp.src_port() == DHCP_SERVER_PORT && udp.dst_port() == DHCP_CLIENT_PORT => {
                    if !udp.verify_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr)) {
                        trace!("dhcp: udp checksum incorrect");
                        return;
                    }
                    Some(udp.len() as usize)
                }
                _ => None,
            };
            if let Some(udp_len) = udp_len {
                let payload = &mut buf[header_len + UDP_HEADER_LEN..header_len + udp_len];
                self.ifaces
                    .get_mut(iface.0)
                    .dhcpv4_process(&mut self.inner, src_addr, payload);
                return;
            }
        }

        {
            let iface = self.ifaces.get(iface.0);
            if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
                // Discard packets with non-unicast source addresses but allow unspecified
                debug!("non-unicast or unspecified source address");
                return;
            }

            if !iface.has_ip_addr(dst_addr) && !iface.has_multicast_group(dst_addr) && !iface.is_broadcast_v4(dst_addr)
            {
                // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
                trace!("Rejecting IPv4 packet; not for us");
                return;
            }

            #[cfg(feature = "medium-ethernet")]
            if let Some(eth_src) = eth_src
                && iface.is_unicast_v4(dst_addr)
            {
                self.inner.neighbor_cache.reset_expiry_if_existing(
                    (iface.handle, IpAddress::Ipv4(src_addr)),
                    eth_src,
                    self.inner.now,
                );
            }
            #[cfg(not(feature = "medium-ethernet"))]
            let _ = eth_src;
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(total_len);

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(feature = "raw")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmp | IpProtocol::Udp | IpProtocol::Tcp);
            #[cfg(feature = "multicast")]
            let stack_wants = stack_wants || next_header == IpProtocol::Igmp;
            self.process_raw_ip(IpVersion::Ipv4, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(not(feature = "raw"))]
        let handled_by_raw = false;

        // Strip the IP header.
        buf.pull_front(header_len);

        match next_header {
            IpProtocol::Icmp => self.process_icmpv4(iface, src_addr, dst_addr, buf),
            #[cfg(feature = "multicast")]
            IpProtocol::Igmp => self
                .ifaces
                .get_mut(iface.0)
                .process_igmp(&mut self.inner, dst_addr, buf),
            #[cfg(feature = "udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                IpAddress::Ipv4(src_addr),
                IpAddress::Ipv4(dst_addr),
                header_len,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => self.process_tcp(iface, IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr), buf),
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
    #[cfg(feature = "tcp")]
    fn process_tcp(&mut self, iface: IfaceHandle, src_addr: IpAddress, dst_addr: IpAddress, mut buf: PacketBuf) {
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

        // Connected sockets: exact 4-tuple match. Immediate replies the socket
        // state machine produces (RST, challenge ACK) are serialized in the loop,
        // so the socket borrow ends, and transmitted after.
        let mut matched = false;
        let mut reply_buf = None;
        for (_, socket) in self.sockets.tcp.iter_mut() {
            if socket.accepts(&src_addr, &dst_addr, &tcp_repr) {
                matched = true;
                reply_buf = socket
                    .process(self.inner.now, &src_addr, &dst_addr, &tcp_repr)
                    .map(|reply| crate::tcp::build_tcp_packet(&reply, &dst_addr, &src_addr));
                break;
            }
        }
        if matched {
            if let Some(reply) = reply_buf {
                self.transmit_reply(iface, reply, dst_addr, src_addr, IpProtocol::Tcp, 64);
            }
            return;
        }

        // Listeners: a SYN to a listened endpoint is recorded in the accept
        // queue of the most specific matching listener (exact local address
        // beats wildcard), and an RST aimed at a recorded SYN cancels it.
        // Nothing is replied, the handshake starts when the connection is
        // accepted.
        #[cfg(feature = "tcp-listener")]
        if crate::tcp::process_listeners(&mut self.sockets.tcp_listeners, &src_addr, &dst_addr, &tcp_repr) {
            return;
        }

        // The packet wasn't handled by a socket: send a TCP RST packet.
        // Never reply to a TCP RST packet with another TCP RST packet.
        if tcp_repr.control != TcpControl::Rst {
            let reply = TcpSocketState::rst_reply(&tcp_repr);
            let reply = crate::tcp::build_tcp_packet(&reply, &dst_addr, &src_addr);
            self.transmit_reply(iface, reply, dst_addr, src_addr, IpProtocol::Tcp, 64);
        }
    }

    #[cfg(feature = "ipv4")]
    fn process_icmpv4(&mut self, iface: IfaceHandle, src_addr: Ipv4Address, dst_addr: Ipv4Address, mut buf: PacketBuf) {
        let mut icmp_packet = check!(Icmpv4Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum() {
            trace!("icmpv4: checksum incorrect");
            return;
        }

        #[cfg(not(feature = "icmp-ping-reply"))]
        let _ = (iface, src_addr, dst_addr);
        #[cfg(not(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp"))))]
        let _ = &mut icmp_packet;

        match (icmp_packet.msg_type(), icmp_packet.msg_code()) {
            // Respond to echo requests.
            #[cfg(feature = "icmp-ping-reply")]
            (Icmpv4Message::EchoRequest, 0) => {
                let reply_src = {
                    let iface = self.ifaces.get(iface.0);
                    // Do not send ICMP replies to non-unicast sources.
                    if !iface.is_unicast_v4(src_addr) {
                        return;
                    }
                    // Reply as normal when src_addr and dst_addr are both unicast; only
                    // reply to broadcasts for echo replies and not other ICMP messages.
                    if iface.is_unicast_v4(dst_addr) {
                        dst_addr
                    } else if iface.is_broadcast_v4(dst_addr) {
                        match iface.ipv4_addr() {
                            Some(addr) => addr,
                            None => return,
                        }
                    } else {
                        return;
                    }
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
                self.transmit_reply(
                    iface,
                    reply,
                    IpAddress::Ipv4(reply_src),
                    IpAddress::Ipv4(src_addr),
                    IpProtocol::Icmp,
                    64,
                );
            }

            // Ignore any echo replies.
            (Icmpv4Message::EchoReply, _) => {}

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
            (msg_type, msg_code) if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
                    self.deliver_icmp_error(error, icmp_packet.data_mut());
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
    #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
    fn deliver_icmp_error(&mut self, error: IcmpError, quote: &mut [u8]) {
        let Some(quoted) = parse_quoted_packet(quote) else {
            trace!("icmp error: quote too short to identify a flow, ignoring");
            return;
        };
        let local = IpEndpoint::new(quoted.src_addr, quoted.src_port);
        let remote = IpEndpoint::new(quoted.dst_addr, quoted.dst_port);
        match quoted.protocol {
            #[cfg(feature = "udp")]
            IpProtocol::Udp => crate::udp::process_icmp_error(&mut self.sockets.udp, error, local, remote),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => {
                crate::tcp::process_icmp_error(&mut self.sockets.tcp, error, local, remote, quoted.tcp_seq)
            }
            _ => {}
        }
    }

    #[cfg(feature = "ipv6")]
    fn process_ipv6(&mut self, iface: IfaceHandle, eth_src: Option<EthernetAddress>, mut buf: PacketBuf) {
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

        {
            let iface = self.ifaces.get(iface.0);
            if !iface.has_ip_addr(dst_addr) && !iface.has_multicast_group(dst_addr) && !dst_addr.is_loopback() {
                trace!("Rejecting IPv6 packet; not for us");
                return;
            }

            #[cfg(feature = "medium-ethernet")]
            if let Some(eth_src) = eth_src
                && dst_addr.x_is_unicast()
            {
                self.inner.neighbor_cache.reset_expiry_if_existing(
                    (iface.handle, IpAddress::Ipv6(src_addr)),
                    eth_src,
                    self.inner.now,
                );
            }
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
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(feature = "raw")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmpv6 | IpProtocol::Udp | IpProtocol::Tcp);
            self.process_raw_ip(IpVersion::Ipv6, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(not(feature = "raw"))]
        let handled_by_raw = false;

        // Strip the IP header (and any extension headers).
        buf.pull_front(l4_offset);

        match next_header {
            IpProtocol::Icmpv6 => self.process_icmpv6(iface, eth_src, src_addr, dst_addr, hop_limit, buf),
            #[cfg(feature = "udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                IpAddress::Ipv6(src_addr),
                IpAddress::Ipv6(dst_addr),
                l4_offset,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => self.process_tcp(iface, IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr), buf),
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

    #[cfg(feature = "ipv6")]
    fn process_icmpv6(
        &mut self,
        iface: IfaceHandle,
        eth_src: Option<EthernetAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
        mut buf: PacketBuf,
    ) {
        #[cfg(not(all(feature = "medium-ethernet", feature = "ipv6")))]
        let _ = (eth_src, hop_limit);
        #[cfg(not(feature = "icmp-ping-reply"))]
        let _ = iface;

        let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
        if !icmp_packet.verify_checksum(&src_addr, &dst_addr) {
            trace!("icmpv6: checksum incorrect");
            return;
        }

        #[cfg(not(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp"))))]
        let _ = &mut icmp_packet;

        match icmp_packet.msg_type() {
            // Respond to echo requests.
            #[cfg(feature = "icmp-ping-reply")]
            Icmpv6Message::EchoRequest => {
                let reply_src = if dst_addr.x_is_unicast() {
                    dst_addr
                } else {
                    self.ifaces.get(iface.0).get_source_address_ipv6(&src_addr)
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
                self.transmit_reply(
                    iface,
                    reply,
                    IpAddress::Ipv6(reply_src),
                    IpAddress::Ipv6(src_addr),
                    IpProtocol::Icmpv6,
                    64,
                );
            }

            // Ignore any echo replies.
            Icmpv6Message::EchoReply => {}

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
            msg_type if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv6(msg_type, icmp_packet.msg_code()) {
                    self.deliver_icmp_error(error, icmp_packet.payload_mut());
                }
            }

            // NDISC is only processed if the packet arrived with the un-decremented
            // hop limit, and only on Ethernet mediums.
            #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
            Icmpv6Message::NeighborSolicit if hop_limit == 0xff && eth_src.is_some() => self
                .inner
                .process_ndisc_solicit(self.ifaces.get_mut(iface.0), src_addr, dst_addr, &mut icmp_packet),

            #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
            Icmpv6Message::NeighborAdvert if hop_limit == 0xff && eth_src.is_some() => {
                self.inner
                    .process_ndisc_advert(self.ifaces.get_mut(iface.0), src_addr, &mut icmp_packet)
            }

            // [RFC 3810 § 6.2], reception checks
            #[cfg(feature = "multicast")]
            Icmpv6Message::MldQuery if hop_limit == 1 && src_addr.is_link_local() => self
                .ifaces
                .get_mut(iface.0)
                .process_mldv2(&mut self.inner, dst_addr, &icmp_packet),

            // RFC 4861 §6.1.2: a router advertisement is only valid from a link-local
            // source, with the un-decremented hop limit.
            #[cfg(feature = "slaac")]
            Icmpv6Message::RouterAdvert
                if hop_limit == 0xff
                    && eth_src.is_some()
                    && src_addr.is_link_local()
                    && (dst_addr == IPV6_LINK_LOCAL_ALL_NODES || dst_addr.is_link_local()) =>
            {
                self.ifaces
                    .get_mut(iface.0)
                    .slaac_process_advertisement(&mut self.inner, src_addr, &mut icmp_packet)
            }

            _ => {}
        }
    }

    /// Advance the solicitation retransmission timers of the neighbors being resolved
    /// on this interface, retransmitting solicitations and failing resolutions that
    /// exhausted their probes.
    #[cfg(feature = "medium-ethernet")]
    fn poll_neighbor_timers(&mut self, iface: IfaceHandle) {
        let mut cursor = 0;
        while let Some(event) = self
            .inner
            .neighbor_cache
            .poll_retransmit(iface, self.inner.now, &mut cursor)
        {
            match event {
                ProbeEvent::Retransmit(addr) => {
                    debug!("neighbor {} still unresolved, retransmitting solicitation", addr);
                    self.inner.solicit_neighbor(self.ifaces.get_mut(iface.0), addr);
                }
                ProbeEvent::Failed(addr) => {
                    debug!("neighbor {} resolution failed, dropping queued packets", addr);
                    // RFC 4861 §7.3.3: answer each packet queued on the failed
                    // resolution with an ICMP destination unreachable error.
                    #[cfg(feature = "icmp-errors")]
                    while let Some(packet) = self.inner.pending.pop_matching(&(iface, addr)) {
                        self.deliver_neighbor_failure_error(iface, packet.buf);
                    }
                    #[cfg(not(feature = "icmp-errors"))]
                    while self.inner.pending.pop_matching(&(iface, addr)).is_some() {}
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
    #[cfg(all(feature = "medium-ethernet", feature = "icmp-errors"))]
    fn deliver_neighbor_failure_error(&mut self, iface: IfaceHandle, mut orig: PacketBuf) {
        match IpVersion::of_packet(&orig) {
            #[cfg(feature = "ipv4")]
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
                let reply_src = {
                    let iface = self.ifaces.get(iface.0);
                    if !iface.is_unicast_v4(src_addr) {
                        return;
                    }
                    match iface.get_source_address_ipv4(&src_addr) {
                        Some(addr) => addr,
                        None => return,
                    }
                };
                let mut reply = build_icmpv4_error(
                    &orig,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::HostUnreachable.into(),
                );
                push_ipv4_header(&mut reply, reply_src, src_addr, IpProtocol::Icmp, 64);
                self.process_ipv4(iface, None, reply);
            }
            #[cfg(feature = "ipv6")]
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
                let reply_src = self.ifaces.get(iface.0).get_source_address_ipv6(&src_addr);
                let mut reply = build_icmpv6_error(
                    &orig,
                    &reply_src,
                    &src_addr,
                    Icmpv6Message::DstUnreachable,
                    Icmpv6DstUnreachable::AddrUnreachable.into(),
                    0,
                );
                push_ipv6_header(&mut reply, reply_src, src_addr, IpProtocol::Icmpv6, 64);
                self.process_ipv6(iface, None, reply);
            }
            Err(_) => {}
        }
    }

    /// Transmit an ICMPv4 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are only sent when both the source and the destination of the
    /// offending packet are unicast (RFC 1122 §3.2.2): none about broadcast or
    /// multicast traffic, and none to non-unicast senders.
    #[cfg(feature = "ipv4")]
    pub(crate) fn transmit_icmpv4_error(
        &mut self,
        iface: IfaceHandle,
        orig: &mut PacketBuf,
        msg_type: Icmpv4Message,
        msg_code: u8,
    ) {
        let (src_addr, dst_addr) = {
            let packet = Ipv4Packet::new_unchecked(orig);
            (packet.src_addr(), packet.dst_addr())
        };
        {
            let iface = self.ifaces.get(iface.0);
            if !iface.is_unicast_v4(src_addr) || !iface.is_unicast_v4(dst_addr) {
                return;
            }
        }
        let reply = build_icmpv4_error(orig, msg_type, msg_code);
        self.transmit_reply(
            iface,
            reply,
            IpAddress::Ipv4(dst_addr),
            IpAddress::Ipv4(src_addr),
            IpProtocol::Icmp,
            64,
        );
    }

    /// Transmit an ICMPv6 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are never sent to non-unicast sources, nor about multicast-destined
    /// packets (RFC 4443 §2.4). The exception is an unrecognized hop-by-hop option
    /// whose type demands the error even then (`allow_multicast_dst`).
    #[cfg(feature = "ipv6")]
    pub(crate) fn transmit_icmpv6_error(
        &mut self,
        iface: IfaceHandle,
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
            self.ifaces.get(iface.0).get_source_address_ipv6(&src_addr)
        };
        let reply = build_icmpv6_error(orig, &reply_src, &src_addr, msg_type, msg_code, pointer);
        self.transmit_reply(
            iface,
            reply,
            IpAddress::Ipv6(reply_src),
            IpAddress::Ipv6(src_addr),
            IpProtocol::Icmpv6,
            64,
        );
    }

    /// Route and transmit a locally-generated reply to an ingress packet that
    /// arrived on `arrival`.
    ///
    /// Replies are routed like any other egress ([`TxContext::route_reply`]), so
    /// they may leave a different interface than the packet came in on. With no
    /// route to the destination the reply is dropped.
    fn transmit_reply(
        &mut self,
        arrival: IfaceHandle,
        buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let mut tx = self.tx_context();
        let Some(route) = tx.route_reply(arrival, &dst_addr) else {
            debug!("no route to {}, dropping reply", dst_addr);
            return;
        };
        tx.transmit_ip_routed(&route, buf, src_addr, dst_addr, next_header, hop_limit);
    }
}

// The link-level machinery: ARP and NDISC, the neighbor cache, and frame
// transmission. These are `StackInner` methods operating on one interface,
// because they serve both ingress (above) and socket egress (`TxContext`).
impl StackInner {
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    fn process_arp(&mut self, iface: &mut IfaceState<'_>, mut buf: PacketBuf) {
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

    #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
    fn process_ndisc_solicit(
        &mut self,
        iface: &mut IfaceState<'_>,
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
            self.transmit_ndisc(iface, reply, target_addr, src_addr);
        }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
    fn process_ndisc_advert(
        &mut self,
        iface: &mut IfaceState<'_>,
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

    /// Send a solicitation (ARP request / NDISC neighbor solicit) for the given address.
    #[cfg(feature = "medium-ethernet")]
    fn solicit_neighbor(&mut self, iface: &mut IfaceState<'_>, addr: IpAddress) {
        match addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(addr) => self.transmit_arp_request(iface, addr),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(addr) => self.transmit_ndisc_solicit(iface, addr),
        }
    }

    /// Fill the neighbor cache, and flush any packets that were queued waiting for
    /// this neighbor to resolve.
    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn fill_neighbor(
        &mut self,
        iface: &mut IfaceState<'_>,
        addr: IpAddress,
        hardware_addr: EthernetAddress,
    ) {
        let key = (iface.handle, addr);
        self.neighbor_cache.fill(key, hardware_addr, self.now);

        while let Some(packet) = self.pending.pop_matching(&key) {
            trace!("neighbor: {} resolved, flushing queued packet", addr);
            let ethertype = match packet.key.1 {
                #[cfg(feature = "ipv4")]
                IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                #[cfg(feature = "ipv6")]
                IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
            };
            self.transmit_ethernet(iface, hardware_addr, packet.buf, ethertype);
        }
    }

    /// Look up the destination hardware address for an egress packet, sending a
    /// solicitation (ARP request / NDISC neighbor solicit) if it is not resolved yet.
    ///
    /// `next_hop` is the pre-routed address to resolve on the link, from an
    /// [`EgressRoute`].
    #[cfg(feature = "medium-ethernet")]
    fn lookup_hardware_addr(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: &IpAddress,
        next_hop: IpAddress,
    ) -> NeighborLookup {
        if iface.is_broadcast(dst_addr) {
            return NeighborLookup::Found(EthernetAddress::BROADCAST);
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "ipv4")]
                IpAddress::Ipv4(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x01, 0x00, 0x5e, b[1] & 0x7F, b[2], b[3]])
                }
                #[cfg(feature = "ipv6")]
                IpAddress::Ipv6(addr) => {
                    let b = addr.octets();
                    EthernetAddress::from_bytes(&[0x33, 0x33, b[12], b[13], b[14], b[15]])
                }
            };

            return NeighborLookup::Found(hardware_addr);
        }

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

    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    fn transmit_arp_request(&mut self, iface: &mut IfaceState<'_>, target_addr: Ipv4Address) {
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

    #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
    fn transmit_ndisc_solicit(&mut self, iface: &mut IfaceState<'_>, target_addr: Ipv6Address) {
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
        self.transmit_ndisc(iface, buf, src_addr, dst_addr);
    }

    /// Transmit an NDISC message on the given interface.
    ///
    /// NDISC is link-scoped: the packet is never routed, and the next hop is the
    /// destination itself (an on-link neighbor or a multicast group).
    #[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
    pub(crate) fn transmit_ndisc(
        &mut self,
        iface: &mut IfaceState<'_>,
        mut buf: PacketBuf,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) {
        push_ipv6_header(&mut buf, src_addr, dst_addr, IpProtocol::Icmpv6, 0xff);
        self.transmit_ip_frame(
            iface,
            IpAddress::Ipv6(dst_addr),
            IpAddress::Ipv6(dst_addr),
            buf,
            EthernetProtocol::Ipv6,
        );
    }

    /// Transmit a fully-built IP packet, resolving the destination hardware address
    /// on Ethernet mediums.
    ///
    /// `next_hop` is the pre-routed address to resolve on the link, from an
    /// [`EgressRoute`].
    ///
    /// If the neighbor is not resolved yet, the packet is queued in the interface's
    /// pending queue and flushed when resolution completes.
    /// Transmit a fully-built UDP packet on a given interface as an IPv4 packet from
    /// `src_addr` to `dst_addr`, bypassing routing and source address checks.
    ///
    /// This is how the DHCP client sends from `0.0.0.0` to broadcast on an interface
    /// that has no address yet. A unicast destination that is not on-link is sent
    /// via the routing table's gateway, if any, else directly.
    #[cfg(feature = "dhcpv4")]
    pub(crate) fn transmit_ipv4_on(
        &mut self,
        iface: &mut IfaceState<'_>,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        mut buf: PacketBuf,
    ) {
        push_ipv4_header(&mut buf, src_addr, dst_addr, IpProtocol::Udp, 64);
        let dst = IpAddress::Ipv4(dst_addr);
        let next_hop = if !dst.is_unicast() || iface.in_same_network(&dst) {
            dst
        } else {
            self.routes
                .lookup(&dst, self.now)
                .map(|route| route.via_router)
                .unwrap_or(dst)
        };
        self.transmit_ip_frame(iface, dst, next_hop, buf, EthernetProtocol::Ipv4);
    }

    pub(crate) fn transmit_ip_frame(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: IpAddress,
        next_hop: IpAddress,
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
            },
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn transmit_ethernet(
        &mut self,
        iface: &mut IfaceState<'_>,
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

    fn transmit_raw(&mut self, iface: &mut IfaceState<'_>, #[allow(unused_mut)] mut buf: PacketBuf) {
        #[cfg(feature = "packet-log")]
        {
            trace!("sent on iface {}", iface.handle.0);
            let medium = iface.dev.capabilities().medium;
            crate::packet_log::log_packet(&mut buf, packet_log_layer(medium));
        }
        if iface.dev.transmit(buf).is_err() {
            debug!("iface: cannot transmit, dropping packet");
        }
    }
}

/// The outermost header of a frame on an interface of this medium.
#[cfg(feature = "packet-log")]
fn packet_log_layer(medium: Medium) -> crate::packet_log::Layer {
    match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => crate::packet_log::Layer::Ethernet,
        #[cfg(feature = "medium-ip")]
        Medium::Ip => crate::packet_log::Layer::Ip,
    }
}

/// Prepend an IPv4 header to a fully-built L4 payload.
#[cfg(feature = "ipv4")]
pub(crate) fn push_ipv4_header(
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
#[cfg(feature = "ipv6")]
pub(crate) fn push_ipv6_header(
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
#[cfg(feature = "ipv4")]
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
#[cfg(feature = "ipv6")]
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
#[cfg(feature = "ipv6")]
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
#[cfg(feature = "ipv6")]
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

impl IfaceState<'_> {
    /// The interface's medium.
    #[cfg(all(
        feature = "medium-ethernet",
        any(feature = "raw", all(feature = "multicast", feature = "ipv6"))
    ))]
    pub(crate) fn medium(&self) -> Medium {
        self.dev.capabilities().medium
    }

    /// The interface's Ethernet address.
    ///
    /// Panics on a non-Ethernet interface; only the Ethernet paths call it, and
    /// `add_iface` checks the address matches the medium.
    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn ethernet_addr(&self) -> EthernetAddress {
        self.hardware_addr.ethernet_or_panic()
    }

    /// Note that the interface's configuration changed: bump the generation and
    /// wake whoever is waiting for it.
    ///
    /// Also keeps the solicited-node multicast groups in step with the addresses,
    /// since every address change passes through here.
    pub(crate) fn config_changed(&mut self) {
        #[cfg(all(feature = "multicast", feature = "ipv6", feature = "medium-ethernet"))]
        if self.medium() == Medium::Ethernet {
            self.update_solicited_node_groups();
        }
        self.config_generation = self.config_generation.wrapping_add(1);
        #[cfg(feature = "async")]
        self.config_waker.wake();
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

    /// The assigned addresses, without their origin.
    pub(crate) fn cidrs(&self) -> impl Iterator<Item = &IpCidr> + '_ {
        self.ip_addrs.iter().map(|a| &a.cidr)
    }

    pub(crate) fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.cidrs().any(|probe| probe.address() == addr)
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.cidrs().any(|cidr| cidr.contains_addr(addr))
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(all(feature = "ipv4", any(feature = "icmp-ping-reply", feature = "multicast")))]
    pub(crate) fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.cidrs().find_map(|addr| match *addr {
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
    #[cfg(all(feature = "ipv4", any(feature = "medium-ethernet", feature = "udp", feature = "tcp")))]
    fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.cidrs() {
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
    #[cfg(any(feature = "udp", feature = "tcp"))]
    fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(IpAddress::Ipv4),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(addr) => Some(IpAddress::Ipv6(self.get_source_address_ipv6(addr))),
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(any(feature = "medium-ethernet", feature = "udp"))]
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(feature = "ipv4")]
    fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.cidrs()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "ipv4")]
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "ipv6")]
    pub(crate) fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.cidrs().any(|cidr| {
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

    /// Check whether the interface listens to given destination multicast IP address.
    pub(crate) fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();

        #[cfg(feature = "multicast")]
        if self.multicast.has_multicast_group(addr) {
            return true;
        }

        match addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(key) => key == IPV4_MULTICAST_ALL_SYSTEMS,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(key) => key == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(key),
        }
    }

    /// Get the first link-local IPv6 address of the interface, if present.
    #[cfg(any(feature = "slaac", all(feature = "ipv6", feature = "multicast")))]
    pub(crate) fn link_local_ipv6_address(&self) -> Option<Ipv6Address> {
        self.cidrs().find_map(|cidr| match *cidr {
            IpCidr::Ipv6(cidr) if cidr.address().is_link_local() => Some(cidr.address()),
            _ => None,
        })
    }

    /// Return the IPv6 address that is a candidate source address for the given destination
    /// address, based on RFC 6724.
    ///
    /// # Panics
    /// This function panics if the destination address is unspecified.
    #[cfg(feature = "ipv6")]
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
        if dst_addr.is_loopback() || self.cidrs().filter(|a| matches!(a, IpCidr::Ipv6(_))).count() == 0 {
            return Ipv6Address::LOCALHOST;
        }

        let mut candidate = self
            .cidrs()
            .find_map(|a| match a {
                #[cfg(feature = "ipv4")]
                IpCidr::Ipv4(_) => None,
                IpCidr::Ipv6(a) => Some(a),
            })
            .unwrap(); // NOTE: we check above that there is at least one IPv6 address.

        for addr in self.cidrs().filter_map(|a| match a {
            #[cfg(feature = "ipv4")]
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
#[cfg(all(feature = "medium-ethernet", feature = "ipv6"))]
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
    feature = "ipv4",
    feature = "ipv6",
    feature = "raw",
    feature = "udp",
    feature = "tcp"
))]
mod test {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::iface::IfaceCapabilities;
    use crate::neighbor::MAX_MULTICAST_SOLICIT;
    use crate::raw::RawMode;
    #[cfg(feature = "slaac")]
    use crate::route::RouteOrigin;
    #[cfg(feature = "slaac")]
    use crate::slaac::{SlaacConfig, SlaacState};
    use crate::tcp::State as TcpState;
    use crate::time::Duration;
    use crate::udp::RecvError as UdpRecvError;
    #[allow(unused_imports)]
    use std::vec::Vec;

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
    fn test_stack(medium: Medium) -> (Stack<'static>, Queue, Sent) {
        let rx = Rc::new(RefCell::new(VecDeque::new()));
        let tx = Rc::new(RefCell::new(Vec::new()));
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack
            .add_iface_borrowed(
                Box::leak(Box::new(TestDevice {
                    medium,
                    rx: rx.clone(),
                    tx: tx.clone(),
                })),
                match medium {
                    Medium::Ethernet => HardwareAddress::Ethernet(OUR_HW),
                    Medium::Ip => HardwareAddress::Ip,
                },
            )
            .unwrap();
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)])
            .unwrap();
        // Drain the solicited-node multicast reports the new addresses trigger, so
        // the tests only see the frames they provoke.
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();
        (stack, rx, tx)
    }

    /// OUR_HW 02:00:00:00:00:01 -> fe80::ff:fe00:1 (modified EUI-64 flips the U/L bit back).
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    const OUR_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x1);

    #[test]
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    fn test_auto_link_local() {
        let ll = IfaceAddr {
            cidr: IpCidr::new(OUR_LINK_LOCAL.into(), 64),
            origin: AddrOrigin::LinkLocal,
        };
        let (mut stack, _rx, _tx) = test_stack(Medium::Ethernet);
        let handle = IfaceHandle(0);

        // Present after add_iface, survives set_ip_addrs.
        assert!(stack.iface(handle).ip_addrs().contains(&ll));
        assert!(stack.iface(handle).has_ip_addr(OUR_LINK_LOCAL));

        // Follows the hardware address.
        let generation = stack.iface(handle).config_generation();
        stack
            .iface(handle)
            .set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x02])));
        assert!(!stack.iface(handle).has_ip_addr(OUR_LINK_LOCAL));
        assert!(
            stack
                .iface(handle)
                .has_ip_addr(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2))
        );
        assert_ne!(stack.iface(handle).config_generation(), generation);

        // Can be removed by hand, and a user-set link-local is kept by set_ip_addrs.
        stack
            .iface(handle)
            .remove_ip_addr(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2));
        assert!(
            !stack
                .iface(handle)
                .ip_addrs()
                .iter()
                .any(|a| a.origin == AddrOrigin::LinkLocal)
        );
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V6.into(), 64)])
            .unwrap();
        assert_eq!(
            stack.iface(handle).ip_addrs(),
            &[IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64))]
        );

        // No link-local on an IP-medium interface.
        let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
        assert!(
            !stack
                .iface(handle)
                .ip_addrs()
                .iter()
                .any(|a| a.origin == AddrOrigin::LinkLocal)
        );
    }

    /// An Ethernet frame carrying a router advertisement from `router_hw`/`router_ll`
    /// to all nodes: hop limit 255, source link-layer option, one prefix information
    /// option for `prefix`/64 with the A and L flags.
    #[cfg(feature = "slaac")]
    fn router_advert(
        router_hw: EthernetAddress,
        router_ll: Ipv6Address,
        router_lifetime: Duration,
        prefix: Ipv6Address,
        valid_lifetime: Duration,
        preferred_lifetime: Duration,
    ) -> Vec<u8> {
        let mut icmp = vec![0; 16 + 8 + 32];
        {
            let mut ra = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            ra.set_msg_type(Icmpv6Message::RouterAdvert);
            ra.set_msg_code(0);
            ra.set_current_hop_limit(64);
            ra.set_router_flags(NdiscRouterFlags::OTHER);
            ra.set_router_lifetime(router_lifetime);
            ra.set_reachable_time(Duration::ZERO);
            ra.set_retrans_time(Duration::ZERO);
            let options = ra.payload_mut();
            {
                let mut opt = NdiscOption::new_unchecked(&mut options[..8]);
                opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
                opt.set_data_len(1);
                opt.set_link_layer_addr(RawHardwareAddress::from(router_hw));
            }
            {
                let mut opt = NdiscOption::new_unchecked(&mut options[8..]);
                opt.set_option_type(NdiscOptionType::PrefixInformation);
                opt.set_data_len(4);
                opt.set_prefix_len(64);
                opt.set_prefix_flags(NdiscPrefixInfoFlags::ON_LINK | NdiscPrefixInfoFlags::ADDRCONF);
                opt.set_valid_lifetime(valid_lifetime);
                opt.set_preferred_lifetime(preferred_lifetime);
                opt.clear_prefix_reserved();
                opt.set_prefix(prefix);
            }
            ra.fill_checksum(&router_ll, &IPV6_LINK_LOCAL_ALL_NODES);
        }
        let mut ip = ipv6_packet(router_ll, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol::Icmpv6, &icmp);
        Ipv6Packet::new_unchecked(&mut ip[..]).set_hop_limit(255);

        let mut frame = vec![0; ETHERNET_HEADER_LEN];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame[..]);
            eth.set_dst_addr(EthernetAddress([0x33, 0x33, 0, 0, 0, 1]));
            eth.set_src_addr(router_hw);
            eth.set_ethertype(EthernetProtocol::Ipv6);
        }
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac() {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let our_addr = IpCidr::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into(), 64);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        assert_eq!(stack.iface(iface).slaac(), Some(&SlaacState::default()));
        let generation = stack.iface(iface).config_generation();

        // The first poll solicits routers, from the link-local address to all
        // routers, with our link-layer address attached.
        let deadline = stack.poll(Instant::from_secs(1));
        assert_eq!(tx.borrow().len(), 1);
        {
            let frame = &tx.borrow()[0];
            let mut eth_bytes = frame.clone();
            let eth = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
            assert_eq!(eth.dst_addr(), EthernetAddress([0x33, 0x33, 0, 0, 0, 2]));
            assert_eq!(eth.src_addr(), OUR_HW);
            let mut ip_bytes = frame[ETHERNET_HEADER_LEN..].to_vec();
            assert_eq!(Ipv6Packet::new_unchecked(&mut ip_bytes[..]).hop_limit(), 255);
            let (msg_type, _, _, options) = parse_icmpv6_reply(
                &frame[ETHERNET_HEADER_LEN..],
                OUR_LINK_LOCAL,
                IPV6_LINK_LOCAL_ALL_ROUTERS,
            );
            assert_eq!(msg_type, Icmpv6Message::RouterSolicit);
            assert_eq!(options, [&[1, 1][..], OUR_HW.as_bytes()].concat());
        }
        // Retransmitted every 4 s, three times in total.
        assert_eq!(deadline, Instant::from_secs(5));
        stack.poll(Instant::from_secs(5));
        assert_eq!(tx.borrow().len(), 2);

        // A router answers: the address, the default route and the router's
        // link-layer address are all installed, and solicitation stops.
        let now = Instant::from_secs(6);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        let deadline = stack.poll(now);
        assert_eq!(tx.borrow().len(), 2);
        assert_eq!(deadline, now + Duration::from_secs(1800));
        assert!(stack.iface(iface).ip_addrs().contains(&IfaceAddr {
            cidr: our_addr,
            origin: AddrOrigin::Slaac,
        }));
        let route = stack.routes().get_default_ipv6_route().unwrap();
        assert_eq!(route.via_router, IpAddress::Ipv6(router_ll));
        assert_eq!(route.iface, iface);
        assert_eq!(route.origin, RouteOrigin::Slaac);
        assert_eq!(route.expires_at, Some(now + Duration::from_secs(1800)));
        assert_ne!(stack.iface(iface).config_generation(), generation);
        let state = *stack.iface(iface).slaac().unwrap();
        assert!(state.routers_seen);
        assert!(!state.managed);
        assert!(state.other_config);
        stack.poll(Instant::from_secs(9));
        assert_eq!(tx.borrow().len(), 2);

        // Off-link traffic goes via the router, whose address is already resolved.
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();
        stack
            .udp_socket(udp)
            .send_slice(b"hi", (Ipv6Address::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1), 1000))
            .unwrap();
        assert_eq!(tx.borrow().len(), 3);
        {
            let frame = &tx.borrow()[2];
            let mut eth_bytes = frame.clone();
            let eth = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
            assert_eq!(eth.dst_addr(), router_hw);
            let mut ip_bytes = frame[ETHERNET_HEADER_LEN..].to_vec();
            assert_eq!(
                IpAddress::Ipv6(Ipv6Packet::new_unchecked(&mut ip_bytes[..]).src_addr()),
                our_addr.address()
            );
        }

        // A refresh extends the lifetimes.
        let now = Instant::from_secs(600);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        let deadline = stack.poll(now);
        assert_eq!(deadline, now + Duration::from_secs(1800));
        let route = stack.routes().get_default_ipv6_route().unwrap();
        assert_eq!(route.expires_at, Some(now + Duration::from_secs(1800)));

        // The route expires first, then the address.
        let generation = stack.iface(iface).config_generation();
        let deadline = stack.poll(now + Duration::from_secs(1801));
        assert!(stack.routes().get_default_ipv6_route().is_none());
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert_ne!(stack.iface(iface).config_generation(), generation);
        assert_eq!(deadline, now + Duration::from_secs(7200));
        let deadline = stack.poll(now + Duration::from_secs(7201));
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert_eq!(deadline, Instant::MAX);

        // A router can withdraw with zero lifetimes.
        let now = now + Duration::from_secs(7300);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(now);
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_some());
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::ZERO,
            prefix,
            Duration::ZERO,
            Duration::ZERO,
        ));
        stack.poll(now + Duration::from_secs(1));
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_none());

        // Turning SLAAC off removes what it installed, and nothing else.
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(now + Duration::from_secs(2));
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        stack.iface(iface).set_slaac(None);
        assert!(stack.iface(iface).slaac().is_none());
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_none());
        assert!(stack.iface(iface).has_ip_addr(OUR_V6));
        assert!(stack.iface(iface).has_ip_addr(OUR_LINK_LOCAL));
    }

    /// A router advertisement that is not from a link-local source is ignored.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_ignores_invalid_advert() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle(0);
        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        rx.borrow_mut().push_back(router_advert(
            EthernetAddress([0x02, 0, 0, 0, 0, 0x02]),
            Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xbad),
            Duration::from_secs(1800),
            Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(1));
        assert!(!stack.iface(iface).slaac().unwrap().routers_seen);
        assert!(stack.routes().get_default_ipv6_route().is_none());
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

    /// A stack with two IP-medium interfaces: the first owns [`OUR_V4`]/24,
    /// the second 10.0.0.1/24, and both own fe80::1/64.
    fn test_stack_two_ifaces() -> (Stack<'static>, [Queue; 2], [Sent; 2]) {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let mut rxs = Vec::new();
        let mut txs = Vec::new();
        for addr in [IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V4_B.into(), 24)] {
            let rx = Rc::new(RefCell::new(VecDeque::new()));
            let tx = Rc::new(RefCell::new(Vec::new()));
            let handle = stack
                .add_iface_borrowed(
                    Box::leak(Box::new(TestDevice {
                        medium: Medium::Ip,
                        rx: rx.clone(),
                        tx: tx.clone(),
                    })),
                    HardwareAddress::Ip,
                )
                .unwrap();
            stack
                .iface(handle)
                .set_ip_addrs([addr, IpCidr::new(LINK_LOCAL_V6.into(), 64)])
                .unwrap();
            rxs.push(rx);
            txs.push(tx);
        }
        (stack, rxs.try_into().unwrap(), txs.try_into().unwrap())
    }

    const OUR_V4_B: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const REMOTE_V4_B: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
    const LINK_LOCAL_V6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const LINK_LOCAL_REMOTE_V6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    /// Replies are routed like any other egress: a packet whose sender is on-link
    /// for another interface gets its reply out of that interface, not the one it
    /// arrived on (asymmetric routing).
    #[test]
    fn test_reply_routed_out_other_iface() {
        let (mut stack, rx, tx) = test_stack_two_ifaces();
        // Unknown protocol from the second interface's subnet, arriving on the first.
        let packet = ipv4_packet(REMOTE_V4_B, OUR_V4, IpProtocol(99), b"hello");
        inject(&mut stack, &rx[0], packet.clone());

        assert!(tx[0].borrow().is_empty());
        let tx = tx[1].borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4_B);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::ProtoUnreachable.into());
        assert_eq!(quote, packet);
    }

    /// A reply to an IPv6 link-local source is link-scoped: it goes back out the
    /// arrival interface, even when another interface has a matching on-link
    /// prefix (here, both interfaces own an fe80::/64 address).
    #[test]
    fn test_reply_to_link_local_stays_on_arrival_iface() {
        let (mut stack, rx, tx) = test_stack_two_ifaces();
        let mut icmp = vec![0; 8 + 5];
        {
            let mut echo = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            echo.set_msg_type(Icmpv6Message::EchoRequest);
            echo.set_msg_code(0);
            echo.set_echo_ident(0x1234);
            echo.set_echo_seq_no(1);
            echo.payload_mut().copy_from_slice(b"hello");
            echo.fill_checksum(&LINK_LOCAL_REMOTE_V6, &LINK_LOCAL_V6);
        }
        let packet = ipv6_packet(LINK_LOCAL_REMOTE_V6, LINK_LOCAL_V6, IpProtocol::Icmpv6, &icmp);
        // Arriving on the second interface: an on-link scan would pick the first.
        inject(&mut stack, &rx[1], packet);

        assert!(tx[0].borrow().is_empty());
        let tx = tx[1].borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, _, _, payload) = parse_icmpv6_reply(&tx[0], LINK_LOCAL_V6, LINK_LOCAL_REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::EchoReply);
        assert_eq!(payload, b"hello");
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
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(7, IpListenEndpoint::UNSPECIFIED).unwrap();
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"echo?");
    }

    #[test]
    fn test_icmpv4_port_unreachable_suppressed_by_raw_socket() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // An application handling UDP through a raw socket suppresses the error.
        let handle = stack.add_raw_socket().unwrap();
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
        let handle = stack.add_udp_socket().unwrap();
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
        let raw_handle = stack.add_raw_socket().unwrap();
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
        let udp_handle = stack.add_udp_socket().unwrap();
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
        let iface = stack
            .add_iface_borrowed(
                Box::leak(Box::new(PtpDevice {
                    rx: rx.clone(),
                    sent: sent.clone(),
                    tx_stamps: Rc::new(RefCell::new(VecDeque::new())),
                })),
                HardwareAddress::Ip,
            )
            .unwrap();
        stack.iface(iface).add_ip_addr(IpCidr::new(OUR_V4.into(), 24)).unwrap();

        let handle = stack.add_udp_socket().unwrap();
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
        let handle = stack.add_udp_socket().unwrap();
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
        let handle = stack.add_udp_socket().unwrap();
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
        let handle = stack.add_udp_socket().unwrap();
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
        let handle = stack.add_udp_socket().unwrap();
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
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
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
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
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
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
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
            [
                IfaceAddr::manual(IpCidr::new(OUR_V4.into(), 24)),
                IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64))
            ]
        );
        assert!(stack.iface(iface).has_ip_addr(OUR_V4));
        assert!(!stack.iface(iface).has_ip_addr(new_addr));

        // An echo request to an address we don't have is ignored.
        let echo = ipv4_packet(REMOTE_V4, new_addr, IpProtocol::Icmp, &icmpv4_echo_request(0x1234, 1));
        inject(&mut stack, &rx, echo.clone());
        assert!(tx.borrow().is_empty());

        // A new address is appended, and ingress starts accepting it right away.
        assert_eq!(
            stack.iface(iface).add_ip_addr(IpCidr::new(new_addr.into(), 8)).unwrap(),
            None
        );
        assert!(stack.iface(iface).has_ip_addr(new_addr));
        inject(&mut stack, &rx, echo.clone());
        assert_eq!(tx.borrow().len(), 1);
        let (msg_type, ..) = parse_icmpv4_reply(&tx.borrow()[0], new_addr, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::EchoReply);

        // Re-adding an address already assigned updates its prefix in place,
        // returning the CIDR it had.
        assert_eq!(
            stack
                .iface(iface)
                .add_ip_addr(IpCidr::new(new_addr.into(), 24))
                .unwrap(),
            Some(IpCidr::new(new_addr.into(), 8))
        );
        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [
                IfaceAddr::manual(IpCidr::new(OUR_V4.into(), 24)),
                IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64)),
                IfaceAddr::manual(IpCidr::new(new_addr.into(), 24)),
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
        stack
            .iface(iface)
            .set_ip_addrs([IpCidr::new(new_addr.into(), 8)])
            .unwrap();
        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [IfaceAddr::manual(IpCidr::new(new_addr.into(), 8))]
        );
        assert!(!stack.iface(iface).has_ip_addr(OUR_V4));
    }

    #[test]
    #[should_panic]
    fn test_iface_reject_non_unicast_ip_addr() {
        let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
        stack
            .iface(IfaceHandle(0))
            .add_ip_addr(IpCidr::new(Ipv4Address::new(224, 0, 0, 1).into(), 24))
            .unwrap();
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
        let udp = stack.add_udp_socket().unwrap();
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
        stack
            .iface(iface)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)])
            .unwrap();
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
