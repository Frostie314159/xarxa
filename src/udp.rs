//! UDP sockets.
//!
//! [`Stack::add_udp_socket`](crate::Stack::add_udp_socket) creates a socket inside
//! the stack and returns a [`UdpHandle`] identifying it. All operations go through
//! [`Stack::udp`](crate::Stack::udp), which borrows the socket as a [`UdpSocket`]:
//! receiving only touches the socket state, while sending transmits the datagram
//! immediately.
//!
//! A single [`bind`](UdpSocket::bind) call pins down (parts of) the socket's
//! 4-tuple, local and remote halves at once, each part exact or wildcard. Binding
//! to port 0 allocates an ephemeral port, and binding an identical 4-tuple to
//! another socket's is rejected.
//!
//! Received packets are queued with their IP and UDP headers still in the buffer.
//! The addresses returned in [`UdpMetadata`] are parsed back out of those header
//! bytes.

use alloc::collections::VecDeque;
use core::fmt;
use core::ops::{Deref, Range};

use crate::buf::PacketBuf;
use crate::slab::Slab;
use crate::stack::{Iface, StackInner, TxContext, addr_score, alloc_ephemeral_port};
use crate::wire::{
    ETHERNET_HEADER_LEN, IPV4_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol,
    IpVersion, Ipv4Packet, Ipv6Packet, UDP_HEADER_LEN, UdpPacket,
};

/// A handle to a UDP socket added to a [`Stack`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::remove_udp_socket`]: crate::Stack::remove_udp_socket
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpHandle(pub(crate) usize);

/// Metadata for a sent or received UDP datagram.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UdpMetadata {
    /// The remote endpoint: the sender of an incoming datagram, or the destination of
    /// an outgoing one.
    pub endpoint: IpEndpoint,
    /// The local address: the destination of an incoming datagram (always set), or
    /// the source of an outgoing one. If not set on an outgoing datagram (and the
    /// socket is not bound to a single address), a suitable source address is
    /// selected automatically.
    pub local_address: Option<IpAddress>,
}

impl<T: Into<IpEndpoint>> From<T> for UdpMetadata {
    fn from(value: T) -> Self {
        Self {
            endpoint: value.into(),
            local_address: None,
        }
    }
}

impl fmt::Display for UdpMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.endpoint)
    }
}

/// Error returned by [`UdpSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    /// The socket is already bound.
    InvalidState,
    /// Another UDP socket holds an identical 4-tuple.
    InUse,
    /// No free port in the ephemeral range (only possible with tens of thousands
    /// of bound sockets).
    NoFreePorts,
    /// The local and remote addresses belong to different address families, or no
    /// local address is available for the given remote.
    Unaddressable,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::InUse => write!(f, "port in use"),
            BindError::NoFreePorts => write!(f, "no free ports"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`UdpSocket::send_slice`] and [`UdpSocket::send_with`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    /// The socket is not bound, the destination address or port is unspecified, or
    /// no matching source address is available.
    Unaddressable,
    /// The payload does not fit in a packet buffer, or no buffer is available.
    BufferFull,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`UdpSocket::recv`] and the peek methods.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    /// The RX queue is empty.
    Exhausted,
    /// The provided slice is smaller than the payload. (The packet is dropped by
    /// `recv_slice`, but not by `peek_slice`.)
    Truncated,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// UDP socket state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct UdpSocketState {
    /// The local half of the socket's 4-tuple. The address filters the packet's
    /// destination, from any address of any version to one exact address. A zero
    /// port means the socket is not bound.
    local: IpListenEndpoint,
    /// The remote half of the socket's 4-tuple. Specified parts filter ingress
    /// (only matching datagrams are delivered) and are the default destination
    /// for sends. Unspecified parts match any remote.
    remote: IpListenEndpoint,
    rx_queue: VecDeque<PacketBuf>,
    hop_limit: Option<u8>,
}

impl UdpSocketState {
    /// Create an unbound UDP socket.
    pub(crate) fn new() -> UdpSocketState {
        UdpSocketState {
            local: IpListenEndpoint::UNSPECIFIED,
            remote: IpListenEndpoint::UNSPECIFIED,
            rx_queue: VecDeque::new(),
            hop_limit: None,
        }
    }

    /// Queue an ingress datagram. `buf` must be a full IP packet (IP header
    /// included), truncated to the UDP length.
    pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
        self.rx_queue.push_back(buf);
    }

    /// Score this socket against an ingress datagram.
    ///
    /// `None` if the socket does not match (a specified tuple part differs),
    /// else how specific the match is, so that the most specific socket wins the
    /// datagram. Connected sockets outscore bound-only ones, and exact addresses
    /// outscore wildcards (see [`addr_score`]).
    ///
    /// `dst_is_bcast` relaxes the local-address filter: sockets bound to a
    /// specific address also accept broadcast/multicast traffic on their port.
    /// It never relaxes the IP version.
    fn match_score(
        &self,
        src_addr: &IpAddress,
        src_port: u16,
        dst_addr: &IpAddress,
        dst_port: u16,
        dst_is_bcast: bool,
    ) -> Option<u8> {
        // The local port is always concrete on a bound socket, and must match.
        if self.local.port != dst_port {
            return None;
        }
        let mut score = match addr_score(&self.local, dst_addr) {
            Some(score) => score,
            // Bound to one address, and this is broadcast/multicast traffic on
            // its port: it gets it anyway, as long as the version is its own.
            None if dst_is_bcast && self.local.version() == Some(dst_addr.version()) => 2,
            None => return None,
        };
        score += addr_score(&self.remote, src_addr)?;
        if self.remote.port != 0 {
            if self.remote.port != src_port {
                return None;
            }
            score += 1;
        }
        Some(score)
    }
}

/// A received UDP datagram.
///
/// Returned by [`UdpSocket::recv`]. Derefs to the UDP payload.
///
/// This is zero-copy, it contains the owned buffer the packet arrived in. Dropping it frees the buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct RecvPacket {
    buf: PacketBuf,
    meta: UdpMetadata,
    payload: Range<usize>,
}

impl RecvPacket {
    fn new(mut buf: PacketBuf) -> Self {
        let (meta, payload) = parse_datagram(&mut buf);
        Self { buf, meta, payload }
    }

    /// The datagram's metadata: remote endpoint and local address.
    pub fn meta(&self) -> UdpMetadata {
        self.meta
    }

    /// The UDP payload.
    pub fn payload(&self) -> &[u8] {
        &self.buf[self.payload.clone()]
    }
}

impl Deref for RecvPacket {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.payload()
    }
}

/// Parse the addresses and the payload location out of a queued datagram (a full IP
/// packet starting at the IP header).
///
/// The packet was validated on ingress, so this cannot fail.
fn parse_datagram(buf: &mut PacketBuf) -> (UdpMetadata, Range<usize>) {
    let (src_addr, dst_addr, header_len): (IpAddress, IpAddress, usize) =
        match IpVersion::of_packet(buf).expect("queued packet was validated on ingress") {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_unchecked(&mut buf[..]);
                (
                    packet.src_addr().into(),
                    packet.dst_addr().into(),
                    packet.header_len() as usize,
                )
            }
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_unchecked(&mut buf[..]);
                (packet.src_addr().into(), packet.dst_addr().into(), IPV6_HEADER_LEN)
            }
        };

    let udp = UdpPacket::new_unchecked(&mut buf[header_len..]);
    let meta = UdpMetadata {
        endpoint: IpEndpoint::new(src_addr, udp.src_port()),
        local_address: Some(dst_addr),
    };
    let payload = header_len + UDP_HEADER_LEN..header_len + udp.len() as usize;
    (meta, payload)
}

/// A UDP socket borrowed from a [`Stack`], returned by [`Stack::udp`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::udp`]: crate::Stack::udp
pub struct UdpSocket<'a> {
    pub(crate) sockets: &'a mut Slab<UdpSocketState>,
    pub(crate) index: usize,
    pub(crate) tx: TxContext<'a>,
}

impl UdpSocket<'_> {
    /// This socket's state in the slab.
    #[inline]
    fn inner(&self) -> &UdpSocketState {
        self.sockets.get(self.index)
    }

    /// Mutable variant of [`inner`](Self::inner).
    #[inline]
    fn inner_mut(&mut self) -> &mut UdpSocketState {
        self.sockets.get_mut(self.index)
    }

    /// Return the bound local endpoint. The address is the filter the bind
    /// scoped the socket to. A zero port means the socket is not bound.
    #[inline]
    pub fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner().local
    }

    /// Return the bound remote endpoint. Unspecified parts match any remote:
    /// a fully unspecified endpoint means an ordinary unconnected socket.
    #[inline]
    pub fn remote_endpoint(&self) -> IpListenEndpoint {
        self.inner().remote
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method.
    pub fn hop_limit(&self) -> Option<u8> {
        self.inner().hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA
    /// recommended] value (64).
    ///
    /// # Panics
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        assert!(hop_limit != Some(0));
        self.inner_mut().hop_limit = hop_limit
    }

    /// Bind the socket, fixing (parts of) its 4-tuple.
    ///
    /// Every UDP socket is identified by the (local address, local port, remote
    /// address, remote port) tuple, and binding pins parts of it down: each part
    /// of `local` and `remote` is either exact or a wildcard (absent or
    /// unspecified address / zero port):
    ///
    /// - `bind(port, ANY)`: server on all addresses of both IP versions.
    /// - `bind((Ipv4Address::UNSPECIFIED, port), ANY)`: server on all IPv4
    ///   addresses, and no IPv6 one.
    /// - `bind((addr, port), ANY)`: server on one address.
    /// - `bind(0, ANY)`: unconnected sender. A free port in the 49152..=65535
    ///   range is allocated, picked at a random starting point.
    /// - `bind((addr, 0), ANY)`: pin the source address, allocate the port.
    /// - `bind(0, remote)`: ordinary connected client. The local address is
    ///   resolved from the routing tables (a connected socket always has a
    ///   concrete local address), and an ephemeral local port is allocated.
    ///
    /// (`ANY` above is [`IpListenEndpoint::UNSPECIFIED`], the fully wildcard
    /// remote.)
    ///
    /// Specified parts of `remote` filter ingress, so only datagrams matching them
    /// are delivered, and are the default destination for sends. The remote half is
    /// not all-or-nothing: e.g. a remote with only the address specified accepts
    /// any port of that one peer.
    ///
    /// A bind is rejected only if another UDP socket holds the *identical*
    /// 4-tuple. Sharing a local port is fine as long as the tuples differ
    /// (e.g. a connected socket next to a wildcard server socket, two sockets
    /// connected to different remotes, or the two halves of a dual stack,
    /// `(Ipv4Address::UNSPECIFIED, port)` and `(Ipv6Address::UNSPECIFIED,
    /// port)`). Distinct overlapping tuples are never ambiguous, since each
    /// datagram is handed to the most specific match. Ephemeral allocation
    /// applies the same rule, so connected sockets can reuse ports held by
    /// sockets with a different remote.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is already bound (see
    /// [is_open](#method.is_open)), `Err(BindError::InUse)` on an identical
    /// bind, `Err(BindError::NoFreePorts)` if the ephemeral range is exhausted,
    /// and `Err(BindError::Unaddressable)` on an address family mismatch or if
    /// no local address is available for the given remote.
    pub fn bind(
        &mut self,
        local: impl Into<IpListenEndpoint>,
        remote: impl Into<IpListenEndpoint>,
    ) -> Result<(), BindError> {
        let mut local: IpListenEndpoint = local.into();
        let remote: IpListenEndpoint = remote.into();
        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        // Neither half may restrict the socket to a family the other excludes.
        // That includes the per-version wildcards, which restrict without naming
        // an address.
        if let (Some(local_version), Some(remote_version)) = (local.version(), remote.version())
            && local_version != remote_version
        {
            return Err(BindError::Unaddressable);
        }

        // A fully-specified remote resolves a wildcard local address via a route
        // lookup. A connected socket always has a concrete local address.
        if let Some(remote_addr) = remote.concrete_addr()
            && remote.port != 0
            && local.concrete_addr().is_none()
        {
            local.addr = Some(
                self.tx
                    .get_source_address(&remote_addr)
                    .ok_or(BindError::Unaddressable)?,
            );
        }

        // Only an *identical* 4-tuple conflicts: any difference (a wildcard vs.
        // an exact part included) is resolved by demux picking the most
        // specific match, so nothing is shadowed.
        let (sockets, index) = (&self.sockets, self.index);
        let in_use = |local: IpListenEndpoint| {
            sockets
                .iter()
                .any(|(i, s)| i != index && s.local == local && s.remote == remote)
        };

        if local.port == 0 {
            local.port = alloc_ephemeral_port(self.tx.rand(), |port| {
                in_use(IpListenEndpoint { addr: local.addr, port })
            })
            .ok_or(BindError::NoFreePorts)?;
        } else if in_use(local) {
            return Err(BindError::InUse);
        }

        let state = self.inner_mut();
        state.local = local;
        state.remote = remote;
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        let state = self.inner_mut();
        state.local = IpListenEndpoint::UNSPECIFIED;
        state.remote = IpListenEndpoint::UNSPECIFIED;
        state.rx_queue.clear();
    }

    /// Check whether the socket is open (bound to a port).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().local.port != 0
    }

    /// Check whether the RX queue is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.inner().rx_queue.is_empty()
    }

    /// Dequeue a received datagram, as an owned packet ([`RecvPacket`]).
    ///
    /// This is zero-copy: the returned value is the buffer the datagram arrived in.
    ///
    /// Returns `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn recv(&mut self) -> Result<RecvPacket, RecvError> {
        let buf = self.inner_mut().rx_queue.pop_front().ok_or(RecvError::Exhausted)?;
        Ok(RecvPacket::new(buf))
    }

    /// Dequeue a received datagram, copying the payload into the given slice, and
    /// return the number of octets copied along with its metadata.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the
    /// payload, the packet is dropped and `Err(RecvError::Truncated)` is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let packet = self.recv()?;
        let payload = packet.payload();
        if data.len() < payload.len() {
            return Err(RecvError::Truncated);
        }
        data[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), packet.meta()))
    }

    /// Peek at the next received datagram without dequeueing it, returning its
    /// payload and its metadata.
    ///
    /// Returns `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn peek(&mut self) -> Result<(&[u8], UdpMetadata), RecvError> {
        let buf = self
            .sockets
            .get_mut(self.index)
            .rx_queue
            .front_mut()
            .ok_or(RecvError::Exhausted)?;
        let (meta, payload) = parse_datagram(buf);
        Ok((&buf[payload], meta))
    }

    /// Peek at the next received datagram without dequeueing it, copying the payload
    /// into the given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the
    /// payload, no data is copied and `Err(RecvError::Truncated)` is returned. The
    /// packet stays in the queue.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let (payload, meta) = self.peek()?;
        if data.len() < payload.len() {
            return Err(RecvError::Truncated);
        }
        data[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), meta))
    }

    /// Send a datagram to the given remote endpoint, copying the payload from a slice.
    ///
    /// See [send_with](#method.send_with).
    pub fn send_slice(&mut self, data: &[u8], meta: impl Into<UdpMetadata>) -> Result<(), SendError> {
        self.send_with(data.len(), meta, |buf| {
            buf.copy_from_slice(data);
            data.len()
        })
    }

    /// Send a datagram, building the payload in place.
    ///
    /// The destination is `meta.endpoint`, with unspecified parts defaulted from
    /// the socket's bound remote endpoint. On a connected socket, sending to
    /// `IpEndpoint::UNSPECIFIED` sends to the connected remote. An explicitly
    /// specified destination is honored even on a connected socket.
    ///
    /// The closure gets a `max_size`-byte slice inside a freshly allocated packet
    /// buffer, and returns how many bytes it wrote. The datagram is then sent
    /// immediately. If the destination's neighbor is unresolved, the packet is queued
    /// inside the stack and sent when resolution completes. This still counts as a
    /// successful send.
    ///
    /// Returns `Err(SendError::Unaddressable)` if the socket is not bound, the
    /// destination address or port is still unspecified after defaulting, the
    /// destination's address family does not match the source address, or no source
    /// address is available.
    /// Returns `Err(SendError::BufferFull)` if the payload cannot fit in a packet
    /// buffer.
    pub fn send_with(
        &mut self,
        max_size: usize,
        meta: impl Into<UdpMetadata>,
        f: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SendError> {
        let mut meta = meta.into();
        let local = self.inner().local;
        let remote = self.inner().remote;
        let hop_limit = self.inner().hop_limit.unwrap_or(64);

        if local.port == 0 {
            return Err(SendError::Unaddressable);
        }

        // Default unspecified parts of the destination from the bound remote. Only a
        // concrete remote address is a destination. The per-version wildcards are
        // filters, and leave the destination unspecified.
        if meta.endpoint.addr.is_unspecified()
            && let Some(addr) = remote.concrete_addr()
        {
            meta.endpoint.addr = addr;
        }
        if meta.endpoint.port == 0 {
            meta.endpoint.port = remote.port;
        }
        if !meta.endpoint.is_specified() {
            return Err(SendError::Unaddressable);
        }
        // A bind scoped to one IP version cannot send over the other: the replies
        // would arrive on a version its own ingress filter drops.
        if local
            .version()
            .is_some_and(|version| version != meta.endpoint.addr.version())
        {
            return Err(SendError::Unaddressable);
        }

        // Pick the source address: explicit in the metadata, else the socket's bound
        // address (only a concrete one is an address, the wildcards are filters),
        // else one chosen from the destination.
        let src_addr = match meta.local_address.or(local.concrete_addr()) {
            Some(addr) => addr,
            None => self
                .tx
                .get_source_address(&meta.endpoint.addr)
                .ok_or(SendError::Unaddressable)?,
        };
        if src_addr.version() != meta.endpoint.addr.version() {
            return Err(SendError::Unaddressable);
        }

        // Build the datagram: reserve headroom for the headers below, write the
        // payload, prepend the UDP header.
        let ip_header_len = match meta.endpoint.addr {
            IpAddress::Ipv4(_) => IPV4_HEADER_LEN,
            IpAddress::Ipv6(_) => IPV6_HEADER_LEN,
        };
        let headroom = ETHERNET_HEADER_LEN + ip_header_len + UDP_HEADER_LEN;

        let mut buf = PacketBuf::new();
        if max_size > buf.capacity() - headroom {
            return Err(SendError::BufferFull);
        }
        buf.reserve(headroom);
        buf.set_len(max_size);
        let size = f(&mut buf);
        assert!(size <= max_size);
        buf.set_len(size);

        buf.push_front(UDP_HEADER_LEN);
        let udp_len = buf.len();
        {
            let mut udp = UdpPacket::new_unchecked(&mut buf);
            udp.set_src_port(local.port);
            udp.set_dst_port(meta.endpoint.port);
            udp.set_len(udp_len as u16);
            udp.fill_checksum(&src_addr, &meta.endpoint.addr);
        }

        trace!("udp:{}:{}: sending {} octets", local, meta.endpoint, size);

        self.tx
            .transmit_ip(buf, src_addr, meta.endpoint.addr, IpProtocol::Udp, hop_limit);
        Ok(())
    }
}

impl StackInner {
    /// Process an ingress UDP packet: validate it and queue it on the first matching
    /// socket.
    ///
    /// `buf` starts at the UDP header. `ip_header_len` is the length of the IP header
    /// in front of it, which is added back to the buffer before queueing, so that
    /// `recv` can parse the addresses back out of it.
    pub(crate) fn process_udp(
        &mut self,
        iface: &Iface,
        sockets: &mut Slab<UdpSocketState>,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        ip_header_len: usize,
        mut buf: PacketBuf,
    ) {
        let Ok(udp_packet) = UdpPacket::new_checked(&mut buf) else {
            trace!("udp: malformed packet");
            return;
        };
        if !udp_packet.verify_checksum(&src_addr, &dst_addr) {
            trace!("udp: checksum incorrect");
            return;
        }

        let src_port = udp_packet.src_port();
        let dst_port = udp_packet.dst_port();
        if dst_port == 0 {
            return;
        }
        let udp_len = udp_packet.len() as usize;
        let payload_len = udp_len - UDP_HEADER_LEN;

        // Strip anything past the UDP length, and add the IP header back: the queued
        // packet keeps its headers, and recv() parses the addresses back out of them.
        buf.set_len(udp_len);
        buf.push_front(ip_header_len);

        // Sockets bound to a specific address also accept broadcast/multicast traffic
        // on their port.
        let dst_is_bcast = iface.is_broadcast(&dst_addr) || dst_addr.is_multicast();

        // Linear scan, most specific match wins: every candidate whose
        // specified tuple parts all match is scored by how specific those parts
        // are. Connected sockets beat bound-only ones, exact addresses beat
        // per-version wildcards beat wildcards. Ties (only possible between
        // sockets specific in *different* parts) go to the earliest socket.
        let mut best: Option<(usize, u8)> = None;
        for (index, socket) in sockets.iter() {
            if let Some(score) = socket.match_score(&src_addr, src_port, &dst_addr, dst_port, dst_is_bcast)
                && best.is_none_or(|(_, best_score)| score > best_score)
            {
                best = Some((index, score));
            }
        }

        if let Some((index, _)) = best {
            let socket = sockets.get_mut(index);
            trace!(
                "udp:{}: receiving {} octets from {}:{}",
                socket.local, payload_len, src_addr, src_port
            );
            socket.rx_enqueue(buf);
            return;
        }

        trace!("udp: no socket bound to port {}, dropping", dst_port);
        // TODO: send an ICMP port unreachable error.
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::iface::{IfaceCapabilities, Interface, Medium};
    use crate::stack::{Config, Stack};
    use crate::wire::{EthernetAddress, IpCidr, Ipv4Address, Ipv6Address};

    fn stack_with_socket() -> (Stack, UdpHandle) {
        let mut stack = Stack::new();
        let handle = stack.add_udp_socket();
        (stack, handle)
    }

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const OTHER_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 3);
    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    /// The fully wildcard remote: an ordinary unconnected bind.
    const ANY: IpListenEndpoint = IpListenEndpoint::UNSPECIFIED;

    /// A device that swallows every frame the stack transmits.
    struct TestingDevice;

    impl Interface for TestingDevice {
        fn capabilities(&self) -> IfaceCapabilities {
            IfaceCapabilities {
                medium: Medium::Ip,
                max_transmission_unit: 1500,
            }
        }

        fn receive(&mut self) -> Option<PacketBuf> {
            None
        }

        fn transmit(&mut self, _buf: PacketBuf) -> Result<(), PacketBuf> {
            Ok(())
        }
    }

    /// A stack with one interface owning `LOCAL_ADDR`, so that binds with a
    /// specified remote can resolve their local address.
    fn stack_with_iface() -> Stack {
        let mut stack = Stack::new();
        stack.add_iface(
            Box::new(TestingDevice),
            Config {
                hardware_addr: EthernetAddress([0x02; 6]),
                ip_addrs: vec![IpCidr::new(LOCAL_ADDR.into(), 24)],
            },
        );
        stack
    }

    /// Build a queued-datagram buffer the way ingress does, as a full IPv4 + UDP packet.
    fn queued_packet_from(src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, payload: &[u8]) -> PacketBuf {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut buf = PacketBuf::new();
        buf.set_len(IPV4_HEADER_LEN + udp_len);
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + udp_len) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut buf[IPV4_HEADER_LEN..]);
            udp.set_src_port(src_port);
            udp.set_dst_port(LOCAL_PORT);
            udp.set_len(udp_len as u16);
            udp.payload_mut().copy_from_slice(payload);
            udp.fill_checksum(&src_addr.into(), &dst_addr.into());
        }
        buf
    }

    fn queued_packet(payload: &[u8]) -> PacketBuf {
        queued_packet_from(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, payload)
    }

    /// Run a packet through the stack's UDP ingress demux.
    fn deliver(stack: &mut Stack, src_addr: Ipv4Address, src_port: u16, payload: &[u8]) {
        deliver_to(stack, src_addr, src_port, LOCAL_ADDR, payload)
    }

    /// Like [`deliver`], with an explicit destination address.
    fn deliver_to(stack: &mut Stack, src_addr: Ipv4Address, src_port: u16, dst_addr: Ipv4Address, payload: &[u8]) {
        let mut buf = queued_packet_from(src_addr, src_port, dst_addr, payload);
        buf.pull_front(IPV4_HEADER_LEN);
        stack.inner.process_udp(
            stack.ifaces.get(0),
            &mut stack.sockets.udp,
            src_addr.into(),
            dst_addr.into(),
            IPV4_HEADER_LEN,
            buf,
        );
    }

    #[test]
    fn test_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        assert!(!socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT, ANY), Ok(()));
        assert!(socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT, ANY), Err(BindError::InvalidState));

        socket.close();
        assert!(!socket.is_open());
        assert_eq!(socket.bind((LOCAL_ADDR, LOCAL_PORT), ANY), Ok(()));
        assert_eq!(
            socket.local_endpoint(),
            IpListenEndpoint {
                addr: Some(LOCAL_ADDR.into()),
                port: LOCAL_PORT
            }
        );
        assert_eq!(socket.remote_endpoint(), IpListenEndpoint::UNSPECIFIED);
    }

    #[test]
    fn test_bind_ephemeral() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();

        stack.udp(h1).bind(0, ANY).unwrap();
        let p1 = stack.udp(h1).local_endpoint().port;
        assert!(p1 >= EPHEMERAL_PORT_MIN);

        // The second allocation must avoid the first socket's port.
        stack.udp(h2).bind(0, ANY).unwrap();
        let p2 = stack.udp(h2).local_endpoint().port;
        assert!(p2 >= EPHEMERAL_PORT_MIN);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_bind_conflicts() {
        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();

        // Identical 4-tuples conflict.
        stack.udp(h1).bind(LOCAL_PORT, ANY).unwrap();
        assert_eq!(stack.udp(h2).bind(LOCAL_PORT, ANY), Err(BindError::InUse));
        // A specific address next to an address-less bind on the same port is
        // fine: the tuples differ, and demux picks the most specific match.
        stack.udp(h2).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        // Two different specific addresses may share a port.
        let h3 = stack.add_udp_socket();
        let h4 = stack.add_udp_socket();
        let h5 = stack.add_udp_socket();
        stack.udp(h3).bind((LOCAL_ADDR, LOCAL_PORT + 2), ANY).unwrap();
        stack.udp(h4).bind((OTHER_ADDR, LOCAL_PORT + 2), ANY).unwrap();
        // ...but the same specific address may not.
        assert_eq!(
            stack.udp(h5).bind((LOCAL_ADDR, LOCAL_PORT + 2), ANY),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_bind_conflicts_connected() {
        let mut stack = stack_with_iface();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();
        let h3 = stack.add_udp_socket();
        let h4 = stack.add_udp_socket();

        // A connected socket and a wildcard-remote socket share a local port:
        // the 4-tuples differ.
        stack.udp(h1).bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT)).unwrap();
        stack.udp(h2).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        // So do two sockets connected to different remotes.
        stack.udp(h3).bind(LOCAL_PORT, (OTHER_ADDR, REMOTE_PORT)).unwrap();

        // The identical local + remote is rejected. (h1's local address was
        // resolved to LOCAL_ADDR, so this bind duplicates its whole tuple.)
        assert_eq!(
            stack.udp(h4).bind((LOCAL_ADDR, LOCAL_PORT), (REMOTE_ADDR, REMOTE_PORT)),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_bind_conflicts_per_version() {
        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();
        let h3 = stack.add_udp_socket();

        // The two halves of a dual stack are different tuples, so they may
        // share a port, as may the address-less bind that covers both.
        stack.udp(h1).bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY).unwrap();
        stack.udp(h2).bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY).unwrap();
        stack.udp(h3).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp(h3).close();

        // Identity does distinguish the versions: only the same half conflicts.
        assert_eq!(
            stack.udp(h3).bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_send_per_version_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY).unwrap();

        // The bind scopes the socket to IPv6, so an IPv4 destination contradicts it.
        assert_eq!(
            socket.send_slice(b"hi", (REMOTE_ADDR, REMOTE_PORT)),
            Err(SendError::Unaddressable)
        );
    }

    #[test]
    fn test_demux_per_version() {
        // A bind to any IPv6 address takes no IPv4 traffic, not even on the port
        // it holds.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        stack
            .udp(handle)
            .bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"no");
        assert!(!stack.udp(handle).can_recv());

        // The IPv4 half of the same port does take it.
        let handle = stack.add_udp_socket();
        stack
            .udp(handle)
            .bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"yes");
        assert_eq!(&*stack.udp(handle).recv().unwrap(), b"yes");
    }

    #[test]
    fn test_bind_connected() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        let mut socket = stack.udp(handle);

        // Local fully wildcard + exact remote: the ordinary connected client.
        // The local address is resolved from the routing tables, and an
        // ephemeral port is allocated.
        socket.bind(0, (REMOTE_ADDR, REMOTE_PORT)).unwrap();
        let local = socket.local_endpoint();
        assert_eq!(local.addr, Some(LOCAL_ADDR.into()));
        assert!(local.port >= EPHEMERAL_PORT_MIN);
        assert_eq!(
            socket.remote_endpoint(),
            IpListenEndpoint {
                addr: Some(REMOTE_ADDR.into()),
                port: REMOTE_PORT
            }
        );
    }

    #[test]
    fn test_bind_connected_unaddressable() {
        // Without any interface there is no local address for the remote.
        let (mut stack, handle) = stack_with_socket();
        assert_eq!(
            stack.udp(handle).bind(0, (REMOTE_ADDR, REMOTE_PORT)),
            Err(BindError::Unaddressable)
        );

        // Mismatched local/remote address families.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        assert_eq!(
            stack.udp(handle).bind(
                (LOCAL_ADDR, LOCAL_PORT),
                (crate::wire::Ipv6Address::LOCALHOST, REMOTE_PORT)
            ),
            Err(BindError::Unaddressable)
        );
    }

    #[test]
    fn test_connected_demux_filter() {
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        stack.udp(handle).bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT)).unwrap();

        // Matching the connected remote: delivered.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"yes");
        assert_eq!(&*stack.udp(handle).recv().unwrap(), b"yes");

        // Wrong source address or port: filtered out.
        deliver(&mut stack, OTHER_ADDR, REMOTE_PORT, b"no");
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"no");
        assert!(!stack.udp(handle).can_recv());
    }

    #[test]
    fn test_remote_addr_only_filter() {
        // A partially specified remote: any port of one peer.
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        stack.udp(handle).bind(LOCAL_PORT, (REMOTE_ADDR, 0)).unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"a");
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"b");
        deliver(&mut stack, OTHER_ADDR, REMOTE_PORT, b"no");
        assert_eq!(&*stack.udp(handle).recv().unwrap(), b"a");
        assert_eq!(&*stack.udp(handle).recv().unwrap(), b"b");
        assert!(!stack.udp(handle).can_recv());
    }

    #[test]
    fn test_demux_priority() {
        // When several sockets match a datagram, the most specific one wins,
        // regardless of creation order: connected beats bound-to-address beats
        // wildcard.
        let mut stack = stack_with_iface();
        let h_any = stack.add_udp_socket();
        let h_addr = stack.add_udp_socket();
        let h_conn = stack.add_udp_socket();
        stack.udp(h_any).bind(LOCAL_PORT, ANY).unwrap();
        stack.udp(h_addr).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();
        stack
            .udp(h_conn)
            .bind((LOCAL_ADDR, LOCAL_PORT), (REMOTE_ADDR, REMOTE_PORT))
            .unwrap();

        // From the connected remote: the connected socket wins.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"conn");
        // From another port of the same peer: the address-bound socket.
        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT + 1, b"addr");
        // To another local address: only the wildcard socket matches.
        deliver_to(&mut stack, REMOTE_ADDR, REMOTE_PORT, OTHER_ADDR, b"any");

        assert_eq!(&*stack.udp(h_conn).recv().unwrap(), b"conn");
        assert!(!stack.udp(h_conn).can_recv());
        assert_eq!(&*stack.udp(h_addr).recv().unwrap(), b"addr");
        assert!(!stack.udp(h_addr).can_recv());
        assert_eq!(&*stack.udp(h_any).recv().unwrap(), b"any");
        assert!(!stack.udp(h_any).can_recv());
    }

    #[test]
    fn test_demux_priority_per_version() {
        // The per-version wildcard sits between the address-less bind and an
        // exact address: it takes its version's traffic away from the
        // dual-stack socket, and gives it up to the exact address in turn.
        let mut stack = stack_with_iface();
        let h_any = stack.add_udp_socket();
        let h_v4 = stack.add_udp_socket();
        let h_addr = stack.add_udp_socket();
        stack.udp(h_any).bind(LOCAL_PORT, ANY).unwrap();
        stack
            .udp(h_v4)
            .bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT), ANY)
            .unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"v4");
        assert_eq!(&*stack.udp(h_v4).recv().unwrap(), b"v4");
        assert!(!stack.udp(h_any).can_recv());

        stack.udp(h_addr).bind((LOCAL_ADDR, LOCAL_PORT), ANY).unwrap();

        deliver(&mut stack, REMOTE_ADDR, REMOTE_PORT, b"addr");
        assert_eq!(&*stack.udp(h_addr).recv().unwrap(), b"addr");
        assert!(!stack.udp(h_v4).can_recv());
        assert!(!stack.udp(h_any).can_recv());
    }

    #[test]
    fn test_send_defaults_to_remote() {
        let mut stack = stack_with_iface();
        let handle = stack.add_udp_socket();
        let mut socket = stack.udp(handle);

        // Unconnected socket: a wildcard destination is unaddressable.
        socket.bind(LOCAL_PORT, ANY).unwrap();
        assert_eq!(
            socket.send_slice(b"hi", IpEndpoint::UNSPECIFIED),
            Err(SendError::Unaddressable)
        );
        socket.close();

        // Connected socket: the destination defaults to the bound remote, and
        // an explicit destination overrides it.
        socket.bind(LOCAL_PORT, (REMOTE_ADDR, REMOTE_PORT)).unwrap();
        assert_eq!(socket.send_slice(b"hi", IpEndpoint::UNSPECIFIED), Ok(()));
        assert_eq!(socket.send_slice(b"hi", IpEndpoint::new(OTHER_ADDR.into(), 9)), Ok(()));
    }

    #[test]
    fn test_recv() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();

        assert!(!socket.can_recv());
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));

        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));
        assert!(socket.can_recv());

        let packet = socket.recv().unwrap();
        assert_eq!(packet.payload(), b"abcdef");
        assert_eq!(&*packet, b"abcdef");
        assert_eq!(
            packet.meta(),
            UdpMetadata {
                endpoint: IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT),
                local_address: Some(LOCAL_ADDR.into()),
            }
        );
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_peek_and_recv_slice() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();
        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));

        let (payload, meta) = socket.peek().unwrap();
        assert_eq!(payload, b"abcdef");
        assert_eq!(meta.endpoint.port, REMOTE_PORT);

        // Peeking does not dequeue.
        let mut slice = [0; 16];
        assert_eq!(socket.peek_slice(&mut slice).unwrap().0, 6);
        assert_eq!(&slice[..6], b"abcdef");

        let (len, meta) = socket.recv_slice(&mut slice).unwrap();
        assert_eq!(&slice[..len], b"abcdef");
        assert_eq!(meta.endpoint, IpEndpoint::new(REMOTE_ADDR.into(), REMOTE_PORT));
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Exhausted));
    }

    #[test]
    fn test_recv_slice_truncated() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind(LOCAL_PORT, ANY).unwrap();
        socket.inner_mut().rx_enqueue(queued_packet(b"abcdef"));

        let mut slice = [0; 4];
        // peek_slice keeps the packet...
        assert_eq!(socket.peek_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(socket.can_recv());
        // ...recv_slice drops it.
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(!socket.can_recv());
    }
}
