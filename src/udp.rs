//! UDP sockets.
//!
//! [`Stack::add_udp_socket`](crate::Stack::add_udp_socket) creates a socket inside
//! the stack and returns a [`UdpHandle`] identifying it. All operations go through
//! [`Stack::udp`](crate::Stack::udp), which borrows the socket as a [`UdpSocket`]:
//! receiving only touches the socket state, while sending transmits the datagram
//! immediately.
//!
//! Binding to port 0 allocates an ephemeral port, and binds that would shadow
//! another socket are rejected.
//!
//! Received packets are queued with their IP and UDP headers still in the buffer.
//! The addresses returned in [`UdpMetadata`] are parsed back out of those header
//! bytes.

use core::fmt;
use core::ops::{Deref, Range};
use std::collections::VecDeque;

use crate::buf::PacketBuf;
use crate::slab::Slab;
use crate::stack::{Iface, StackInner, TxContext, alloc_ephemeral_port};
use crate::wire::{
    ETHERNET_HEADER_LEN, IPV4_HEADER_LEN, IPV6_HEADER_LEN, IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol,
    IpVersion, Ipv4Packet, Ipv6Packet, UDP_HEADER_LEN, UdpPacket,
};

/// A handle to a UDP socket added to a [`Stack`].
///
/// [`Stack`]: crate::Stack
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpHandle(pub(crate) usize);

/// Metadata for a sent or received UDP datagram.
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    /// The socket is already bound.
    InvalidState,
    /// Another UDP socket's binding overlaps this one: same port, and address
    /// filters that can both match one address.
    InUse,
    /// No free port in the ephemeral range (only possible with tens of thousands
    /// of bound sockets).
    NoFreePorts,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::InUse => write!(f, "port in use"),
            BindError::NoFreePorts => write!(f, "no free ports"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`UdpSocket::send_slice`] and [`UdpSocket::send_with`].
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
    endpoint: IpListenEndpoint,
    rx_queue: VecDeque<PacketBuf>,
    hop_limit: Option<u8>,
}

impl UdpSocketState {
    /// Create an unbound UDP socket.
    pub(crate) fn new() -> UdpSocketState {
        UdpSocketState {
            endpoint: IpListenEndpoint::default(),
            rx_queue: VecDeque::new(),
            hop_limit: None,
        }
    }

    /// Queue an ingress datagram. `buf` must be a full IP packet (IP header
    /// included), truncated to the UDP length.
    pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
        self.rx_queue.push_back(buf);
    }
}

/// A received UDP datagram.
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

/// Whether two bind address filters can both match one address, i.e. whether binding
/// both would leave ingress demux with two equally good candidates.
///
/// The per-version wildcards are what make this more than an equality test: a bind to
/// any IPv4 address overlaps every IPv4 bind and no IPv6 one.
fn addrs_overlap(a: IpListenEndpoint, b: IpListenEndpoint) -> bool {
    match (a.addr, b.addr) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) if a.is_unspecified() || b.is_unspecified() => a.version() == b.version(),
        (Some(a), Some(b)) => a == b,
    }
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

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpListenEndpoint {
        self.inner().endpoint
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

    /// Bind the socket to the given endpoint.
    ///
    /// The endpoint's address scopes the bind. Absent, it matches any address of
    /// either IP version. Unspecified (`0.0.0.0` / `::`), any address of that
    /// version alone. Concrete, that address alone.
    ///
    /// A port of zero means "allocate an ephemeral port": a free port in the
    /// 49152..=65535 range, picked at a random starting point. An explicit port
    /// that overlaps another UDP socket's binding (same port, and address filters
    /// that can both match one address) is rejected, since each datagram is handed
    /// to a single socket and the binds would shadow each other. Binds that cannot
    /// overlap are allowed, so the two halves of a dual stack,
    /// `(Ipv4Address::UNSPECIFIED, port)` and `(Ipv6Address::UNSPECIFIED, port)`,
    /// can be served by two sockets.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is already bound (see
    /// [is_open](#method.is_open)), `Err(BindError::InUse)` on an overlapping
    /// bind, and `Err(BindError::NoFreePorts)` if the ephemeral range is
    /// exhausted.
    pub fn bind<T: Into<IpListenEndpoint>>(&mut self, endpoint: T) -> Result<(), BindError> {
        let mut endpoint = endpoint.into();
        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        if endpoint.port == 0 {
            // Skip every port any other UDP socket has bound, regardless of
            // address.
            let (sockets, index) = (&self.sockets, self.index);
            endpoint.port = alloc_ephemeral_port(self.tx.rand(), |port| {
                sockets.iter().any(|(i, s)| i != index && s.endpoint.port == port)
            })
            .ok_or(BindError::NoFreePorts)?;
        } else if self
            .sockets
            .iter()
            .any(|(i, s)| i != self.index && s.endpoint.port == endpoint.port && addrs_overlap(s.endpoint, endpoint))
        {
            return Err(BindError::InUse);
        }

        self.inner_mut().endpoint = endpoint;
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        let state = self.inner_mut();
        state.endpoint = IpListenEndpoint::default();
        state.rx_queue.clear();
    }

    /// Check whether the socket is open (bound to a port).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().endpoint.port != 0
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

    /// Send a datagram to the given remote endpoint, building the payload in place.
    ///
    /// The closure gets a `max_size`-byte slice inside a freshly allocated packet
    /// buffer, and returns how many bytes it wrote. The datagram is then sent
    /// immediately. If the destination's neighbor is unresolved, the packet is queued
    /// inside the stack and sent when resolution completes. This still counts as a
    /// successful send.
    ///
    /// Returns `Err(SendError::Unaddressable)` if the socket is not bound, the
    /// destination address or port is zero, the destination's address family does not
    /// match the source address, or no source address is available.
    /// Returns `Err(SendError::BufferFull)` if the payload cannot fit in a packet
    /// buffer.
    pub fn send_with(
        &mut self,
        max_size: usize,
        meta: impl Into<UdpMetadata>,
        f: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SendError> {
        let meta = meta.into();
        let endpoint = self.inner().endpoint;
        let hop_limit = self.inner().hop_limit.unwrap_or(64);

        if endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() || meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        // A bind scoped to one IP version cannot send over the other: the replies
        // would arrive on a version its own ingress filter drops.
        if endpoint
            .version()
            .is_some_and(|version| version != meta.endpoint.addr.version())
        {
            return Err(SendError::Unaddressable);
        }

        // Pick the source address: explicit in the metadata, else the socket's bound
        // address (only a concrete one is an address, the wildcards are filters),
        // else one chosen from the destination.
        let src_addr = match meta.local_address.or(endpoint.concrete_addr()) {
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
            udp.set_src_port(endpoint.port);
            udp.set_dst_port(meta.endpoint.port);
            udp.set_len(udp_len as u16);
            udp.fill_checksum(&src_addr, &meta.endpoint.addr);
        }

        net_trace!("udp:{}:{}: sending {} octets", endpoint, meta.endpoint, size);

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
            net_trace!("udp: malformed packet");
            return;
        };
        if !udp_packet.verify_checksum(&src_addr, &dst_addr) {
            net_trace!("udp: checksum incorrect");
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

        for (_, socket) in sockets.iter_mut() {
            if socket.endpoint.port != dst_port {
                continue;
            }
            // The broadcast relaxation applies to the address, never to the IP
            // version: a socket bound to any IPv4 address is not an IPv6 socket.
            match socket.endpoint.addr {
                None => {}
                Some(addr) if addr.is_unspecified() => {
                    if addr.version() != dst_addr.version() {
                        continue;
                    }
                }
                Some(addr) => {
                    if addr != dst_addr && !dst_is_bcast {
                        continue;
                    }
                }
            }

            net_trace!(
                "udp:{}: receiving {} octets from {}:{}",
                socket.endpoint,
                payload_len,
                src_addr,
                src_port
            );
            socket.rx_enqueue(buf);
            return;
        }

        net_trace!("udp: no socket bound to port {}, dropping", dst_port);
        // TODO: send an ICMP port unreachable error.
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::stack::Stack;
    use crate::wire::{Ipv4Address, Ipv6Address};

    fn stack_with_socket() -> (Stack, UdpHandle) {
        let mut stack = Stack::new();
        let handle = stack.add_udp_socket();
        (stack, handle)
    }

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    /// Build a queued-datagram buffer the way ingress does, as a full IPv4 + UDP packet.
    fn queued_packet(payload: &[u8]) -> PacketBuf {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut buf = PacketBuf::new();
        buf.set_len(IPV4_HEADER_LEN + udp_len);
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + udp_len) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(REMOTE_ADDR);
            ip.set_dst_addr(LOCAL_ADDR);
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut buf[IPV4_HEADER_LEN..]);
            udp.set_src_port(REMOTE_PORT);
            udp.set_dst_port(LOCAL_PORT);
            udp.set_len(udp_len as u16);
            udp.payload_mut().copy_from_slice(payload);
            udp.fill_checksum(&REMOTE_ADDR.into(), &LOCAL_ADDR.into());
        }
        buf
    }

    #[test]
    fn test_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        assert!(!socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert!(socket.is_open());
        assert_eq!(socket.bind(LOCAL_PORT), Err(BindError::InvalidState));

        socket.close();
        assert!(!socket.is_open());
        assert_eq!(socket.bind((LOCAL_ADDR, LOCAL_PORT)), Ok(()));
        assert_eq!(
            socket.endpoint(),
            IpListenEndpoint {
                addr: Some(LOCAL_ADDR.into()),
                port: LOCAL_PORT
            }
        );
    }

    #[test]
    fn test_bind_ephemeral() {
        use crate::stack::EPHEMERAL_PORT_MIN;

        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();

        stack.udp(h1).bind(0).unwrap();
        let p1 = stack.udp(h1).endpoint().port;
        assert!(p1 >= EPHEMERAL_PORT_MIN);

        // The second allocation must avoid the first socket's port.
        stack.udp(h2).bind(0).unwrap();
        let p2 = stack.udp(h2).endpoint().port;
        assert!(p2 >= EPHEMERAL_PORT_MIN);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_bind_conflicts() {
        const OTHER_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 3);

        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();

        // Address-less binds conflict on the port alone.
        stack.udp(h1).bind(LOCAL_PORT).unwrap();
        assert_eq!(stack.udp(h2).bind(LOCAL_PORT), Err(BindError::InUse));
        // A specific address conflicts with an address-less bind on the same port.
        assert_eq!(stack.udp(h2).bind((LOCAL_ADDR, LOCAL_PORT)), Err(BindError::InUse));
        // A different port is fine.
        stack.udp(h2).bind(LOCAL_PORT + 1).unwrap();

        // Two different specific addresses may share a port.
        let h3 = stack.add_udp_socket();
        let h4 = stack.add_udp_socket();
        let h5 = stack.add_udp_socket();
        stack.udp(h3).bind((LOCAL_ADDR, LOCAL_PORT + 2)).unwrap();
        stack.udp(h4).bind((OTHER_ADDR, LOCAL_PORT + 2)).unwrap();
        // ...but the same specific address may not.
        assert_eq!(stack.udp(h5).bind((LOCAL_ADDR, LOCAL_PORT + 2)), Err(BindError::InUse));
    }

    #[test]
    fn test_bind_conflicts_per_version() {
        let mut stack = Stack::new();
        let h1 = stack.add_udp_socket();
        let h2 = stack.add_udp_socket();
        let h3 = stack.add_udp_socket();
        let h4 = stack.add_udp_socket();

        // The two halves of a dual stack can never match the same datagram, so
        // they may share a port.
        stack.udp(h1).bind((Ipv4Address::UNSPECIFIED, LOCAL_PORT)).unwrap();
        stack.udp(h2).bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT)).unwrap();

        // A concrete address does overlap the wildcard of its own version...
        assert_eq!(stack.udp(h3).bind((LOCAL_ADDR, LOCAL_PORT)), Err(BindError::InUse));
        // ...and so does the address-less bind, which matches both versions.
        assert_eq!(stack.udp(h3).bind(LOCAL_PORT), Err(BindError::InUse));

        // A different port is fine, and then the address-less bind takes both
        // versions away from anything that would follow it.
        stack.udp(h3).bind(LOCAL_PORT + 1).unwrap();
        assert_eq!(
            stack.udp(h4).bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT + 1)),
            Err(BindError::InUse)
        );
    }

    #[test]
    fn test_send_per_version_bind() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind((Ipv6Address::UNSPECIFIED, LOCAL_PORT)).unwrap();

        // The bind scopes the socket to IPv6, so an IPv4 destination contradicts it.
        assert_eq!(
            socket.send_slice(b"hi", (REMOTE_ADDR, REMOTE_PORT)),
            Err(SendError::Unaddressable)
        );
    }

    #[test]
    fn test_recv() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind(LOCAL_PORT).unwrap();

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
        socket.bind(LOCAL_PORT).unwrap();
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
        socket.bind(LOCAL_PORT).unwrap();
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
