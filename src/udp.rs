//! UDP sockets.

use core::fmt;
use core::ops::{Deref, Range};
use std::collections::VecDeque;

use crate::buf::PacketBuf;
use crate::slab::Slab;
use crate::stack::{Iface, StackInner};
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
    /// The port is zero.
    Unaddressable,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
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

/// A UDP socket borrowed from a [`Stack`], returned by [`Stack::udp`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::udp`]: crate::Stack::udp
pub struct UdpSocket<'a> {
    pub(crate) state: &'a mut UdpSocketState,
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<Iface>,
}

impl UdpSocket<'_> {
    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpListenEndpoint {
        self.state.endpoint
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method.
    pub fn hop_limit(&self) -> Option<u8> {
        self.state.hop_limit
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
        self.state.hop_limit = hop_limit
    }

    /// Bind the socket to the given endpoint.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is already bound (see
    /// [is_open](#method.is_open)), and `Err(BindError::Unaddressable)` if the port
    /// in the given endpoint is zero.
    pub fn bind<T: Into<IpListenEndpoint>>(&mut self, endpoint: T) -> Result<(), BindError> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 {
            return Err(BindError::Unaddressable);
        }
        if self.is_open() {
            return Err(BindError::InvalidState);
        }
        self.state.endpoint = endpoint;
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        self.state.endpoint = IpListenEndpoint::default();
        self.state.rx_queue.clear();
    }

    /// Check whether the socket is open (bound to a port).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.state.endpoint.port != 0
    }

    /// Check whether the RX queue is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.state.rx_queue.is_empty()
    }

    /// Dequeue a received datagram, as an owned packet ([`RecvPacket`]).
    ///
    /// This is zero-copy: the returned value is the buffer the datagram arrived in.
    ///
    /// Returns `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn recv(&mut self) -> Result<RecvPacket, RecvError> {
        let buf = self.state.rx_queue.pop_front().ok_or(RecvError::Exhausted)?;
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
        let buf = self.state.rx_queue.front_mut().ok_or(RecvError::Exhausted)?;
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
        let endpoint = self.state.endpoint;
        let hop_limit = self.state.hop_limit.unwrap_or(64);

        if endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() || meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        // Pick the source address: explicit in the metadata, else the socket's bound
        // address, else one chosen from the destination.
        let src_addr = match meta.local_address.or(endpoint.addr) {
            Some(addr) => addr,
            None => self
                .inner
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

        // Hand it down the IP layer, out the first interface.
        // TODO: route to the right interface.
        let Some((_, iface)) = self.ifaces.iter_mut().next() else {
            net_debug!("udp: no interface, dropping packet");
            return Ok(());
        };
        match (src_addr, meta.endpoint.addr) {
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                self.inner
                    .transmit_ipv4(iface, buf, src, dst, IpProtocol::Udp, hop_limit)
            }
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                self.inner
                    .transmit_ipv6(iface, buf, src, dst, IpProtocol::Udp, hop_limit)
            }
            // Family mismatch is rejected above.
            _ => unreachable!(),
        }
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
        let dst_is_bcast = self.is_broadcast(&dst_addr) || dst_addr.is_multicast();

        for (_, socket) in sockets.iter_mut() {
            if socket.endpoint.port != dst_port {
                continue;
            }
            if let Some(addr) = socket.endpoint.addr
                && addr != dst_addr
                && !dst_is_bcast
            {
                continue;
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
    use crate::stack::{Config, Stack};
    use crate::wire::{EthernetAddress, Ipv4Address};

    fn stack_with_socket() -> (Stack, UdpHandle) {
        let mut stack = Stack::new(Config {
            hardware_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ip_addrs: vec![],
        });
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
        assert_eq!(socket.bind(0), Err(BindError::Unaddressable));
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
    fn test_recv() {
        let (mut stack, handle) = stack_with_socket();
        let mut socket = stack.udp(handle);
        socket.bind(LOCAL_PORT).unwrap();

        assert!(!socket.can_recv());
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));

        socket.state.rx_enqueue(queued_packet(b"abcdef"));
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
        socket.state.rx_enqueue(queued_packet(b"abcdef"));

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
        socket.state.rx_enqueue(queued_packet(b"abcdef"));

        let mut slice = [0; 4];
        // peek_slice keeps the packet...
        assert_eq!(socket.peek_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(socket.can_recv());
        // ...recv_slice drops it.
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(!socket.can_recv());
    }
}
