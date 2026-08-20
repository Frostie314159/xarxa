//! DNS client.
//!
//! [`DnsClient`] resolves host names to IP addresses using a UDP socket it
//! creates inside the [`Stack`]. Requires the `dns` feature.
//!
//! Usage:
//! - Create it with [`DnsClient::new`], giving it the DNS servers to use.
//! - Start a query with [`DnsClient::start_query`].
//! - Call [`DnsClient::poll`] after every [`Stack::poll`], and again when the
//!   deadline it returns arrives.
//! - Read the result with [`DnsClient::get_query_result`].

use core::cmp::min;
#[cfg(feature = "async")]
use core::task::Waker;

use alloc::vec::Vec as AllocVec;
use heapless::Vec;

use crate::stack::Stack;
use crate::time::{Duration, Instant};
use crate::udp::{RecvError, SendError, UdpHandle};
use crate::wire::dns::{Flags, HEADER_LEN, Opcode, Packet, Question, Rcode, Record, RecordData, Type};
use crate::wire::{self, IpAddress, IpEndpoint, IpListenEndpoint};

#[cfg(feature = "async")]
use crate::waker::WakerRegistration;

/// Maximum length of a name, in wire format.
pub const DNS_MAX_NAME_SIZE: usize = 255;
/// Maximum number of addresses returned by one query.
pub const DNS_MAX_RESULT_COUNT: usize = 4;
/// Maximum number of DNS servers.
pub const DNS_MAX_SERVER_COUNT: usize = 4;

const DNS_PORT: u16 = 53;
const MDNS_DNS_PORT: u16 = 5353;
const RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(10_000);
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(10_000); // Should generally be 2-10 secs

#[cfg(all(feature = "mdns", feature = "ipv6"))]
const MDNS_IPV6_ADDR: IpAddress = IpAddress::Ipv6(crate::wire::Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));

#[cfg(all(feature = "mdns", feature = "ipv4"))]
const MDNS_IPV4_ADDR: IpAddress = IpAddress::Ipv4(crate::wire::Ipv4Address::new(224, 0, 0, 251));

/// Error returned by [`DnsClient::start_query`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartQueryError {
    /// The name is empty, or has an empty or too long label.
    InvalidName,
    /// The name is longer than [`DNS_MAX_NAME_SIZE`] in wire format.
    NameTooLong,
}

impl core::fmt::Display for StartQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartQueryError::InvalidName => write!(f, "Invalid name"),
            StartQueryError::NameTooLong => write!(f, "Name too long"),
        }
    }
}

impl core::error::Error for StartQueryError {}

/// Error returned by [`DnsClient::get_query_result`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GetQueryResultError {
    /// Query is not done yet.
    Pending,
    /// Query failed.
    Failed,
}

impl core::fmt::Display for GetQueryResultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GetQueryResultError::Pending => write!(f, "Query is not done yet"),
            GetQueryResultError::Failed => write!(f, "Query failed"),
        }
    }
}

impl core::error::Error for GetQueryResultError {}

/// State for an in-progress DNS query.
#[derive(Debug)]
struct DnsQuery {
    state: State,

    #[cfg(feature = "async")]
    waker: WakerRegistration,
}

impl DnsQuery {
    fn set_state(&mut self, state: State) {
        self.state = state;
        #[cfg(feature = "async")]
        self.waker.wake();
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum State {
    Pending(PendingQuery),
    Completed(CompletedQuery),
    Failure,
}

#[derive(Debug)]
struct PendingQuery {
    name: Vec<u8, DNS_MAX_NAME_SIZE>,
    type_: Type,

    txid: u16, // transaction ID

    timeout_at: Option<Instant>,
    retransmit_at: Instant,
    delay: Duration,

    server_idx: usize,
    mdns: MulticastDns,
}

/// Whether a query is sent with multicast DNS.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MulticastDns {
    /// Send the query to the configured DNS servers.
    Disabled,
    /// Send the query to the mDNS multicast address. Requires the `mdns` feature.
    #[cfg(feature = "mdns")]
    Enabled,
}

#[derive(Debug)]
struct CompletedQuery {
    addresses: Vec<IpAddress, DNS_MAX_RESULT_COUNT>,
}

/// A handle to an in-progress DNS query.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DnsQueryHandle(usize);

/// A DNS client.
///
/// Owns a UDP socket inside the [`Stack`], bound to an ephemeral port.
/// Remove it with [`remove`](Self::remove) to free the socket.
#[derive(Debug)]
pub struct DnsClient {
    socket: UdpHandle,
    servers: Vec<IpAddress, DNS_MAX_SERVER_COUNT>,
    queries: AllocVec<Option<DnsQuery>>,
}

impl DnsClient {
    /// Create a DNS client.
    ///
    /// Creates and binds a UDP socket in `stack`.
    /// Truncates the server list if `servers.len() > DNS_MAX_SERVER_COUNT`.
    pub fn new(stack: &mut Stack, servers: &[IpAddress]) -> DnsClient {
        let truncated_servers = &servers[..min(servers.len(), DNS_MAX_SERVER_COUNT)];

        let socket = stack.add_udp_socket();
        // A fresh socket on an ephemeral port: can only fail if the whole
        // ephemeral range is taken.
        unwrap!(stack.udp_socket(socket).bind(0, IpListenEndpoint::UNSPECIFIED));

        DnsClient {
            socket,
            servers: Vec::from_slice(truncated_servers).unwrap(),
            queries: AllocVec::new(),
        }
    }

    /// Destroy the client, removing its UDP socket from `stack`.
    ///
    /// Pending queries are cancelled.
    pub fn remove(self, stack: &mut Stack) {
        stack.remove_udp_socket(self.socket);
    }

    /// The UDP socket the client sends and receives on.
    ///
    /// Use it to set the hop limit. Don't bind, close or read from it.
    pub fn socket(&self) -> UdpHandle {
        self.socket
    }

    /// Update the list of DNS servers, will replace all existing servers
    ///
    /// Truncates the server list if `servers.len() > DNS_MAX_SERVER_COUNT`.
    pub fn update_servers(&mut self, servers: &[IpAddress]) {
        if servers.len() > DNS_MAX_SERVER_COUNT {
            trace!("Max DNS Servers exceeded. Increase DNS_MAX_SERVER_COUNT");
            self.servers = Vec::from_slice(&servers[..DNS_MAX_SERVER_COUNT]).unwrap();
        } else {
            self.servers = Vec::from_slice(servers).unwrap();
        }
    }

    fn find_free_query(&mut self) -> DnsQueryHandle {
        for (i, q) in self.queries.iter().enumerate() {
            if q.is_none() {
                return DnsQueryHandle(i);
            }
        }

        self.queries.push(None);
        DnsQueryHandle(self.queries.len() - 1)
    }

    /// Start a query.
    ///
    /// `name` is specified in human-friendly format, such as `"rust-lang.org"`.
    /// It accepts names both with and without trailing dot, and they're treated
    /// the same (there's no support for DNS search path).
    ///
    /// With the `mdns` feature, names ending in `.local` are sent with multicast DNS.
    pub fn start_query(
        &mut self,
        stack: &mut Stack,
        name: &str,
        query_type: Type,
    ) -> Result<DnsQueryHandle, StartQueryError> {
        let mut name = name.as_bytes();

        if name.is_empty() {
            trace!("invalid name: zero length");
            return Err(StartQueryError::InvalidName);
        }

        // Remove trailing dot, if any
        if name[name.len() - 1] == b'.' {
            name = &name[..name.len() - 1];
        }

        let mut raw_name: Vec<u8, DNS_MAX_NAME_SIZE> = Vec::new();

        #[allow(unused_mut)]
        let mut mdns = MulticastDns::Disabled;
        #[cfg(feature = "mdns")]
        if name.split(|&c| c == b'.').next_back().unwrap() == b"local" {
            trace!("Starting a mDNS query");
            mdns = MulticastDns::Enabled;
        }

        for s in name.split(|&c| c == b'.') {
            if s.len() > 63 {
                trace!("invalid name: too long label");
                return Err(StartQueryError::InvalidName);
            }
            if s.is_empty() {
                trace!("invalid name: zero length label");
                return Err(StartQueryError::InvalidName);
            }

            // Push label
            raw_name.push(s.len() as u8).map_err(|_| StartQueryError::NameTooLong)?;
            raw_name
                .extend_from_slice(s)
                .map_err(|_| StartQueryError::NameTooLong)?;
        }

        // Push terminator.
        raw_name.push(0x00).map_err(|_| StartQueryError::NameTooLong)?;

        self.start_query_raw(stack, &raw_name, query_type, mdns)
    }

    /// Start a query with a raw (wire-format) DNS name, such as
    /// `b"\x09rust-lang\x03org\x00"`.
    ///
    /// You probably want to use [`start_query`](Self::start_query) instead.
    pub fn start_query_raw(
        &mut self,
        stack: &mut Stack,
        raw_name: &[u8],
        query_type: Type,
        mdns: MulticastDns,
    ) -> Result<DnsQueryHandle, StartQueryError> {
        let name = Vec::from_slice(raw_name).map_err(|_| StartQueryError::NameTooLong)?;
        let handle = self.find_free_query();

        self.queries[handle.0] = Some(DnsQuery {
            state: State::Pending(PendingQuery {
                name,
                type_: query_type,
                txid: stack.inner.rand.rand_u32() as u16,
                delay: RETRANSMIT_DELAY,
                timeout_at: None,
                retransmit_at: Instant::ZERO,
                server_idx: 0,
                mdns,
            }),
            #[cfg(feature = "async")]
            waker: WakerRegistration::new(),
        });
        Ok(handle)
    }

    /// Get the result of a query.
    ///
    /// If the query is completed, the query slot is automatically freed.
    ///
    /// # Panics
    /// Panics if the handle corresponds to a free slot.
    pub fn get_query_result(
        &mut self,
        handle: DnsQueryHandle,
    ) -> Result<Vec<IpAddress, DNS_MAX_RESULT_COUNT>, GetQueryResultError> {
        let slot = &mut self.queries[handle.0];
        let q = slot.as_mut().unwrap();
        match &mut q.state {
            // Query is not done yet.
            State::Pending(_) => Err(GetQueryResultError::Pending),
            // Query is done
            State::Completed(q) => {
                let res = q.addresses.clone();
                *slot = None; // Free up the slot for recycling.
                Ok(res)
            }
            State::Failure => {
                *slot = None; // Free up the slot for recycling.
                Err(GetQueryResultError::Failed)
            }
        }
    }

    /// Cancels a query, freeing the slot.
    ///
    /// # Panics
    /// Panics if the handle corresponds to an already free slot.
    pub fn cancel_query(&mut self, handle: DnsQueryHandle) {
        let slot = &mut self.queries[handle.0];
        if slot.is_none() {
            panic!("Canceling query in a free slot.")
        }
        *slot = None; // Free up the slot for recycling.
    }

    /// Assign a waker to a query slot.
    ///
    /// The waker will be woken when the query completes, either successfully or failed.
    ///
    /// # Panics
    /// Panics if the handle corresponds to an already free slot.
    #[cfg(feature = "async")]
    pub fn register_query_waker(&mut self, handle: DnsQueryHandle, waker: &Waker) {
        self.queries[handle.0].as_mut().unwrap().waker.register(waker);
    }

    /// Advance the client: process received responses and send due queries.
    ///
    /// Uses the time of the last `Stack::poll`.
    ///
    /// Returns the next time `poll` should be called to retransmit a query, or
    /// [`Instant::MAX`] if no query is pending. Call it after every [`Stack::poll`],
    /// and again when that deadline arrives.
    #[must_use]
    pub fn poll(&mut self, stack: &mut Stack) -> Instant {
        self.process(stack);
        self.dispatch(stack)
    }

    fn accepts(&self, remote: IpEndpoint) -> bool {
        (remote.port == DNS_PORT && self.servers.contains(&remote.addr)) || (remote.port == MDNS_DNS_PORT)
    }

    fn process(&mut self, stack: &mut Stack) {
        loop {
            let mut pkt = match stack.udp_socket(self.socket).recv() {
                Ok(pkt) => pkt,
                Err(RecvError::Exhausted) | Err(RecvError::InvalidState) => return,
                // ICMP errors about our queries: the retransmit timer deals with those.
                Err(_) => continue,
            };

            let remote = pkt.meta().endpoint;
            if !self.accepts(remote) {
                trace!("dns packet from unexpected source {}", remote);
                continue;
            }

            trace!("receiving {} octets from {}", pkt.len(), remote);

            let p = match Packet::new_checked(pkt.payload_mut()) {
                Ok(x) => x,
                Err(_) => {
                    trace!("dns packet malformed");
                    continue;
                }
            };
            if p.opcode() != Opcode::Query {
                trace!("unwanted opcode {:?}", p.opcode());
                continue;
            }

            if !p.flags().contains(Flags::RESPONSE) {
                trace!("packet doesn't have response bit set");
                continue;
            }

            if p.question_count() != 1 {
                trace!("bad question count {:?}", p.question_count());
                continue;
            }

            // Find pending query
            let mut matched = false;
            'queries: for q in self.queries.iter_mut().flatten() {
                if let State::Pending(pq) = &mut q.state {
                    if p.transaction_id() != pq.txid {
                        continue;
                    }
                    matched = true;

                    if p.rcode() == Rcode::NXDomain {
                        trace!("rcode NXDomain");
                        q.set_state(State::Failure);
                        continue;
                    }

                    let payload = p.payload();
                    let (mut payload, question) = match Question::parse(payload) {
                        Ok(x) => x,
                        Err(_) => {
                            trace!("question malformed");
                            break;
                        }
                    };

                    if question.type_ != pq.type_ {
                        trace!("question type mismatch");
                        break;
                    }

                    match eq_names(p.parse_name(question.name), p.parse_name(&pq.name)) {
                        Ok(true) => {}
                        Ok(false) => {
                            trace!("question name mismatch");
                            break;
                        }
                        Err(_) => {
                            trace!("dns question name malformed");
                            break;
                        }
                    }

                    let mut addresses = Vec::new();

                    for _ in 0..p.answer_record_count() {
                        let (payload2, r) = match Record::parse(payload) {
                            Ok(x) => x,
                            Err(_) => {
                                trace!("dns answer record malformed");
                                break 'queries;
                            }
                        };
                        payload = payload2;

                        match eq_names(p.parse_name(r.name), p.parse_name(&pq.name)) {
                            Ok(true) => {}
                            Ok(false) => {
                                trace!("answer name mismatch: {:?}", r);
                                continue;
                            }
                            Err(_) => {
                                trace!("dns answer record name malformed");
                                break 'queries;
                            }
                        }

                        match r.data {
                            #[cfg(feature = "ipv4")]
                            RecordData::A(addr) => {
                                trace!("A: {:?}", addr);
                                if addresses.push(addr.into()).is_err() {
                                    trace!("too many addresses in response, ignoring {:?}", addr);
                                }
                            }
                            #[cfg(feature = "ipv6")]
                            RecordData::Aaaa(addr) => {
                                trace!("AAAA: {:?}", addr);
                                if addresses.push(addr.into()).is_err() {
                                    trace!("too many addresses in response, ignoring {:?}", addr);
                                }
                            }
                            RecordData::Cname(name) => {
                                trace!("CNAME: {:?}", name);

                                // When faced with a CNAME, recursive resolvers are supposed to
                                // resolve the CNAME and append the results for it.
                                //
                                // We update the query with the new name, so that we pick up the A/AAAA
                                // records for the CNAME when we parse them later.
                                // I believe it's mandatory the CNAME results MUST come *after* in the
                                // packet, so it's enough to do one linear pass over it.
                                if copy_name(&mut pq.name, p.parse_name(name)).is_err() {
                                    trace!("dns answer cname malformed");
                                    break 'queries;
                                }
                            }
                            RecordData::Other(type_, data) => {
                                trace!("unknown: {:?} {:?}", type_, data)
                            }
                        }
                    }

                    q.set_state(if addresses.is_empty() {
                        State::Failure
                    } else {
                        State::Completed(CompletedQuery { addresses })
                    });

                    // If we get here, packet matched the current query, stop processing.
                    break;
                }
            }

            if !matched {
                // If we get here, packet matched with no query.
                trace!("no query matched");
            }
        }
    }

    fn dispatch(&mut self, stack: &mut Stack) -> Instant {
        let now = stack.inner.now;
        let mut next_poll_at = Instant::MAX;

        for q in self.queries.iter_mut().flatten() {
            if let State::Pending(pq) = &mut q.state {
                // As per RFC 6762 any DNS query ending in .local. MUST be sent as mdns
                // so we internally overwrite the servers for any of those queries
                // in this function.
                let servers = match pq.mdns {
                    #[cfg(feature = "mdns")]
                    MulticastDns::Enabled => &[
                        #[cfg(feature = "ipv6")]
                        MDNS_IPV6_ADDR,
                        #[cfg(feature = "ipv4")]
                        MDNS_IPV4_ADDR,
                    ],
                    MulticastDns::Disabled => self.servers.as_slice(),
                };

                let timeout = if let Some(timeout) = pq.timeout_at {
                    timeout
                } else {
                    let v = now + RETRANSMIT_TIMEOUT;
                    pq.timeout_at = Some(v);
                    v
                };

                // Check timeout
                if timeout < now {
                    // DNS timeout
                    pq.timeout_at = Some(now + RETRANSMIT_TIMEOUT);
                    pq.retransmit_at = Instant::ZERO;
                    pq.delay = RETRANSMIT_DELAY;

                    // Try next server. We check below whether we've tried all servers.
                    pq.server_idx += 1;
                }
                // Check if we've run out of servers to try.
                if pq.server_idx >= servers.len() {
                    trace!("already tried all servers.");
                    q.set_state(State::Failure);
                    continue;
                }

                // Check so the IP address is valid
                if servers[pq.server_idx].is_unspecified() {
                    trace!("invalid unspecified DNS server addr.");
                    q.set_state(State::Failure);
                    continue;
                }

                if pq.retransmit_at > now {
                    // query is waiting for retransmit
                    next_poll_at = next_poll_at.min(pq.retransmit_at);
                    continue;
                }

                let question = Question {
                    name: &pq.name,
                    type_: pq.type_,
                };

                let mut payload = [0u8; 512];
                let payload = &mut payload[..HEADER_LEN + question.buffer_len()];
                let mut packet = Packet::new_unchecked(payload);
                packet.set_transaction_id(pq.txid);
                packet.set_flags(Flags::RECURSION_DESIRED);
                packet.set_opcode(Opcode::Query);
                packet.set_question_count(1);
                packet.set_answer_record_count(0);
                packet.set_authority_record_count(0);
                packet.set_additional_record_count(0);
                question.emit(packet.payload_mut());

                let dst_port = match pq.mdns {
                    #[cfg(feature = "mdns")]
                    MulticastDns::Enabled => MDNS_DNS_PORT,
                    MulticastDns::Disabled => DNS_PORT,
                };

                let dst = IpEndpoint::new(servers[pq.server_idx], dst_port);

                trace!("sending {} octets to {}", payload.len(), dst);

                match stack.udp_socket(self.socket).send_slice(payload, dst) {
                    Ok(()) => {}
                    Err(e) => {
                        // `Unaddressable` is the "no source address for destination" case.
                        // The others can't happen for a bound socket and a ≤512 byte payload.
                        let _: SendError = e;
                        trace!("send to {} failed: {:?}", dst, e);
                        q.set_state(State::Failure);
                        continue;
                    }
                }

                pq.retransmit_at = now + pq.delay;
                pq.delay = MAX_RETRANSMIT_DELAY.min(pq.delay * 2);
                next_poll_at = next_poll_at.min(pq.retransmit_at);
            }
        }

        next_poll_at
    }
}

fn eq_names<'a>(
    mut a: impl Iterator<Item = wire::Result<&'a [u8]>>,
    mut b: impl Iterator<Item = wire::Result<&'a [u8]>>,
) -> wire::Result<bool> {
    loop {
        match (a.next(), b.next()) {
            // Handle errors
            (Some(Err(e)), _) => return Err(e),
            (_, Some(Err(e))) => return Err(e),

            // Both finished -> equal
            (None, None) => return Ok(true),

            // One finished before the other -> not equal
            (None, _) => return Ok(false),
            (_, None) => return Ok(false),

            // Got two labels, check if they're equal
            (Some(Ok(la)), Some(Ok(lb))) => {
                if la != lb {
                    return Ok(false);
                }
            }
        }
    }
}

fn copy_name<'a, const N: usize>(
    dest: &mut Vec<u8, N>,
    name: impl Iterator<Item = wire::Result<&'a [u8]>>,
) -> Result<(), wire::Error> {
    dest.truncate(0);

    for label in name {
        let label = label?;
        dest.push(label.len() as u8).map_err(|_| wire::Error)?;
        dest.extend_from_slice(label).map_err(|_| wire::Error)?;
    }

    // Write terminator 0x00
    dest.push(0).map_err(|_| wire::Error)?;

    Ok(())
}
