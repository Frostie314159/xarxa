//! TCP listeners.

use std::collections::VecDeque;

use super::{
    DEFAULT_MSS, ListenError, MIN_REMOTE_MSS, SocketBuffer, State, TcpControl, TcpHandle, TcpRepr, TcpSocketState,
    TcpTimestampRepr, Tuple,
};
use crate::rand::Rand;
use crate::slab::Slab;
use crate::stack::addr_matches;
use crate::tcp::TcpSeqNumber;
use crate::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

/// A handle to a TCP listener added to a [`Stack`].
///
/// [`Stack`]: crate::Stack
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpListenerHandle(pub(crate) usize);

/// A SYN recorded in a listener's accept queue: the parsed handshake state
/// needed to create the connection socket at accept time.
#[derive(Debug)]
struct PendingSyn {
    tuple: Tuple,
    /// The remote's initial sequence number plus one.
    remote_seq_no: TcpSeqNumber,
    /// The remote window advertised in the SYN (never scaled).
    remote_win_len: usize,
    /// The window scale the remote offered, if any.
    remote_win_scale: Option<u8>,
    /// Whether the remote supports selective ACK.
    remote_has_sack: bool,
    /// The MSS the remote advertised (clamped), or the default.
    remote_mss: usize,
    /// The timestamp option of the SYN, if present.
    timestamp: Option<TcpTimestampRepr>,
}

/// TCP listener state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct TcpListenerState {
    /// The listened endpoint. A zero port means the listener is closed. The
    /// address scopes the listen, from any address of any version down to one
    /// exact address.
    local: IpListenEndpoint,
    /// The accept queue: SYNs waiting to be accepted, deduplicated by 4-tuple.
    queue: VecDeque<PendingSyn>,
}

impl TcpListenerState {
    pub(crate) fn new() -> TcpListenerState {
        TcpListenerState {
            local: IpListenEndpoint::UNSPECIFIED,
            queue: VecDeque::new(),
        }
    }

    /// Whether a segment to (`dst_addr`, `dst_port`) is aimed at this listener.
    pub(crate) fn matches(&self, dst_addr: &IpAddress, dst_port: u16) -> bool {
        self.local.port != 0 && dst_port == self.local.port && addr_matches(&self.local, dst_addr)
    }

    /// Offer an ingress segment to this listener, returning whether it was
    /// consumed.
    ///
    /// The listener consumes exactly two things, and never replies to either.
    /// A SYN to the listened endpoint is recorded in the accept queue,
    /// deduplicated by 4-tuple with the newest SYN winning, so retransmissions
    /// (or a client aborting and reconnecting from the same port) update the
    /// entry in place. An RST aimed at a recorded SYN removes it. Everything
    /// else is left to the caller's RST fallback.
    pub(crate) fn process(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress, repr: &TcpRepr) -> bool {
        let tuple = Tuple {
            local: IpEndpoint::new(*dst_addr, repr.dst_port),
            remote: IpEndpoint::new(*src_addr, repr.src_port),
        };

        match repr.control {
            TcpControl::Syn if repr.ack_number.is_none() => {
                if !self.matches(dst_addr, repr.dst_port) {
                    return false;
                }

                let syn = PendingSyn {
                    tuple,
                    remote_seq_no: repr.seq_number + 1,
                    // The window field of a SYN is never scaled.
                    remote_win_len: repr.window_len as usize,
                    remote_win_scale: repr.window_scale,
                    remote_has_sack: repr.sack_permitted,
                    remote_mss: match repr.max_seg_size {
                        // A zero MSS is treated as if the option were absent,
                        // a tiny one is clamped.
                        Some(mss) if mss != 0 => (mss as usize).max(MIN_REMOTE_MSS),
                        _ => DEFAULT_MSS,
                    },
                    timestamp: repr.timestamp,
                };

                if let Some(entry) = self.queue.iter_mut().find(|s| s.tuple == tuple) {
                    // A retransmission of a queued SYN, or a new connection
                    // attempt reusing the same ports. The newest SYN wins.
                    *entry = syn;
                } else {
                    net_trace!("listener:{}: SYN from {}", self.local, tuple.remote);
                    self.queue.push_back(syn);
                }
                true
            }
            TcpControl::Rst => {
                // The client gave up before we accepted. The only acceptable
                // sequence number for a connection with nothing received past
                // the SYN is exactly RCV.NXT.
                if let Some(index) = self
                    .queue
                    .iter()
                    .position(|s| s.tuple == tuple && repr.seq_number == s.remote_seq_no)
                {
                    net_trace!("listener: queued SYN {} reset by remote", tuple);
                    self.queue.remove(index);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

/// A TCP listener borrowed from a [`Stack`], returned by [`Stack::tcp_listener`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::tcp_listener`]: crate::Stack::tcp_listener
///
/// Use a [`TcpListener`] to accept incoming TCP connections.
///
/// A listener can be bound to a port and optionally an address.
/// It receives all incoming connection attempts and queues them.
/// Calling [`accept`](TcpListener::accept) pops a connection from the queue
/// and constructs a full [`TcpSocket`](crate::tcp::TcpSocket) for it.
///
/// Connection attempts (SYN packets) are not answered (with a SYN|ACK packet) until you accept them.
pub struct TcpListener<'a> {
    pub(crate) listeners: &'a mut Slab<TcpListenerState>,
    pub(crate) index: usize,
    pub(crate) tcp: &'a mut Slab<TcpSocketState>,
    pub(crate) rand: &'a mut Rand,
}

impl TcpListener<'_> {
    /// This listener's state in the slab.
    #[inline]
    fn inner(&self) -> &TcpListenerState {
        self.listeners.get(self.index)
    }

    /// Mutable variant of [`inner`](Self::inner).
    #[inline]
    fn inner_mut(&mut self) -> &mut TcpListenerState {
        self.listeners.get_mut(self.index)
    }

    /// Start listening on the given endpoint.
    ///
    /// Returns:
    /// - `Err(ListenError::Unaddressable)` if the port is zero.
    /// - `Err(ListenError::InvalidState)` if the listener is already listening
    ///   (unless it is listening on this same endpoint, which is a no-op).
    /// - `Err(ListenError::InUse)` if another listener is bound to an identical
    ///   endpoint. Listeners on the same port with *different* specificity (one
    ///   wildcard, one per-version, one per-address) may coexist.
    pub fn listen(&mut self, local_endpoint: impl Into<IpListenEndpoint>) -> Result<(), ListenError> {
        let local = local_endpoint.into();
        if local.port == 0 {
            return Err(ListenError::Unaddressable);
        }
        if self.is_open() {
            if self.inner().local == local {
                return Ok(());
            }
            return Err(ListenError::InvalidState);
        }
        if self.listeners.iter().any(|(i, l)| i != self.index && l.local == local) {
            return Err(ListenError::InUse);
        }

        self.inner_mut().local = local;
        Ok(())
    }

    /// Stop listening, dropping all queued SYNs.
    ///
    /// The dropped SYNs are not reset. The clients' retransmissions are
    /// answered with an RST once the listener is gone.
    pub fn close(&mut self) {
        let state = self.inner_mut();
        state.local = IpListenEndpoint::UNSPECIFIED;
        state.queue.clear();
    }

    /// Whether the listener is listening.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().local.port != 0
    }

    /// Return the listened endpoint. The address is the filter the listen scoped
    /// the listener to. A zero port means the listener is closed.
    #[inline]
    pub fn local_endpoint(&self) -> IpListenEndpoint {
        self.inner().local
    }

    /// Whether a connection attempt is waiting to be [`accept`](Self::accept)ed.
    pub fn can_accept(&self) -> bool {
        !self.inner().queue.is_empty()
    }

    /// Accept a queued connection attempt, allocating the actual socket for it,
    /// with receive and transmit buffers of the given capacities.
    ///
    /// The new socket starts in the SYN-RECEIVED state and is added to the stack.
    ///
    /// Returns `None` if no connection attempt is queued.
    pub fn accept(&mut self, rx_capacity: usize, tx_capacity: usize) -> Option<TcpHandle> {
        let state = self.listeners.get_mut(self.index);
        let syn = state.queue.pop_front()?;
        net_trace!("listener:{}: accepting {}", state.local, syn.tuple);

        // The SYN-RECEIVED socket continuing the recorded SYN. This mirrors
        // what the SYN would have set up in a LISTEN-state socket: the SYN|ACK
        // itself is built by the socket's dispatch from this state.
        let mut s = TcpSocketState::new(
            SocketBuffer::new(vec![0; rx_capacity]),
            SocketBuffer::new(vec![0; tx_capacity]),
        );
        s.state = State::SynReceived;
        s.tuple = Some(syn.tuple);
        s.local_seq_no = TcpSocketState::random_seq_no(self.rand);
        s.remote_seq_no = syn.remote_seq_no;
        s.remote_last_seq = s.local_seq_no;
        s.remote_has_sack = syn.remote_has_sack;
        s.remote_win_scale = syn.remote_win_scale;
        // Remote doesn't support window scaling, don't do it.
        if syn.remote_win_scale.is_none() {
            s.remote_win_shift = 0;
        }
        s.remote_win_len = syn.remote_win_len;
        s.remote_mss = syn.remote_mss;
        s.congestion_controller.inner_mut().set_mss(syn.remote_mss);
        match syn.timestamp {
            // Remote doesn't support timestamps, don't do it.
            None => s.tsval_generator = None,
            Some(ts) => s.last_remote_tsval = ts.tsval,
        }

        Some(TcpHandle(self.tcp.add_with(|_| s)))
    }
}
