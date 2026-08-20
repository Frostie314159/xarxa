// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP, and RFC 4861 § 7.2 and § 7.3.

use alloc::vec::Vec;

use crate::buf::PacketBuf;
use crate::stack::IfaceHandle;
use crate::time::{Duration, Instant};
use crate::wire::{EthernetAddress, IpAddress};

/// Key identifying a neighbor: the interface it is reachable through, plus its
/// protocol address.
pub(crate) type Key = (IfaceHandle, IpAddress);

/// Maximum number of entries in the neighbor cache.
pub(crate) const NEIGHBOR_CACHE_COUNT: usize = 8;

/// Maximum number of packets waiting for neighbor resolution, per interface.
///
/// When the queue is full, the oldest packet is dropped to make room.
pub(crate) const PENDING_QUEUE_COUNT: usize = 16;

/// How long a packet may sit in the pending queue before it is dropped.
pub(crate) const PENDING_QUEUE_LIFETIME: Duration = Duration::from_millis(5_000);

/// Maximum number of solicitations sent for one resolution before giving up.
/// (RFC 4861 MAX_MULTICAST_SOLICIT)
pub(crate) const MAX_MULTICAST_SOLICIT: u8 = 3;

/// Delay between solicitation retransmissions. (RFC 4861 RETRANS_TIMER)
pub(crate) const RETRANS_TIMER: Duration = Duration::from_millis(1_000);

/// State of a neighbor cache entry, in the style of RFC 4861 § 7.3.2.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
enum State {
    /// Address resolution is in progress: solicitations are being sent, no answer
    /// yet. Egress packets for this neighbor are queued in the [PendingQueue]
    /// meanwhile.
    Incomplete {
        /// Number of solicitations sent so far.
        probes_sent: u8,
        /// When to send the next solicitation.
        retrans_at: Instant,
    },
    /// The neighbor's hardware address is known.
    Reachable {
        hardware_addr: EthernetAddress,
        /// The timestamp past which the mapping should be discarded.
        expires_at: Instant,
    },
}

/// An answer to a neighbor cache lookup.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(EthernetAddress),
    /// Resolution of this neighbor is already in progress.
    Pending,
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
}

impl Answer {
    /// Returns whether a valid address was found.
    #[cfg(feature = "ipv6")]
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A due resolution timer, returned by [Cache::poll_retransmit].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeEvent {
    /// Another solicitation should be sent to the neighbor.
    Retransmit(IpAddress),
    /// Resolution failed after the maximum number of solicitations. The entry has
    /// been removed; packets queued on it should be dropped.
    Failed(IpAddress),
}

/// A neighbor cache backed by a map.
#[derive(Debug)]
pub struct Cache {
    storage: Vec<(Key, State)>,
}

impl Cache {
    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub fn new() -> Self {
        Self { storage: Vec::new() }
    }

    pub(crate) fn lookup(&self, key: &Key, timestamp: Instant) -> Answer {
        assert!(key.1.is_unicast());

        match self.get(key) {
            Some(State::Reachable {
                hardware_addr,
                expires_at,
            }) if timestamp < expires_at => Answer::Found(hardware_addr),
            Some(State::Incomplete { .. }) => Answer::Pending,
            _ => Answer::NotFound,
        }
    }

    /// Create an INCOMPLETE entry for a neighbor, starting address resolution.
    ///
    /// The caller sends the first solicitation itself; the entry's retransmission
    /// timer takes over from there (see [Cache::poll_retransmit]).
    pub(crate) fn start_resolution(&mut self, key: Key, timestamp: Instant) {
        debug_assert!(key.1.is_unicast());

        self.insert(
            key,
            State::Incomplete {
                probes_sent: 1,
                retrans_at: timestamp + RETRANS_TIMER,
            },
        );
    }

    /// Advance the retransmission timers of the neighbors being resolved on `iface`,
    /// one entry per call.
    ///
    /// `cursor` is the scan position. Start it at 0 and call in a loop until `None`
    /// is returned: each call resumes the scan where the previous one stopped, so
    /// the whole loop is one pass over the cache.
    ///
    /// An entry with probes left gets its probe counter bumped and its timer
    /// rearmed, and is returned as [ProbeEvent::Retransmit] so the caller sends
    /// another solicitation; an entry that exhausted its probes is removed and
    /// returned as [ProbeEvent::Failed] so the caller drops the packets queued on it.
    pub(crate) fn poll_retransmit(
        &mut self,
        iface: IfaceHandle,
        timestamp: Instant,
        cursor: &mut usize,
    ) -> Option<ProbeEvent> {
        while let Some((key, state)) = self.storage.get_mut(*cursor) {
            let addr = key.1;
            match state {
                State::Incomplete {
                    probes_sent,
                    retrans_at,
                } if key.0 == iface && timestamp >= *retrans_at => {
                    if *probes_sent >= MAX_MULTICAST_SOLICIT {
                        // The last entry moves into `cursor`; examine it next.
                        self.storage.swap_remove(*cursor);
                        return Some(ProbeEvent::Failed(addr));
                    }
                    *probes_sent += 1;
                    *retrans_at = timestamp + RETRANS_TIMER;
                    *cursor += 1;
                    return Some(ProbeEvent::Retransmit(addr));
                }
                _ => *cursor += 1,
            }
        }
        None
    }

    /// The earliest retransmission timer in the cache, if any.
    pub(crate) fn poll_at(&self) -> Option<Instant> {
        self.storage
            .iter()
            .filter_map(|(_, state)| match state {
                State::Incomplete { retrans_at, .. } => Some(*retrans_at),
                State::Reachable { .. } => None,
            })
            .min()
    }

    pub fn reset_expiry_if_existing(&mut self, key: Key, source_hardware_addr: EthernetAddress, timestamp: Instant) {
        if let Some(State::Reachable {
            hardware_addr,
            expires_at,
        }) = self.get_mut(&key)
            && source_hardware_addr == *hardware_addr
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
        }
    }

    pub fn fill(&mut self, key: Key, hardware_addr: EthernetAddress, timestamp: Instant) {
        debug_assert!(key.1.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(key, hardware_addr, expires_at);
    }

    pub fn fill_with_expiration(&mut self, key: Key, hardware_addr: EthernetAddress, expires_at: Instant) {
        debug_assert!(key.1.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        match self.get(&key) {
            Some(State::Reachable {
                hardware_addr: old_hardware_addr,
                ..
            }) if old_hardware_addr != hardware_addr => {
                trace!("replaced {} => {} (was {})", key.1, hardware_addr, old_hardware_addr);
            }
            Some(State::Reachable { .. }) => {}
            Some(State::Incomplete { .. }) => {
                trace!("filled {} => {} (was incomplete)", key.1, hardware_addr);
            }
            None => {
                trace!("filled {} => {} (was empty)", key.1, hardware_addr);
            }
        }

        self.insert(
            key,
            State::Reachable {
                hardware_addr,
                expires_at,
            },
        );
    }

    /// Remove all entries for the given interface.
    pub(crate) fn purge_iface(&mut self, iface: IfaceHandle) {
        self.storage.retain(|(key, _)| key.0 != iface);
    }

    /// Remove all entries. Will be needed when addresses are changed at runtime.
    #[allow(unused)]
    pub(crate) fn flush(&mut self) {
        self.storage.clear()
    }

    fn insert(&mut self, key: Key, state: State) {
        if let Some(entry) = self.get_mut(&key) {
            *entry = state;
        } else if self.storage.len() < NEIGHBOR_CACHE_COUNT {
            self.storage.push((key, state));
        } else {
            // The cache is full, and we need to evict an entry. Prefer evicting
            // resolved entries: evicting an in-progress resolution would strand the
            // packets queued on it.
            let index = self
                .storage
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, state))| match state {
                    State::Reachable { expires_at, .. } => (0, *expires_at),
                    State::Incomplete { retrans_at, .. } => (1, *retrans_at),
                })
                .expect("empty neighbor cache storage")
                .0;

            let (_old_key, _) = self.storage[index];
            trace!("neighbor cache full, evicted {}", _old_key.1);
            self.storage[index] = (key, state);
        }
    }

    fn get(&self, key: &Key) -> Option<State> {
        self.storage
            .iter()
            .find(|(probe, _)| probe == key)
            .map(|(_, state)| *state)
    }

    fn get_mut(&mut self, key: &Key) -> Option<&mut State> {
        self.storage
            .iter_mut()
            .find(|(probe, _)| probe == key)
            .map(|(_, state)| state)
    }
}

/// A packet waiting for neighbor resolution.
#[derive(Debug)]
pub(crate) struct PendingPacket {
    pub key: Key,
    pub buf: PacketBuf,
    pub expires_at: Instant,
}

/// A queue of egress packets waiting for neighbor resolution.
///
/// When egress needs a neighbor that is not in the [Cache], the fully-built IP packet
/// is queued here and a solicitation (ARP request / NDISC neighbor solicit) is sent
/// instead, retransmitted per RFC 4861 until an answer arrives or the probe limit is
/// reached. When the answer arrives and fills the cache, the queued packets are
/// flushed to the device; if resolution fails, they are dropped.
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    packets: Vec<PendingPacket>,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self { packets: Vec::new() }
    }

    /// Queue a packet waiting for `key` to resolve.
    pub fn push(&mut self, key: Key, buf: PacketBuf, timestamp: Instant) {
        if self.packets.len() >= PENDING_QUEUE_COUNT {
            trace!("neighbor: pending queue full, dropping oldest packet");
            self.packets.remove(0);
        }
        self.packets.push(PendingPacket {
            key,
            buf,
            expires_at: timestamp + PENDING_QUEUE_LIFETIME,
        });
    }

    /// Remove and return all packets waiting for `key`, in FIFO order.
    pub fn take_matching(&mut self, key: &Key) -> Vec<PendingPacket> {
        self.packets.extract_if(.., |packet| packet.key == *key).collect()
    }

    /// Drop packets that have waited too long.
    pub fn purge_expired(&mut self, timestamp: Instant) {
        self.packets.retain(|packet| {
            if timestamp >= packet.expires_at {
                trace!(
                    "neighbor: dropping queued packet for {}, resolution timed out",
                    packet.key.1
                );
                false
            } else {
                true
            }
        });
    }

    /// Drop all packets queued on the given interface.
    pub fn purge_iface(&mut self, iface: IfaceHandle) {
        self.packets.retain(|packet| packet.key.0 != iface);
    }

    /// The earliest expiry timer in the queue, if any.
    pub fn poll_at(&self) -> Option<Instant> {
        self.packets.iter().map(|packet| packet.expires_at).min()
    }
}

#[cfg(all(test, feature = "ipv6"))]
mod test {
    use super::*;
    use crate::stack::IfaceHandle;
    use crate::wire::Ipv6Address;
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    const IF_0: IfaceHandle = IfaceHandle(0);
    const IF_1: IfaceHandle = IfaceHandle(1);

    const HADDR_A: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);
    const HADDR_B: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 2]);
    const HADDR_C: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 3]);
    const HADDR_D: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 4]);

    fn key(addr: Ipv6Address) -> Key {
        (IF_0, addr.into())
    }

    #[test]
    fn test_fill() {
        let mut cache = Cache::new();

        assert!(!cache.lookup(&key(MOCK_IP_ADDR_1), Instant::from_millis(0)).found());
        assert!(!cache.lookup(&key(MOCK_IP_ADDR_2), Instant::from_millis(0)).found());

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(!cache.lookup(&key(MOCK_IP_ADDR_2), Instant::from_millis(0)).found());
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new();

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &key(MOCK_IP_ADDR_1),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new();

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_per_iface() {
        let mut cache = Cache::new();

        // The same protocol address resolves independently on different interfaces.
        cache.fill((IF_0, MOCK_IP_ADDR_1.into()), HADDR_A, Instant::ZERO);
        cache.fill((IF_1, MOCK_IP_ADDR_1.into()), HADDR_B, Instant::ZERO);
        assert_eq!(
            cache.lookup(&(IF_0, MOCK_IP_ADDR_1.into()), Instant::ZERO),
            Answer::Found(HADDR_A)
        );
        assert_eq!(
            cache.lookup(&(IF_1, MOCK_IP_ADDR_1.into()), Instant::ZERO),
            Answer::Found(HADDR_B)
        );

        cache.purge_iface(IF_0);
        assert!(!cache.lookup(&(IF_0, MOCK_IP_ADDR_1.into()), Instant::ZERO).found());
        assert_eq!(
            cache.lookup(&(IF_1, MOCK_IP_ADDR_1.into()), Instant::ZERO),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new();

        // Fill the cache to capacity, with the entry for MOCK_IP_ADDR_2 being the
        // one that expires soonest.
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(100));
        cache.fill(key(MOCK_IP_ADDR_2), HADDR_B, Instant::from_millis(50));
        for i in 0..(NEIGHBOR_CACHE_COUNT - 2) {
            let mut addr = MOCK_IP_ADDR_3.octets();
            addr[14] = 1;
            addr[15] = i as u8;
            cache.fill(key(Ipv6Address::from(addr)), HADDR_C, Instant::from_millis(200));
        }
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_2), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(!cache.lookup(&key(MOCK_IP_ADDR_4), Instant::from_millis(1000)).found());

        cache.fill(key(MOCK_IP_ADDR_4), HADDR_D, Instant::from_millis(300));
        assert!(!cache.lookup(&key(MOCK_IP_ADDR_2), Instant::from_millis(1000)).found());
        assert_eq!(
            cache.lookup(&key(MOCK_IP_ADDR_4), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_resolution_failure() {
        let mut cache = Cache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1), t0);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1), t0), Answer::Pending);

        // First probe was sent at t0; nothing to do before the retransmission timer.
        assert_eq!(cache.poll_retransmit(IF_0, t0, &mut 0), None);
        assert_eq!(cache.poll_at(), Some(t0 + RETRANS_TIMER));

        // Second and third probes.
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER * 2, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );

        // Probe limit reached: resolution fails, the entry is removed.
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER * 3, &mut 0),
            Some(ProbeEvent::Failed(MOCK_IP_ADDR_1.into()))
        );
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1), t0), Answer::NotFound);
        assert_eq!(cache.poll_at(), None);
    }

    #[test]
    fn test_resolution_success() {
        let mut cache = Cache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1), t0);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1), t0), Answer::Pending);

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, t0);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1), t0), Answer::Found(HADDR_A));

        // The resolved entry has no retransmission timer anymore.
        assert_eq!(cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0), None);
        assert_eq!(cache.poll_at(), None);
    }

    #[test]
    fn test_retransmit_other_iface() {
        let mut cache = Cache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution((IF_1, MOCK_IP_ADDR_1.into()), t0);
        // Polling one interface's timers doesn't touch another's entries.
        assert_eq!(cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0), None);
        assert_eq!(
            cache.poll_retransmit(IF_1, t0 + RETRANS_TIMER, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );
    }

    #[test]
    fn test_pending_queue() {
        let mut queue = PendingQueue::new();

        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::new(), Instant::ZERO);
        queue.push(key(MOCK_IP_ADDR_2), PacketBuf::new(), Instant::ZERO);
        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::new(), Instant::ZERO);
        // Same address, different interface: distinct key.
        queue.push((IF_1, MOCK_IP_ADDR_1.into()), PacketBuf::new(), Instant::ZERO);

        let taken = queue.take_matching(&key(MOCK_IP_ADDR_1));
        assert_eq!(taken.len(), 2);
        assert!(queue.take_matching(&key(MOCK_IP_ADDR_1)).is_empty());
        assert_eq!(queue.take_matching(&key(MOCK_IP_ADDR_2)).len(), 1);
        assert_eq!(queue.take_matching(&(IF_1, MOCK_IP_ADDR_1.into())).len(), 1);
    }

    #[test]
    fn test_pending_queue_full() {
        let mut queue = PendingQueue::new();

        for _ in 0..PENDING_QUEUE_COUNT {
            queue.push(key(MOCK_IP_ADDR_1), PacketBuf::new(), Instant::ZERO);
        }
        // This push drops the oldest packet to make room.
        queue.push(key(MOCK_IP_ADDR_2), PacketBuf::new(), Instant::ZERO);

        assert_eq!(queue.take_matching(&key(MOCK_IP_ADDR_1)).len(), PENDING_QUEUE_COUNT - 1);
        assert_eq!(queue.take_matching(&key(MOCK_IP_ADDR_2)).len(), 1);
    }

    #[test]
    fn test_pending_queue_expire() {
        let mut queue = PendingQueue::new();

        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::new(), Instant::ZERO);
        assert_eq!(queue.poll_at(), Some(Instant::ZERO + PENDING_QUEUE_LIFETIME));
        queue.purge_expired(Instant::ZERO + PENDING_QUEUE_LIFETIME);
        assert!(queue.take_matching(&key(MOCK_IP_ADDR_1)).is_empty());
        assert_eq!(queue.poll_at(), None);
    }

    #[test]
    fn test_pending_queue_purge_iface() {
        let mut queue = PendingQueue::new();

        queue.push((IF_0, MOCK_IP_ADDR_1.into()), PacketBuf::new(), Instant::ZERO);
        queue.push((IF_1, MOCK_IP_ADDR_1.into()), PacketBuf::new(), Instant::ZERO);

        queue.purge_iface(IF_0);
        assert!(queue.take_matching(&(IF_0, MOCK_IP_ADDR_1.into())).is_empty());
        assert_eq!(queue.take_matching(&(IF_1, MOCK_IP_ADDR_1.into())).len(), 1);
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Cache {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Cache({=[?]})", self.storage.as_slice());
    }
}
