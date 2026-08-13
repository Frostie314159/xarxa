// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use crate::buf::PacketBuf;
use crate::time::{Duration, Instant};
use crate::wire::{EthernetAddress, IpAddress};

/// Maximum number of entries in a neighbor cache.
pub(crate) const NEIGHBOR_CACHE_COUNT: usize = 8;

/// Maximum number of packets waiting for neighbor resolution, per interface.
///
/// When the queue is full, the oldest packet is dropped to make room.
pub(crate) const PENDING_QUEUE_COUNT: usize = 16;

/// How long a packet may sit in the pending queue before it is dropped.
pub(crate) const PENDING_QUEUE_LIFETIME: Duration = Duration::from_millis(3_000);

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
pub struct Neighbor {
    hardware_addr: EthernetAddress,
    expires_at: Instant,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(EthernetAddress),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A neighbor cache backed by a map.
#[derive(Debug)]
pub struct Cache {
    storage: Vec<(IpAddress, Neighbor)>,
    silent_until: Instant,
}

impl Cache {
    /// Minimum delay between discovery requests, in milliseconds.
    pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);

    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
            silent_until: Instant::from_millis(0),
        }
    }

    pub fn reset_expiry_if_existing(
        &mut self,
        protocol_addr: IpAddress,
        source_hardware_addr: EthernetAddress,
        timestamp: Instant,
    ) {
        if let Some(Neighbor {
            expires_at,
            hardware_addr,
        }) = self.get_mut(&protocol_addr)
            && source_hardware_addr == *hardware_addr
        {
            *expires_at = timestamp + Self::ENTRY_LIFETIME;
        }
    }

    pub fn fill(&mut self, protocol_addr: IpAddress, hardware_addr: EthernetAddress, timestamp: Instant) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(protocol_addr, hardware_addr, expires_at);
    }

    pub fn fill_with_expiration(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: EthernetAddress,
        expires_at: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
        };

        if let Some(old_neighbor) = self.get_mut(&protocol_addr) {
            if old_neighbor.hardware_addr != hardware_addr {
                net_trace!(
                    "replaced {} => {} (was {})",
                    protocol_addr,
                    hardware_addr,
                    old_neighbor.hardware_addr
                );
            }
            *old_neighbor = neighbor;
        } else if self.storage.len() < NEIGHBOR_CACHE_COUNT {
            self.storage.push((protocol_addr, neighbor));
            net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
        } else {
            // The cache is full, and we need to evict an entry.
            let index = self
                .storage
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, neighbor))| neighbor.expires_at)
                .expect("empty neighbor cache storage")
                .0;

            let (_old_protocol_addr, _old_neighbor) = self.storage[index];
            self.storage[index] = (protocol_addr, neighbor);
            net_trace!(
                "filled {} => {} (evicted {} => {})",
                protocol_addr,
                hardware_addr,
                _old_protocol_addr,
                _old_neighbor.hardware_addr
            );
        }
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        assert!(protocol_addr.is_unicast());

        if let Some(&(
            _,
            Neighbor {
                expires_at,
                hardware_addr,
            },
        )) = self.storage.iter().find(|(addr, _)| addr == protocol_addr)
            && timestamp < expires_at
        {
            return Answer::Found(hardware_addr);
        }

        if timestamp < self.silent_until {
            Answer::RateLimited
        } else {
            Answer::NotFound
        }
    }

    pub(crate) fn limit_rate(&mut self, timestamp: Instant) {
        self.silent_until = timestamp + Self::SILENT_TIME;
    }

    fn get_mut(&mut self, protocol_addr: &IpAddress) -> Option<&mut Neighbor> {
        self.storage
            .iter_mut()
            .find(|(addr, _)| addr == protocol_addr)
            .map(|(_, neighbor)| neighbor)
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

/// A packet waiting for neighbor resolution.
#[derive(Debug)]
pub(crate) struct PendingPacket {
    pub next_hop: IpAddress,
    pub buf: PacketBuf,
    pub expires_at: Instant,
}

/// A queue of egress packets waiting for neighbor resolution.
///
/// When egress needs a neighbor that is not in the [Cache], the fully-built IP packet
/// is queued here and a solicitation (ARP request / NDISC neighbor solicit) is sent
/// instead. When the answer arrives and fills the cache, the packets are
/// transmitted.
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    packets: Vec<PendingPacket>,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self { packets: Vec::new() }
    }

    /// Queue a packet waiting for `next_hop` to resolve.
    pub fn push(&mut self, next_hop: IpAddress, buf: PacketBuf, timestamp: Instant) {
        if self.packets.len() >= PENDING_QUEUE_COUNT {
            net_trace!("neighbor: pending queue full, dropping oldest packet");
            self.packets.remove(0);
        }
        self.packets.push(PendingPacket {
            next_hop,
            buf,
            expires_at: timestamp + PENDING_QUEUE_LIFETIME,
        });
    }

    /// Remove and return all packets waiting for `addr`, in FIFO order.
    pub fn take_matching(&mut self, addr: &IpAddress) -> Vec<PendingPacket> {
        self.packets.extract_if(.., |packet| packet.next_hop == *addr).collect()
    }

    /// Drop packets that have waited too long.
    pub fn purge_expired(&mut self, timestamp: Instant) {
        self.packets.retain(|packet| {
            if timestamp >= packet.expires_at {
                net_trace!(
                    "neighbor: dropping pending packet for {}, resolution timed out",
                    packet.next_hop
                );
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    const HADDR_A: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 1]);
    const HADDR_B: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 2]);
    const HADDR_C: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 3]);
    const HADDR_D: EthernetAddress = EthernetAddress([0, 0, 0, 0, 0, 4]);

    #[test]
    fn test_fill() {
        let mut cache = Cache::new();

        assert!(!cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)).found());
        assert!(!cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0)).found());

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(!cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0)).found());
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert!(!cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0)).found());
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new();

        // Fill the cache to capacity, with the entry for MOCK_IP_ADDR_2 being the
        // one that expires soonest.
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(50));
        for i in 0..(NEIGHBOR_CACHE_COUNT - 2) {
            let mut addr = MOCK_IP_ADDR_3.octets();
            addr[14] = 1;
            addr[15] = i as u8;
            cache.fill(
                crate::wire::Ipv6Address::from(addr).into(),
                HADDR_C,
                Instant::from_millis(200),
            );
        }
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(!cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)).found());

        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(300));
        assert!(!cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)).found());
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_hush() {
        let mut cache = Cache::new();

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(2000)),
            Answer::NotFound
        );
    }

    #[test]
    fn test_flush() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(!cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0)).found());

        cache.flush();
        assert!(!cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)).found());
    }

    #[test]
    fn test_pending_queue() {
        let mut queue = PendingQueue::new();

        queue.push(MOCK_IP_ADDR_1.into(), PacketBuf::new(), Instant::ZERO);
        queue.push(MOCK_IP_ADDR_2.into(), PacketBuf::new(), Instant::ZERO);
        queue.push(MOCK_IP_ADDR_1.into(), PacketBuf::new(), Instant::ZERO);

        let taken = queue.take_matching(&MOCK_IP_ADDR_1.into());
        assert_eq!(taken.len(), 2);
        assert!(queue.take_matching(&MOCK_IP_ADDR_1.into()).is_empty());
        assert_eq!(queue.take_matching(&MOCK_IP_ADDR_2.into()).len(), 1);
    }

    #[test]
    fn test_pending_queue_full() {
        let mut queue = PendingQueue::new();

        for _ in 0..PENDING_QUEUE_COUNT {
            queue.push(MOCK_IP_ADDR_1.into(), PacketBuf::new(), Instant::ZERO);
        }
        // This push drops the oldest packet to make room.
        queue.push(MOCK_IP_ADDR_2.into(), PacketBuf::new(), Instant::ZERO);

        assert_eq!(
            queue.take_matching(&MOCK_IP_ADDR_1.into()).len(),
            PENDING_QUEUE_COUNT - 1
        );
        assert_eq!(queue.take_matching(&MOCK_IP_ADDR_2.into()).len(), 1);
    }

    #[test]
    fn test_pending_queue_expire() {
        let mut queue = PendingQueue::new();

        queue.push(MOCK_IP_ADDR_1.into(), PacketBuf::new(), Instant::ZERO);
        queue.purge_expired(Instant::ZERO + PENDING_QUEUE_LIFETIME);
        assert!(queue.take_matching(&MOCK_IP_ADDR_1.into()).is_empty());
    }
}
