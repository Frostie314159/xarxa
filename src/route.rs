//! IP routing.
//!
//! [`Routes`] is the routing table, accessed with [`Stack::routes`] and
//! [`Stack::routes_mut`].
//!
//! Routes are keyed by a CIDR. On lookup most specific CIDR wins. Each route contains:
//! - via
//! - outgoing interface
//! - optional expiry time.
//!
//! On-link destinations (in the same network as one of the stack's addresses) do
//! not consult the table: the next hop is the destination itself.
//!
//! [`Stack::routes`]: crate::Stack::routes
//! [`Stack::routes_mut`]: crate::Stack::routes_mut

use alloc::vec::Vec;

use crate::stack::IfaceHandle;
use crate::time::Instant;
use crate::wire::{IpAddress, IpCidr};
#[cfg(feature = "proto-ipv4")]
use crate::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use crate::wire::{Ipv6Address, Ipv6Cidr};

#[cfg(feature = "proto-ipv4")]
const IPV4_DEFAULT: IpCidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0));
#[cfg(feature = "proto-ipv6")]
const IPV6_DEFAULT: IpCidr = IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

/// A prefix of addresses that should be routed via a router, out of an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddress,
    /// The interface this route goes out of.
    pub iface: IfaceHandle,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, out of `iface`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address, iface: IfaceHandle) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            iface,
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, out of `iface`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address, iface: IfaceHandle) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            iface,
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns `true` if the route is a default route for IPv4.
    #[cfg(feature = "proto-ipv4")]
    pub fn is_ipv4_gateway(&self) -> bool {
        self.cidr == IPV4_DEFAULT
    }

    /// Returns `true` if the route is a default route for IPv6.
    #[cfg(feature = "proto-ipv6")]
    pub fn is_ipv6_gateway(&self) -> bool {
        self.cidr == IPV6_DEFAULT
    }
}

/// A routing table.
#[derive(Debug, Default)]
pub struct Routes {
    storage: Vec<Route>,
}

impl Routes {
    /// Creates a new empty routing table.
    pub(crate) fn new() -> Self {
        Self { storage: Vec::new() }
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut Vec<Route>)>(&mut self, f: F) {
        f(&mut self.storage);
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway` dev `iface`").
    ///
    /// Returns the previous default route, if any.
    #[cfg(feature = "proto-ipv4")]
    pub fn add_default_ipv4_route(&mut self, gateway: Ipv4Address, iface: IfaceHandle) -> Option<Route> {
        let old = self.remove_default_ipv4_route();
        self.storage.push(Route::new_ipv4_gateway(gateway, iface));
        old
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway` dev `iface`").
    ///
    /// Returns the previous default route, if any.
    #[cfg(feature = "proto-ipv6")]
    pub fn add_default_ipv6_route(&mut self, gateway: Ipv6Address, iface: IfaceHandle) -> Option<Route> {
        let old = self.remove_default_ipv6_route();
        self.storage.push(Route::new_ipv6_gateway(gateway, iface));
        old
    }

    /// Returns the ipv4 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_default_ipv4_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv4_gateway()).copied()
    }

    /// Returns the ipv6 default route if there is one in the route table.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_default_ipv6_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv6_gateway()).copied()
    }

    /// Remove the default ipv4 gateway, returning it if it existed.
    #[cfg(feature = "proto-ipv4")]
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        let index = self.storage.iter().position(|r| r.is_ipv4_gateway())?;
        Some(self.storage.remove(index))
    }

    /// Remove the default ipv6 gateway, returning it if it existed.
    #[cfg(feature = "proto-ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        let index = self.storage.iter().position(|r| r.is_ipv6_gateway())?;
        Some(self.storage.remove(index))
    }

    /// Look up the route for `addr`: the most specific matching prefix that has not
    /// expired.
    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) -> Option<&Route> {
        assert!(addr.is_unicast());

        self.storage
            .iter()
            // Keep only matching routes
            .filter(|route| {
                if let Some(expires_at) = route.expires_at
                    && timestamp > expires_at
                {
                    return false;
                }
                route.cidr.contains_addr(addr)
            })
            // pick the most specific one (highest prefix_len)
            .max_by_key(|route| route.cidr.prefix_len())
    }

    /// Remove all routes that go out of the given interface.
    pub(crate) fn purge_iface(&mut self, iface: IfaceHandle) {
        self.storage.retain(|route| route.iface != iface);
    }
}

#[cfg(all(test, feature = "proto-ipv4", feature = "proto-ipv6"))]
mod test {
    use super::*;

    const IF_0: IfaceHandle = IfaceHandle(0);
    const IF_1: IfaceHandle = IfaceHandle(1);

    const ADDR_1A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 1);
    const ADDR_1B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 13);
    const ADDR_1C: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 42);
    fn cidr_1() -> Ipv6Cidr {
        Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), 64)
    }

    const ADDR_2A: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 1);
    const ADDR_2B: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 21);
    fn cidr_2() -> Ipv6Cidr {
        Ipv6Cidr::new(Ipv6Address::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 0), 64)
    }

    /// Look up and return (via_router, iface).
    fn lookup(routes: &Routes, addr: Ipv6Address, at_millis: i64) -> Option<(IpAddress, IfaceHandle)> {
        routes
            .lookup(&addr.into(), Instant::from_millis(at_millis))
            .map(|route| (route.via_router, route.iface))
    }

    #[test]
    fn test_fill() {
        let mut routes = Routes::new();

        assert_eq!(lookup(&routes, ADDR_1A, 0), None);
        assert_eq!(lookup(&routes, ADDR_1B, 0), None);
        assert_eq!(lookup(&routes, ADDR_1C, 0), None);
        assert_eq!(lookup(&routes, ADDR_2A, 0), None);
        assert_eq!(lookup(&routes, ADDR_2B, 0), None);

        let route = Route {
            cidr: cidr_1().into(),
            via_router: ADDR_1A.into(),
            iface: IF_0,
            preferred_until: None,
            expires_at: None,
        };
        routes.update(|storage| storage.push(route));

        assert_eq!(lookup(&routes, ADDR_1A, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&routes, ADDR_1B, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&routes, ADDR_1C, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&routes, ADDR_2A, 0), None);
        assert_eq!(lookup(&routes, ADDR_2B, 0), None);

        let route2 = Route {
            cidr: cidr_2().into(),
            via_router: ADDR_2A.into(),
            iface: IF_1,
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.update(|storage| storage.push(route2));

        assert_eq!(lookup(&routes, ADDR_1A, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&routes, ADDR_2A, 0), Some((ADDR_2A.into(), IF_1)));
        assert_eq!(lookup(&routes, ADDR_2B, 0), Some((ADDR_2A.into(), IF_1)));

        // The expiry timestamp itself is still valid...
        assert_eq!(lookup(&routes, ADDR_2A, 10), Some((ADDR_2A.into(), IF_1)));
        // ...but past it, the route is gone.
        assert_eq!(lookup(&routes, ADDR_2B, 11), None);
        assert_eq!(lookup(&routes, ADDR_1A, 11), Some((ADDR_1A.into(), IF_0)));
    }

    #[test]
    fn test_most_specific_wins() {
        let mut routes = Routes::new();

        routes.add_default_ipv6_route(ADDR_1A, IF_0);
        routes.update(|storage| {
            storage.push(Route {
                cidr: cidr_2().into(),
                via_router: ADDR_2A.into(),
                iface: IF_1,
                preferred_until: None,
                expires_at: None,
            })
        });

        // In cidr_2: the /64 wins over the default route.
        assert_eq!(lookup(&routes, ADDR_2B, 0), Some((ADDR_2A.into(), IF_1)));
        // Everything else: the default route.
        assert_eq!(lookup(&routes, ADDR_1B, 0), Some((ADDR_1A.into(), IF_0)));
    }

    #[test]
    fn test_default_route() {
        let mut routes = Routes::new();
        let gw1 = Ipv4Address::new(192, 168, 1, 1);
        let gw2 = Ipv4Address::new(192, 168, 1, 2);

        assert!(routes.get_default_ipv4_route().is_none());
        assert!(routes.add_default_ipv4_route(gw1, IF_0).is_none());

        // Adding a second default route replaces the first.
        let old = routes.add_default_ipv4_route(gw2, IF_1).unwrap();
        assert_eq!(old.via_router, gw1.into());
        let current = routes.get_default_ipv4_route().unwrap();
        assert_eq!(current.via_router, gw2.into());
        assert_eq!(current.iface, IF_1);

        assert!(routes.remove_default_ipv4_route().is_some());
        assert!(routes.get_default_ipv4_route().is_none());
    }

    #[test]
    fn test_purge_iface() {
        let mut routes = Routes::new();
        routes.update(|storage| {
            storage.push(Route {
                cidr: cidr_1().into(),
                via_router: ADDR_1A.into(),
                iface: IF_0,
                preferred_until: None,
                expires_at: None,
            });
            storage.push(Route {
                cidr: cidr_2().into(),
                via_router: ADDR_2A.into(),
                iface: IF_1,
                preferred_until: None,
                expires_at: None,
            });
        });

        routes.purge_iface(IF_0);
        assert_eq!(lookup(&routes, ADDR_1A, 0), None);
        assert_eq!(lookup(&routes, ADDR_2A, 0), Some((ADDR_2A.into(), IF_1)));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Routes {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Routes({=[?]})", self.storage.as_slice());
    }
}
