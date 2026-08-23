//! This is an integration test rather than a unit test because it has to own the
//! whole pool, and unit tests run in parallel threads of one process

use xarxa::iface::{IfaceCapabilities, Interface, Medium};
use xarxa::udp::SendError;
use xarxa::wire::{HardwareAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address};
use xarxa::{PacketBuf, Stack};

/// A device that receives nothing and drops (frees) whatever it is given.
struct NullDevice;

impl Interface for NullDevice {
    fn capabilities(&self) -> IfaceCapabilities {
        let mut caps = IfaceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        None
    }
    fn transmit(&mut self, _buf: PacketBuf) -> Result<(), PacketBuf> {
        Ok(())
    }
    fn can_transmit(&mut self) -> bool {
        true
    }
}

/// One test function, so that every step runs in order on the one pool.
#[test]
fn exhaustion() {
    let mut dev = NullDevice;
    let mut stack = Stack::new(0x1234_5678_dead_beef);
    let iface = stack.add_iface_borrowed(&mut dev, HardwareAddress::Ip).unwrap();
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 24))
        .unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(1234, IpListenEndpoint::UNSPECIFIED).unwrap();
    let dst = IpEndpoint::new(Ipv4Address::new(192, 168, 1, 2).into(), 5678);

    // Sends work while the pool has buffers. The device drops what it is given,
    // so a send leaves the pool as it found it.
    stack.udp_socket(udp).send_slice(b"hello", dst).unwrap();

    // Take every buffer.
    let mut held = Vec::new();
    while let Some(buf) = PacketBuf::try_new() {
        held.push(buf);
    }
    assert!(!held.is_empty());
    assert!(PacketBuf::try_new().is_none());

    // A send now fails, and the socket is unharmed.
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst),
        Err(SendError::NoBuffer)
    );
    assert!(stack.udp_socket(udp).is_open());

    // Freeing one buffer is enough for a send. Taking it back starves sends again.
    drop(held.pop());
    stack.udp_socket(udp).send_slice(b"hello", dst).unwrap();
    held.push(PacketBuf::try_new().unwrap());
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst),
        Err(SendError::NoBuffer)
    );

    // Everything freed: the pool is whole again.
    let count = held.len();
    drop(held);
    let mut again = Vec::new();
    while let Some(buf) = PacketBuf::try_new() {
        again.push(buf);
    }
    assert!(again.len() >= count);
}
