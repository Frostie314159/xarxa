//! This is an integration test rather than a unit test because it has to own the
//! whole pool, and unit tests run in parallel threads of one process

use xarxa::Stack;
use xarxa::driver::PacketBuf;
use xarxa::iface::Medium;
use xarxa::udp::SendError;
use xarxa::wire::{HardwareAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address};

use test_device::TestDevice;

// The mock device the library's own unit tests use. It lives in `src/` so that both
// can share it; it is written against the public API, so including it here works.
#[path = "../src/test_device.rs"]
mod test_device;

/// One test function, so that every step runs in order on the one pool.
#[test]
fn exhaustion() {
    let mut stack = Stack::new(0x1234_5678_dead_beef);
    // The device copies out and drops (frees) whatever it is given.
    let iface = TestDevice::new(Medium::Ip).install(&mut stack, HardwareAddress::Ip);
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
