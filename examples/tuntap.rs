//! Bare minimum example: bring up a TUN/TAP interface and reply to pings.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example tuntap -- tap0        # TAP (Ethernet medium)
//! cargo run --example tuntap -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! ping 192.168.69.1
//! ping fdaa::1
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::phy::{Medium, TunTapInterface, wait};
use xarxa::stack::{Config, Stack};
use xarxa::wire::{EthernetAddress, IpAddress, IpCidr};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let medium = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        Medium::Ip
    } else {
        Medium::Ethernet
    };
    let name = args.first().map(String::as_str).unwrap_or("tap0");

    let device = TunTapInterface::new(name, medium).unwrap();
    let fd = device.as_raw_fd();

    let config = Config {
        hardware_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        ip_addrs: vec![
            IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
            IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
        ],
    };

    let mut stack = Stack::new(config);
    stack.add_phy(Box::new(device));

    loop {
        stack.poll();
        wait(fd, None).unwrap();
    }
}
