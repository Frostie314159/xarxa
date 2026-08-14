//! TCP echo server: bring up a TUN/TAP interface and echo back everything
//! received on TCP port 6969.
//!
//! There is no listen backlog: a single socket serves one connection at a time,
//! and goes back to listening when the connection closes.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example tcp_server -- tap0        # TAP (Ethernet medium)
//! cargo run --example tcp_server -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! nc 192.168.69.1 6969
//! nc fdaa::1 6969
//! ```

use std::os::unix::io::AsRawFd;

use xarxa::iface::{Medium, TunTapInterface, wait};
use xarxa::stack::{Config, Stack};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

const PORT: u16 = 6969;

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

    let mut stack = Stack::new();
    let iface = stack.add_iface(
        Box::new(device),
        Config {
            hardware_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ip_addrs: vec![
                IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
                IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
                IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
            ],
        },
    );

    // Off-link traffic routes to the host's address on this interface.
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 100), iface);

    let tcp_handle = stack.add_tcp_socket(4096, 4096);
    let mut buf = [0u8; 1024];

    let mut was_active = false;
    loop {
        let deadline = stack.poll(Instant::now());

        let mut socket = stack.tcp(tcp_handle);

        if socket.is_active() && !was_active {
            log::info!("tcp: connection from {}", socket.remote_endpoint().unwrap());
        } else if !socket.is_active() && was_active {
            log::info!("tcp: connection closed");
        }
        was_active = socket.is_active();

        // A closed socket (initially, or after a connection ends) goes back to
        // listening.
        if !socket.is_open() {
            log::info!("tcp: listening on port {PORT}");
            socket.listen(PORT).unwrap();
        }

        // Echo: move bytes from the receive buffer to the transmit buffer,
        // dequeueing no more than the transmit buffer has room for.
        while socket.can_recv() && socket.can_send() {
            let free = socket.send_capacity() - socket.send_queue();
            let len = buf.len().min(free);
            let len = socket.recv_slice(&mut buf[..len]).unwrap();
            socket.send_slice(&buf[..len]).unwrap();
        }

        // The remote endpoint closed its transmit half and everything received
        // has been echoed back: close ours too.
        if !socket.may_recv() && socket.may_send() {
            socket.close();
        }

        let timeout = deadline.map(|deadline| {
            let now = Instant::now();
            if deadline <= now {
                std::time::Duration::ZERO
            } else {
                (deadline - now).into()
            }
        });
        wait(fd, timeout).unwrap();
    }
}
