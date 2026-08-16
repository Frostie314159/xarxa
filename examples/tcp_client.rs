//! TCP client: bring up a TUN/TAP interface, connect to a remote endpoint, send
//! a greeting, and print everything received until the remote end closes the
//! connection.
//!
//! On the host, set up the interface and listen for the connection:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! nc -l 1234
//! ```
//!
//! Then run (the remote endpoint defaults to 192.168.69.100:1234):
//!
//! ```sh
//! cargo run --example tcp_client -- tap0        # TAP (Ethernet medium)
//! cargo run --example tcp_client -- --tun tun0  # TUN (IP medium)
//! cargo run --example tcp_client -- tap0 '[fdaa::100]:1234'
//! ```
//!
//! Anything typed into `nc` is printed by the client. Closing `nc` (ctrl-C) closes
//! the connection and exits the client.

use std::io::Write as _;
use std::os::unix::io::AsRawFd;

use xarxa::iface::{Medium, TunTapInterface, wait};
use xarxa::stack::{Config, Stack};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

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
    let remote: IpEndpoint = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("192.168.69.100:1234")
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into();

    let device = TunTapInterface::new(name, medium).unwrap();
    let fd = device.as_raw_fd();

    let mut stack = Stack::new(random_seed());
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

    // Local port 0: the stack allocates an ephemeral port.
    let mut socket = stack.tcp(tcp_handle);
    socket.connect(remote, 0).unwrap();
    log::info!("tcp: connecting to {remote} from {}", socket.local_endpoint().unwrap());

    let mut greeting_sent = false;
    loop {
        let deadline = stack.poll(Instant::now());

        let mut socket = stack.tcp(tcp_handle);

        if !socket.is_active() {
            log::info!("tcp: connection closed");
            break;
        }

        if !greeting_sent && socket.can_send() {
            socket.send_slice(b"Hello over TCP from xarxa!\n").unwrap();
            greeting_sent = true;
        }

        while socket.can_recv() {
            socket
                .recv(|data| {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    stdout.write_all(data).unwrap();
                    stdout.flush().unwrap();
                    (data.len(), ())
                })
                .unwrap();
        }

        // The remote endpoint closed its transmit half: close ours too.
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

/// Quick-and-dirty entropy for the example's PRNG seed. Real firmware should
/// use a hardware RNG or another unpredictable source.
fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
