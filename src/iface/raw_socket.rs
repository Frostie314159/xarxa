#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::buf::PacketBuf;
use crate::iface::{IfaceCapabilities, Interface, Medium};

const SIOCGIFMTU: libc::c_ulong = 0x8921;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;
#[cfg(feature = "medium-ethernet")]
const ETH_P_ALL: libc::c_short = 0x0003;
#[cfg(feature = "medium-ieee802154")]
const ETH_P_IEEE802154: libc::c_short = 0x00F6;

#[repr(C)]
#[derive(Debug)]
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}

fn ifreq_for(name: &str) -> ifreq {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_data: 0,
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }
    ifreq
}

fn ifreq_ioctl(lower: libc::c_int, ifreq: &mut ifreq, cmd: libc::c_ulong) -> io::Result<libc::c_int> {
    unsafe {
        let res = libc::ioctl(lower, cmd as _, ifreq as *mut ifreq);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(ifreq.ifr_data)
}

/// A packet socket bound to a host interface, sending and receiving whole frames.
///
/// Ethernet interfaces carry Ethernet frames ([`Medium::Ethernet`]), `wpan`
/// interfaces carry IEEE 802.15.4 frames ([`Medium::Ieee802154`]). Linux and
/// Android only.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct RawSocketInterface {
    lower: libc::c_int,
    mtu: usize,
    medium: Medium,
}

impl AsRawFd for RawSocketInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.lower
    }
}

impl RawSocketInterface {
    /// Open a packet socket bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    ///
    /// Errors:
    /// - the OS error if the socket cannot be opened or bound, or the
    ///   interface does not exist.
    /// - `Unsupported` for [`Medium::Ip`].
    pub fn new(name: &str, medium: Medium) -> io::Result<RawSocketInterface> {
        let protocol = match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => ETH_P_ALL,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => ETH_P_IEEE802154,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "packet sockets carry link-layer frames, not bare IP packets",
                ));
            }
        };

        let lower = unsafe {
            let lower = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                protocol.to_be() as i32,
            );
            if lower == -1 {
                return Err(io::Error::last_os_error());
            }
            lower
        };

        let mut iface = RawSocketInterface { lower, mtu: 0, medium };
        let mut ifreq = ifreq_for(name);

        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol.to_be() as u16,
            sll_ifindex: ifreq_ioctl(lower, &mut ifreq, SIOCGIFINDEX)?,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        unsafe {
            let res = libc::bind(
                lower,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let mtu = ifreq_ioctl(lower, &mut ifreq, SIOCGIFMTU)? as usize;
        iface.mtu = match medium {
            // SIOCGIFMTU returns the IP MTU (typically 1500 bytes.)
            // xarxa counts the entire Ethernet packet in the MTU, so add the Ethernet header size to it.
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => mtu + crate::wire::ETHERNET_HEADER_LEN,
            // SIOCGIFMTU returns 127 - (ACK_PSDU - FCS - 1) - FCS.
            //                    127 - (5 - 2 - 1) - 2 = 123
            // For IEEE802154, we want to add (ACK_PSDU - FCS - 1), since that is what SIOCGIFMTU
            // uses as the size of the link layer header.
            //
            // https://github.com/torvalds/linux/blob/7475e51b87969e01a6812eac713a1c8310372e8a/net/mac802154/iface.c#L541
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => mtu + 2,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => unreachable!(),
        };

        Ok(iface)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(self.lower, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0);
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::send(self.lower, buffer.as_ptr() as *const libc::c_void, buffer.len(), 0);
            if len == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for RawSocketInterface {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.lower);
        }
    }
}

impl Interface for RawSocketInterface {
    fn capabilities(&self) -> IfaceCapabilities {
        IfaceCapabilities {
            medium: self.medium,
            max_transmission_unit: self.mtu,
        }
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let mut buf = PacketBuf::try_new()?;
        buf.set_len(buf.capacity());
        match self.recv(&mut buf[..]) {
            Ok(size) => {
                buf.set_len(size);
                Some(buf)
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
            Err(err) => core::panic!("{}", err),
        }
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        match self.send(&buf) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                debug!("phy: tx failed due to WouldBlock");
                Err(buf)
            }
            Err(err) => core::panic!("{}", err),
        }
    }

    fn can_transmit(&mut self) -> bool {
        true
    }
}
