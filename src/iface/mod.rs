/*! Network interfaces.

The `iface` module deals with the *network devices*. It provides the [Interface] trait, which
drivers implement to exchange owned [`PacketBuf`]s with the stack:

  * on receive, the driver hands a filled buffer up to the stack;
  * on transmit, the stack hands a built frame down to the driver, which owns the buffer
    until the hardware is done with it, then drops it.

This module provides one implementation of [Interface]: the [TunTapInterface], to transmit and
receive frames on the host OS.
*/

use crate::buf::PacketBuf;

#[cfg(feature = "std")]
mod tuntap;

#[cfg(feature = "std")]
pub use self::tuntap::TunTapInterface;

/// Type of medium of an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames.
    Ethernet,

    /// IP medium. Devices of this type send and receive IP frames, without an
    /// Ethernet header. MAC addresses are not used.
    Ip,
}

/// A description of iface capabilities.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IfaceCapabilities {
    /// Medium of the iface.
    pub medium: Medium,

    /// Maximum transmission unit.
    ///
    /// The network device is unable to send or receive frames larger than the value returned
    /// by this function.
    pub max_transmission_unit: usize,
}

/// An interface for sending and receiving raw network frames.
pub trait Interface {
    /// Get a description of iface capabilities.
    fn capabilities(&self) -> IfaceCapabilities;

    /// Poll for a received frame.
    ///
    /// Returns a buffer holding the received frame if one is available, transferring
    /// ownership of it to the caller.
    fn receive(&mut self) -> Option<PacketBuf>;

    /// Queue a frame for transmission, transferring ownership of the buffer to the iface.
    ///
    /// The iface holds the buffer until the hardware is done with it, then drops it.
    /// If the frame cannot be queued right now (device busy or queue full), the buffer
    /// is handed back in the `Err` variant.
    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf>;
}

/// Wait until given file descriptor becomes readable, but no longer than given timeout.
#[cfg(feature = "std")]
pub fn wait(fd: std::os::unix::io::RawFd, duration: Option<std::time::Duration>) -> std::io::Result<()> {
    use std::{io, mem, ptr};

    unsafe {
        let mut readfds = {
            let mut readfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(readfds.as_mut_ptr());
            libc::FD_SET(fd, readfds.as_mut_ptr());
            readfds.assume_init()
        };

        let mut writefds = {
            let mut writefds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(writefds.as_mut_ptr());
            writefds.assume_init()
        };

        let mut exceptfds = {
            let mut exceptfds = mem::MaybeUninit::<libc::fd_set>::uninit();
            libc::FD_ZERO(exceptfds.as_mut_ptr());
            exceptfds.assume_init()
        };

        let mut timeout = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let timeout_ptr = if let Some(duration) = duration {
            timeout.tv_sec = duration.as_secs() as libc::time_t;
            timeout.tv_usec = duration.subsec_micros() as libc::suseconds_t;
            &mut timeout as *mut _
        } else {
            ptr::null_mut()
        };

        let res = libc::select(fd + 1, &mut readfds, &mut writefds, &mut exceptfds, timeout_ptr);
        if res == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
