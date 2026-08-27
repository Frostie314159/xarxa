/*! Driver implementations for the host OS.

These are [`Driver`](crate::driver::Driver) implementations for Linux and other
unix-like hosts, for running the stack on a PC:

  * [TunTapDriver], a virtual TUN/TAP interface;
  * [RawSocketDriver], a packet socket bound to an existing interface (Ethernet
    or IEEE 802.15.4).

Both need the `std` feature.
*/

#![allow(unsafe_code)]

#[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
mod tuntap;

#[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
pub use self::tuntap::TunTapDriver;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
mod raw_socket;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(feature = "medium-ethernet", feature = "medium-ieee802154")
))]
pub use self::raw_socket::RawSocketDriver;

/// Wait until given file descriptor becomes readable, but no longer than given timeout.
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
