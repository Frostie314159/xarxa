//! Owned packet buffers.

use core::fmt;
use std::ops::{Deref, DerefMut};

/// Size of the buffer in a [`PacketBuf`].
///
/// This is the maximum size of an Ethernet frame: 14 bytes of header plus 1500 bytes of
/// payload. (The 4-byte FCS is not counted, it is typically added/checked/stripped by
/// hardware.)
pub const PACKET_BUF_SIZE: usize = 1514;

struct PacketBufInner {
    /// Offset of the first valid byte within `data`.
    headroom: u16,
    /// Number of valid bytes.
    len: u16,
    // invariant: headroom + len <= PACKET_BUF_SIZE
    data: [u8; PACKET_BUF_SIZE],
}

/// An owned network packet buffer.
///
/// ```text
/// | headroom | data (len) | tailroom |
/// ```
///
/// Currently allocated with `Box`; this will move to a static pool for no-std/no-alloc
/// targets later.
pub struct PacketBuf {
    inner: Box<PacketBufInner>,
}

impl PacketBuf {
    /// Allocate a new, empty packet buffer with zero headroom.
    pub fn new() -> Self {
        Self {
            inner: Box::new(PacketBufInner {
                headroom: 0,
                len: 0,
                data: [0; PACKET_BUF_SIZE],
            }),
        }
    }

    /// Total storage capacity of the buffer, in bytes.
    pub const fn capacity(&self) -> usize {
        PACKET_BUF_SIZE
    }

    /// Amount of free space in front of the payload.
    pub fn headroom(&self) -> usize {
        self.inner.headroom as usize
    }

    /// Length of the payload.
    pub fn len(&self) -> usize {
        self.inner.len as usize
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
    }

    /// Amount of free space behind the payload.
    pub fn tailroom(&self) -> usize {
        PACKET_BUF_SIZE - self.headroom() - self.len()
    }

    /// Set the headroom on an empty buffer, before writing a payload.
    ///
    /// # Panics
    /// Panics if the buffer is not empty, or if `headroom > capacity`.
    pub fn reserve(&mut self, headroom: usize) {
        assert!(self.inner.len == 0);
        assert!(headroom <= PACKET_BUF_SIZE);
        self.inner.headroom = headroom as u16;
    }

    /// Grow the payload at the front by `n` bytes, taking them from the headroom.
    ///
    /// # Panics
    /// Panics if `n > headroom`.
    pub fn push_front(&mut self, n: usize) {
        assert!(n <= self.headroom());
        self.inner.headroom -= n as u16;
        self.inner.len += n as u16;
    }

    /// Shrink the payload at the front by `n` bytes, returning them to the headroom.
    ///
    /// # Panics
    /// Panics if `n > len`.
    pub fn pull_front(&mut self, n: usize) {
        assert!(n <= self.len());
        self.inner.headroom += n as u16;
        self.inner.len -= n as u16;
    }

    /// Set the payload length, growing or shrinking it at the back.
    ///
    /// # Panics
    /// Panics if `headroom + len > capacity`.
    pub fn set_len(&mut self, len: usize) {
        assert!(self.headroom() + len <= PACKET_BUF_SIZE);
        self.inner.len = len as u16;
    }
}

impl Default for PacketBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PacketBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        let start = self.inner.headroom as usize;
        let end = start + self.inner.len as usize;
        &self.inner.data[start..end]
    }
}
impl DerefMut for PacketBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let start = self.inner.headroom as usize;
        let end = start + self.inner.len as usize;
        &mut self.inner.data[start..end]
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("headroom", &self.headroom())
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pull() {
        let mut buf = PacketBuf::new();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.headroom(), 0);
        assert_eq!(buf.tailroom(), PACKET_BUF_SIZE);

        buf.reserve(42);
        assert_eq!(buf.headroom(), 42);
        buf.set_len(100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.tailroom(), PACKET_BUF_SIZE - 142);
        buf.fill(0xaa);

        buf.push_front(20);
        assert_eq!(buf.headroom(), 22);
        assert_eq!(buf.len(), 120);
        assert_eq!(buf[20], 0xaa);

        buf.pull_front(20);
        assert_eq!(buf.headroom(), 42);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf[0], 0xaa);
    }

    #[test]
    #[should_panic]
    fn push_beyond_headroom() {
        let mut buf = PacketBuf::new();
        buf.push_front(1);
    }
}
