//! A `Box<T>` or a `&'d mut T`, behind one pointer-shaped type.

use core::fmt;
use core::ops::{Deref, DerefMut};

/// Something the user gave the stack: a `&'d mut T` lent for the stack's
/// lifetime, or with `alloc` a `Box<T>` the stack owns.
///
/// This is what holds the interfaces' drivers and the TCP sockets' ring buffer
/// storage, the two things the stack does not allocate itself. Without `alloc`
/// it has one variant and is just the `&'d mut T`; with it, both variants are
/// one fat pointer at the same offset, so the deref folds to a load.
pub(crate) struct MaybeBox<'d, T: ?Sized> {
    inner: Inner<'d, T>,
}

enum Inner<'d, T: ?Sized> {
    Borrowed(&'d mut T),
    #[cfg(feature = "alloc")]
    Owned(alloc::boxed::Box<T>),
}

impl<T: ?Sized> Deref for MaybeBox<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        match &self.inner {
            Inner::Borrowed(r) => r,
            #[cfg(feature = "alloc")]
            Inner::Owned(b) => b,
        }
    }
}

impl<T: ?Sized> DerefMut for MaybeBox<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.inner {
            Inner::Borrowed(r) => r,
            #[cfg(feature = "alloc")]
            Inner::Owned(b) => b,
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MaybeBox<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(feature = "defmt")]
impl<T: ?Sized + defmt::Format> defmt::Format for MaybeBox<'_, T> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::Format::format(&**self, f)
    }
}

impl<'d, T: ?Sized> From<&'d mut T> for MaybeBox<'d, T> {
    #[inline]
    fn from(r: &'d mut T) -> Self {
        Self {
            inner: Inner::Borrowed(r),
        }
    }
}

#[cfg(feature = "alloc")]
impl<'d, T: ?Sized> From<alloc::boxed::Box<T>> for MaybeBox<'d, T> {
    #[inline]
    fn from(b: alloc::boxed::Box<T>) -> Self {
        Self { inner: Inner::Owned(b) }
    }
}

#[cfg(feature = "alloc")]
impl<'d, T> From<alloc::vec::Vec<T>> for MaybeBox<'d, [T]> {
    #[inline]
    fn from(v: alloc::vec::Vec<T>) -> Self {
        Self {
            inner: Inner::Owned(v.into_boxed_slice()),
        }
    }
}
