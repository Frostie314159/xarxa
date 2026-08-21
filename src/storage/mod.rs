//! The stack's storage: growable containers with a compile-time bound.
//!
//! This is where the `alloc` feature is decided. With it, [`Vec`] and [`Slab`]
//! grow on the heap and their bound `N` is ignored; without it they hold at most
//! `N` items inline. [`BoundedVec`] and [`BoundedDeque`] hold at most `N` items
//! in both modes: their bound is a policy (how many neighbors to remember, how
//! much a slow consumer may pin), not an allocator limitation, and keeping it the
//! same in both modes means the full-table paths are exercised by the hosted
//! tests.
//!
//! The bounds come from the knobs in `crate::config`.

// Which methods are used depends on the enabled features; the unused ones are
// not worth a `#[cfg]` each.
#![allow(dead_code)]

use core::fmt;

mod bounded_deque;
mod bounded_vec;
mod slab;
mod vec;

// Which containers are used depends on the enabled features.
#[allow(unused_imports)]
pub(crate) use bounded_deque::BoundedDeque;
#[allow(unused_imports)]
pub(crate) use bounded_vec::BoundedVec;
#[allow(unused_imports)]
pub(crate) use slab::Slab;
#[allow(unused_imports)]
pub(crate) use vec::Vec;

/// A table, slab or queue has no room for another item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Full;

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("full")
    }
}

impl core::error::Error for Full {}
