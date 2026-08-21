//! Reusable slots addressed by plain indexes.

use core::fmt;

use super::Full;

/// Reusable slots addressed by plain indexes: a growable list with `alloc`, a
/// plain `[Option<T>; N]` without.
pub(crate) struct Slab<T, const N: usize> {
    #[cfg(feature = "alloc")]
    slots: alloc::vec::Vec<Option<T>>,
    #[cfg(not(feature = "alloc"))]
    slots: [Option<T>; N],
}

impl<T, const N: usize> Slab<T, N> {
    pub const fn new() -> Self {
        #[cfg(feature = "alloc")]
        let slots = alloc::vec::Vec::new();
        #[cfg(not(feature = "alloc"))]
        let slots = [const { None }; N];
        Self { slots }
    }

    /// Add an item, returning its index. Free slots are reused.
    ///
    /// The item is built by calling `f` with the index it is going to get, so that
    /// items can store their own handle. `f` is not called if there is no room.
    pub fn add_with(&mut self, f: impl FnOnce(usize) -> T) -> Result<usize, Full> {
        if let Some((index, slot)) = self.slots.iter_mut().enumerate().find(|(_, slot)| slot.is_none()) {
            *slot = Some(f(index));
            return Ok(index);
        }
        #[cfg(feature = "alloc")]
        {
            let index = self.slots.len();
            self.slots.push(Some(f(index)));
            Ok(index)
        }
        #[cfg(not(feature = "alloc"))]
        {
            Err(Full)
        }
    }

    /// Whether `add_with` would fail.
    pub fn is_full(&self) -> bool {
        #[cfg(feature = "alloc")]
        {
            false
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.slots.iter().all(|slot| slot.is_some())
        }
    }

    /// Remove the item at `index`, returning it.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn remove(&mut self, index: usize) -> T {
        self.slots[index].take().expect("no item at this index")
    }

    /// Get a reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get(&self, index: usize) -> &T {
        self.slots[index].as_ref().expect("no item at this index")
    }

    /// Get a mutable reference to the item at `index`.
    ///
    /// # Panics
    /// Panics if the slot at `index` is empty.
    pub fn get_mut(&mut self, index: usize) -> &mut T {
        self.slots[index].as_mut().expect("no item at this index")
    }

    /// Index of the first occupied slot at or after `from`, if any.
    pub fn next_occupied(&self, from: usize) -> Option<usize> {
        let slots = self.slots.get(from..)?;
        slots.iter().position(|slot| slot.is_some()).map(|i| from + i)
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|item| (index, item)))
    }

    /// Iterate over all occupied slots, with their indexes.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> {
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_mut().map(|item| (index, item)))
    }
}

impl<T, const N: usize> Default for Slab<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Slab<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_slab_add_remove_reuse() {
        let mut slab: Slab<usize, 8> = Slab::new();
        assert_eq!(slab.add_with(|i| i * 10), Ok(0));
        assert_eq!(slab.add_with(|i| i * 10), Ok(1));
        assert_eq!(slab.add_with(|i| i * 10), Ok(2));

        assert_eq!(slab.remove(1), 10);

        // The freed slot is reused.
        assert_eq!(slab.add_with(|i| i * 10), Ok(1));
        assert_eq!(slab.add_with(|i| i * 10), Ok(3));

        let items: std::vec::Vec<_> = slab.iter_mut().map(|(i, item)| (i, *item)).collect();
        assert_eq!(items, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
    }

    #[test]
    #[should_panic]
    fn test_slab_remove_empty_slot() {
        let mut slab: Slab<u32, 8> = Slab::new();
        slab.add_with(|_| 1u32).unwrap();
        slab.remove(0);
        slab.remove(0);
    }

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn test_slab_full() {
        let mut slab: Slab<usize, 2> = Slab::new();
        assert_eq!(slab.add_with(|i| i), Ok(0));
        assert!(!slab.is_full());
        assert_eq!(slab.add_with(|i| i), Ok(1));
        assert!(slab.is_full());
        assert_eq!(slab.add_with(|i| i), Err(Full));
        slab.remove(0);
        assert!(!slab.is_full());
        assert_eq!(slab.add_with(|i| i), Ok(0));
    }
}
