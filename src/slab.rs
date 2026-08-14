//! Vector of reusable slots addressed by plain indexes.

pub(crate) struct Slab<T> {
    slots: Vec<Option<T>>,
}

impl<T> Slab<T> {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Add an item, returning its index. Free slots are reused.
    ///
    /// The item is built by calling `f` with the index it is going to get, so that
    /// items can store their own handle.
    pub fn add_with(&mut self, f: impl FnOnce(usize) -> T) -> usize {
        match self.slots.iter_mut().enumerate().find(|(_, slot)| slot.is_none()) {
            Some((index, slot)) => {
                *slot = Some(f(index));
                index
            }
            None => {
                let index = self.slots.len();
                self.slots.push(Some(f(index)));
                index
            }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_remove_reuse() {
        let mut slab = Slab::new();
        assert_eq!(slab.add_with(|i| i * 10), 0);
        assert_eq!(slab.add_with(|i| i * 10), 1);
        assert_eq!(slab.add_with(|i| i * 10), 2);

        assert_eq!(slab.remove(1), 10);

        // The freed slot is reused.
        assert_eq!(slab.add_with(|i| i * 10), 1);
        assert_eq!(slab.add_with(|i| i * 10), 3);

        let items: Vec<_> = slab.iter_mut().map(|(i, item)| (i, *item)).collect();
        assert_eq!(items, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
    }

    #[test]
    #[should_panic]
    fn test_remove_empty_slot() {
        let mut slab = Slab::new();
        slab.add_with(|_| 1u32);
        slab.remove(0);
        slab.remove(0);
    }
}
