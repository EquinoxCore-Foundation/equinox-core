#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};

use crate::types::{OutPoint, UtxoEntry};

/// Strict memory-bounded LRU cache preventing unbounded RAM growth under heavy IOPS.
pub struct BoundedUtxoCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<OutPoint, (UtxoEntry, u64)>,
    lru_order: BTreeMap<u64, OutPoint>,
}

impl BoundedUtxoCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::with_capacity(capacity.min(65_536)),
            lru_order: BTreeMap::new(),
        }
    }

    pub fn get(&mut self, key: &OutPoint) -> Option<UtxoEntry> {
        let (entry, old_tick) = *self.entries.get(key)?;
        self.lru_order.remove(&old_tick);
        self.tick = self.tick.wrapping_add(1);
        self.entries.insert(*key, (entry, self.tick));
        self.lru_order.insert(self.tick, *key);
        Some(entry)
    }

    pub fn put(&mut self, key: OutPoint, value: UtxoEntry) {
        if self.capacity == 0 {
            return;
        }
        if let Some((_, old_tick)) = self.entries.get(&key).copied() {
            self.lru_order.remove(&old_tick);
        } else if self.entries.len() >= self.capacity {
            if let Some((_, oldest_key)) = self.lru_order.pop_first() {
                self.entries.remove(&oldest_key);
            }
        }
        self.tick = self.tick.wrapping_add(1);
        self.entries.insert(key, (value, self.tick));
        self.lru_order.insert(self.tick, key);
    }

    pub fn remove(&mut self, key: &OutPoint) {
        if let Some((_, old_tick)) = self.entries.remove(key) {
            self.lru_order.remove(&old_tick);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
