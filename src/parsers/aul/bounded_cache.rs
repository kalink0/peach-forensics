use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

use macos_unifiedlogs::traits::Cache;

/// A size-capped [`Cache`] backend for `macos_unifiedlogs::cache::MemoryStringCache`.
///
/// The crate's own default (`MemoryStringCache::default()`) backs both the
/// `uuidtext` and `dsc` caches with a plain, unbounded `HashMap` — its own
/// docs call this out explicitly, since `dsc` (shared-cache-strings) files
/// alone run 30-150MB each. Growing that without a cap across a whole
/// `.logarchive` parse is exactly the failure mode behind a real earlier
/// incident where an AUL import's memory usage grew far past the size of the
/// source data (see this module's parent doc comment). This cache is this
/// project's replacement for the hand-rolled eviction it used to do itself
/// against the pre-0.7 `FileProvider::update_uuid`/`update_dsc` methods,
/// which the crate has since removed in favor of the pluggable `Cache` trait
/// used here.
///
/// Eviction is deliberately simple — once at capacity, drop one arbitrary
/// existing entry before inserting the new one — rather than true LRU: a
/// cache miss here only costs a re-read/re-parse of the backing uuidtext/dsc
/// file, never a wrong or missing result, so there's nothing forensically at
/// stake in which entry gets evicted.
pub struct BoundedCache<V> {
    entries: Mutex<HashMap<String, V>>,
    capacity: usize,
}

impl<V> BoundedCache<V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl<V: Clone> Cache<String, V> for BoundedCache<V> {
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        String: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        // A poisoned lock is treated as a cache miss rather than propagated:
        // the caller falls back to reading the backing file again, so a
        // poisoned mutex costs performance, never a wrong or dropped result.
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn insert(&self, key: String, value: V) -> Option<V> {
        let mut entries = self.entries.lock().ok()?;
        if entries.len() >= self.capacity
            && !entries.contains_key(&key)
            && let Some(evict_key) = entries.keys().next().cloned()
        {
            entries.remove(&evict_key);
        }
        entries.insert(key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_an_absent_key() {
        let cache: BoundedCache<u32> = BoundedCache::new(2);
        assert_eq!(cache.get("missing"), None);
    }

    #[test]
    fn insert_then_get_round_trips_a_value() {
        let cache = BoundedCache::new(2);
        cache.insert("a".to_string(), 1);
        assert_eq!(cache.get("a"), Some(1));
    }

    #[test]
    fn insert_over_capacity_evicts_something_and_keeps_the_new_entry() {
        let cache = BoundedCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.insert("c".to_string(), 3);

        assert_eq!(cache.get("c"), Some(3));
        let remaining = [cache.get("a"), cache.get("b"), cache.get("c")]
            .into_iter()
            .filter(Option::is_some)
            .count();
        assert_eq!(remaining, 2, "capacity of 2 must never be exceeded");
    }

    #[test]
    fn re_inserting_an_existing_key_does_not_evict_to_make_room() {
        let cache = BoundedCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.insert("a".to_string(), 10);

        assert_eq!(cache.get("a"), Some(10));
        assert_eq!(cache.get("b"), Some(2));
    }
}
