use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::traits::{FileProvider, StringCache};
use macos_unifiedlogs::uuidtext::UUIDText;

/// Byte budget for parsed `uuidtext` files. Individual files are small
/// (kilobytes to a few MB), but a real `.logarchive` references thousands
/// of them and interleaves entries from many processes, so the budget must
/// hold the whole working set — a real 817 MB iOS archive's entire uuidtext
/// tree is 59 MB across 2,124 files.
const UUIDTEXT_BUDGET_BYTES: usize = 512 * 1024 * 1024;

/// Byte budget for parsed `dsc` (shared-cache-strings) files, which run
/// 30-150 MB each. Blob for a handful of them at once rather than all of
/// them, since an archive spanning several OS updates carries one per
/// shared-cache build and those are the files behind the earlier AUL
/// memory-blowup incident (see the parent module's doc comment).
const DSC_BUDGET_BYTES: usize = 512 * 1024 * 1024;

/// Approximate heap size of a parsed value, used to keep each cache within
/// its byte budget. Counts the payload buffers that dominate real files, not
/// every struct header — the budget is a memory ceiling, not an exact
/// accounting.
pub trait Weight {
    fn weight(&self) -> usize;
}

impl Weight for UUIDText {
    fn weight(&self) -> usize {
        self.footer_data.len() + self.entry_descriptors.len() * size_of::<u64>() + self.uuid.len()
    }
}

impl Weight for SharedCacheStrings {
    fn weight(&self) -> usize {
        let ranges: usize = self
            .ranges
            .iter()
            .map(|range| range.strings.len() + size_of_val(range))
            .sum();
        let uuids: usize = self
            .uuids
            .iter()
            .map(|uuid| uuid.uuid.len() + uuid.path_string.len() + size_of_val(uuid))
            .sum();
        ranges + uuids + self.dsc_uuid.len()
    }
}

/// The [`StringCache`] used for every AUL parse.
///
/// The crate looks up a `uuidtext`/`dsc` file through this cache once per
/// log entry, so a miss means re-opening, re-reading and re-parsing that
/// file. The crate's own `MemoryStringCache::default()` avoids that with an
/// unbounded `HashMap`, which lets `dsc` files (30-150 MB each) pile up
/// without limit. A small count-capped cache (30 uuidtext / 2 dsc entries)
/// avoids that but thrashes instead: entries from many processes interleave,
/// so files keep getting evicted and re-read, which is cheap on Linux
/// (page cache) but slow wherever opening a file is expensive, such as on
/// Windows with real-time antivirus scanning. Byte-budgeted LRU caches keep
/// the working set resident while still capping memory.
///
/// Files that fail to load are remembered as missing and not retried: the
/// lookup would fail the same way every time on read-only evidence, and the
/// affected entries surface as unresolved strings either way — only the
/// number of repeated failing file opens changes.
pub struct BoundedStringCache {
    uuidtext: LruCache<UUIDText>,
    dsc: LruCache<SharedCacheStrings>,
}

impl BoundedStringCache {
    pub fn new() -> Self {
        Self {
            uuidtext: LruCache::new(UUIDTEXT_BUDGET_BYTES),
            dsc: LruCache::new(DSC_BUDGET_BYTES),
        }
    }
}

impl StringCache for BoundedStringCache {
    fn get_or_load_uuidtext(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<UUIDText>> {
        self.uuidtext
            .get_or_load(uuid, || provider.read_uuidtext(uuid).ok())
    }

    fn get_or_load_dsc(
        &self,
        uuid: &str,
        provider: &impl FileProvider,
    ) -> Option<Arc<SharedCacheStrings>> {
        self.dsc
            .get_or_load(uuid, || provider.read_dsc_uuid(uuid).ok())
    }
}

/// A least-recently-used cache capped by the total [`Weight`] of its values,
/// which also remembers keys whose load failed.
struct LruCache<V> {
    state: Mutex<LruState<V>>,
    budget: usize,
}

struct LruState<V> {
    entries: HashMap<String, LruEntry<V>>,
    missing: HashSet<String>,
    total_weight: usize,
    clock: u64,
}

struct LruEntry<V> {
    value: Arc<V>,
    weight: usize,
    last_used: u64,
}

impl<V: Weight> LruCache<V> {
    fn new(budget: usize) -> Self {
        Self {
            state: Mutex::new(LruState {
                entries: HashMap::new(),
                missing: HashSet::new(),
                total_weight: 0,
                clock: 0,
            }),
            budget,
        }
    }

    /// Returns the cached value for `key`, calling `load` only if `key` is
    /// neither cached nor already known to be missing. The lock is not held
    /// while `load` runs, so file I/O never blocks other lookups. A poisoned
    /// lock bypasses the cache rather than failing the lookup: it can cost
    /// extra file reads, never a wrong or dropped result.
    fn get_or_load(&self, key: &str, load: impl FnOnce() -> Option<V>) -> Option<Arc<V>> {
        if let Ok(mut state) = self.state.lock() {
            state.clock += 1;
            let now = state.clock;
            if let Some(entry) = state.entries.get_mut(key) {
                entry.last_used = now;
                return Some(Arc::clone(&entry.value));
            }
            if state.missing.contains(key) {
                return None;
            }
        }

        let Some(value) = load() else {
            if let Ok(mut state) = self.state.lock() {
                state.missing.insert(key.to_string());
            }
            return None;
        };
        let value = Arc::new(value);
        if let Ok(mut state) = self.state.lock() {
            self.insert(&mut state, key, Arc::clone(&value));
        }
        Some(value)
    }

    /// Evicts least-recently-used entries until `value` fits the budget. A
    /// single value larger than the whole budget is still kept (alone), since
    /// refusing it would make every later lookup of it re-read the file.
    fn insert(&self, state: &mut LruState<V>, key: &str, value: Arc<V>) {
        let weight = value.weight();
        if let Some(old) = state.entries.remove(key) {
            state.total_weight -= old.weight;
        }
        while !state.entries.is_empty() && state.total_weight + weight > self.budget {
            let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(evicted) = state.entries.remove(&oldest) {
                state.total_weight -= evicted.weight;
            }
        }
        state.clock += 1;
        let last_used = state.clock;
        state.total_weight += weight;
        state.entries.insert(
            key.to_string(),
            LruEntry {
                value,
                weight,
                last_used,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct Blob(usize);

    impl Weight for Blob {
        fn weight(&self) -> usize {
            self.0
        }
    }

    fn cached(cache: &LruCache<Blob>, key: &str) -> bool {
        cache.state.lock().unwrap().entries.contains_key(key)
    }

    #[test]
    fn a_hit_does_not_call_the_loader_again() {
        let cache = LruCache::new(100);
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Some(Blob(10))
        };

        assert!(cache.get_or_load("a", load).is_some());
        assert!(cache.get_or_load("a", load).is_some());
        assert_eq!(loads.get(), 1);
    }

    #[test]
    fn a_failed_load_is_remembered_and_not_retried() {
        let cache: LruCache<Blob> = LruCache::new(100);
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            None
        };

        assert!(cache.get_or_load("missing", load).is_none());
        assert!(cache.get_or_load("missing", load).is_none());
        assert_eq!(loads.get(), 1);
    }

    #[test]
    fn eviction_drops_the_least_recently_used_entry() {
        let cache = LruCache::new(30);
        cache.get_or_load("a", || Some(Blob(10)));
        cache.get_or_load("b", || Some(Blob(10)));
        cache.get_or_load("c", || Some(Blob(10)));
        // Touch "a" so "b" becomes the least recently used.
        cache.get_or_load("a", || panic!("a is cached"));
        cache.get_or_load("d", || Some(Blob(10)));

        assert!(cached(&cache, "a"));
        assert!(!cached(&cache, "b"));
        assert!(cached(&cache, "c"));
        assert!(cached(&cache, "d"));
    }

    #[test]
    fn total_weight_never_exceeds_the_budget() {
        let cache = LruCache::new(25);
        for key in ["a", "b", "c", "d", "e"] {
            cache.get_or_load(key, || Some(Blob(10)));
            assert!(cache.state.lock().unwrap().total_weight <= 25);
        }
        assert_eq!(cache.state.lock().unwrap().entries.len(), 2);
    }

    #[test]
    fn a_value_larger_than_the_budget_is_still_cached_alone() {
        let cache = LruCache::new(10);
        cache.get_or_load("small", || Some(Blob(5)));
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Some(Blob(50))
        };

        cache.get_or_load("huge", load);
        cache.get_or_load("huge", load);

        assert_eq!(loads.get(), 1);
        assert!(!cached(&cache, "small"));
        assert_eq!(cache.state.lock().unwrap().total_weight, 50);
    }

    #[test]
    fn uuidtext_weight_counts_the_string_payload() {
        let uuidtext = UUIDText {
            footer_data: vec![0; 1000],
            ..Default::default()
        };
        assert!(uuidtext.weight() >= 1000);
    }

    #[test]
    fn dsc_weight_counts_every_range_string_payload() {
        let mut dsc = SharedCacheStrings::default();
        for _ in 0..3 {
            dsc.ranges.push(macos_unifiedlogs::dsc::RangeDescriptor {
                strings: vec![0; 1000],
                ..Default::default()
            });
        }
        assert!(dsc.weight() >= 3000);
    }
}
