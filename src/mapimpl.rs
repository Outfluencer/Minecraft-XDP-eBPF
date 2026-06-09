use aya::{
    Pod,
    maps::{HashMap, MapData},
};
use log::debug;
use std::fmt::Display;

/// Remove every entry of `map` for which `predicate(key, value)` returns true.
///
/// aya's `HashMap` cannot be mutated while it is being iterated, so the matching
/// keys are collected first and deleted in a second pass.
pub fn remove_if<K, V, F>(
    map: &mut HashMap<MapData, K, V>,
    mut predicate: F,
) -> Result<(), anyhow::Error>
where
    K: Pod + Display,
    V: Pod + Display,
    F: FnMut(&K, &V) -> bool,
{
    let mut keys = Vec::new();
    for item in map.iter() {
        let (k, v) = item?;
        if predicate(&k, &v) {
            debug!("Removing {}: {} from map..", k, v);
            keys.push(k);
        }
    }
    for k in keys {
        map.remove(&k)?;
    }
    Ok(())
}

/// Remove all entries from `map`.
pub fn clear<K, V>(map: &mut HashMap<MapData, K, V>) -> Result<(), anyhow::Error>
where
    K: Pod + Display,
    V: Pod + Display,
{
    remove_if(map, |_, _| true)
}
