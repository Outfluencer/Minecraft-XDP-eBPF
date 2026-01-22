use aya::{
    Pod,
    maps::{HashMap, MapData, PerCpuHashMap},
};
use log::debug;
use std::{fmt::Display, result::Result};

pub trait XdpMapAbstraction<K: Pod + Ord + Display, V: Display> {

    fn clear(&mut self) -> Result<(), anyhow::Error>;

    fn remove_if<F: FnMut(&V) -> bool>(&mut self, predicate: F) -> Result<(), anyhow::Error>;
}

impl<K: Pod + Ord + Display, V: Pod + Display> XdpMapAbstraction<K, V> for HashMap<MapData, K, V> {

    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.remove_if(|_| true)
    }

    fn remove_if<F>(&mut self, mut predicate: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&V) -> bool,
    {
        let mut keys = Vec::new();
        for item in self.iter() {
            let (k, v) = item?;
            if predicate(&v) {
                debug!("Removing {}: {} from map..", k, v);
                keys.push(k);
            }
        }

        for k in keys {
            self.remove(&k)?;
        }
        Ok(())
    }
}

impl<K: Pod + Ord + Display, V: Pod + Display> XdpMapAbstraction<K, V>
    for PerCpuHashMap<MapData, K, V>
{
    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.remove_if(|_| true)
    }

    fn remove_if<F>(&mut self, mut predicate: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&V) -> bool,
    {
        let mut keys_to_remove = Vec::new();

        for item in self.iter() {
            let (k, values) = item?;
            // With 4-tuple RSS, only ONE CPU should have a non-zero value
            if let Some(val) = find_active_value(&values) {
                if predicate(&val) {
                    debug!("Removing {}: {} from per-cpu map..", k, val);
                    keys_to_remove.push(k);
                }
            }
        }

        for k in keys_to_remove {
            self.remove(&k)?;
        }
        Ok(())
    }
}


// Helper to check if a value is all zeros (empty/unused slot)
#[inline]
fn is_zero<V: Pod>(v: &V) -> bool {
    let bytes = unsafe {
        std::slice::from_raw_parts(v as *const V as *const u8, std::mem::size_of::<V>())
    };
    bytes.iter().all(|&b| b == 0)
}

#[inline]
fn find_active_value<V: Pod + Copy>(values: &aya::maps::PerCpuValues<V>) -> Option<V> {
    values.iter().find(|v| !is_zero(*v)).copied()
}
