use aya::{
    Pod,
    maps::{HashMap, MapData, PerCpuHashMap},
};
use log::info;
use std::{fmt::Display, result::Result};

pub trait XdpMapAbstraction<K: Pod + Ord + Display, V: Display> {
    fn for_each<F>(&self, func: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(K, V) -> Result<(), anyhow::Error>;

    fn clear(&mut self) -> Result<(), anyhow::Error>;

    fn remove_if<F: FnMut(&V) -> bool>(&mut self, predicate: F) -> Result<(), anyhow::Error>;
}

impl<K: Pod + Ord + Display, V: Pod + Display> XdpMapAbstraction<K, V> for HashMap<MapData, K, V> {
    fn for_each<F>(&self, mut func: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(K, V) -> Result<(), anyhow::Error>,
    {
        for item in self.iter() {
            let (k, v) = item?;
            func(k, v)?;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.remove_if(|_| true)
    }

    fn remove_if<F>(&mut self, mut predicate: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&V) -> bool,
    {
        let mut keys = Vec::new();
        self.for_each(|k, v| {
            if predicate(&v) {
                keys.push(k);
                info!("Removing {}: {} from map..", k, v);
            }
            Ok(())
        })?;

        keys.sort_unstable();
        keys.dedup();

        for k in keys {
            self.remove(&k)?;
        }
        Ok(())
    }
}

impl<K: Pod + Ord + Display, V: Pod + Display> XdpMapAbstraction<K, V>
    for PerCpuHashMap<MapData, K, V>
{
    fn for_each<F>(&self, mut func: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(K, V) -> Result<(), anyhow::Error>,
    {
        for item in self.iter() {
            let (k, values) = item?;
            for val in values.iter() {
                func(k, *val)?;
            }
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.remove_if(|_| true)
    }

    fn remove_if<F>(&mut self, mut predicate: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&V) -> bool,
    {
        let mut keys_to_remove = Vec::new();

        // Helper to check if a value is all zeros (empty/unused slot)
        let is_zero = |v: &V| -> bool {
            let bytes = unsafe {
                std::slice::from_raw_parts(v as *const V as *const u8, std::mem::size_of::<V>())
            };
            bytes.iter().all(|&b| b == 0)
        };

        for item in self.iter() {
            let (k, values) = item?;
            for val in values.iter() {
                if is_zero(val) {
                    continue;
                }
                if predicate(val) {
                    keys_to_remove.push(k);
                    info!("Removing {}: {} from map..", k, val);
                    break;
                }
            }
        }
        keys_to_remove.sort_unstable();
        keys_to_remove.dedup();
        for ele in keys_to_remove {
            self.remove(&ele)?;
        }
        Ok(())
    }
}
