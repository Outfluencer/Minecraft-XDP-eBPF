use aya::{
    maps::{HashMap, MapData, PerCpuHashMap, PerCpuValues},
    Pod,
};
use std::result::Result;

pub trait XdpMapAbstraction<K: Pod + Ord, V> {
    fn for_each<F>(&self, func: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(K, V) -> Result<(), anyhow::Error>;

    fn remove(&mut self, key: &K) -> Result<(), anyhow::Error>;

    fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.remove_if(|_, _| true)
    }

    fn remove_if<F>(&mut self, mut predicate: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&K, &V) -> bool,
    {
        let mut keys = Vec::new();
        self.for_each(|k, v| {
            if predicate(&k, &v) {
                keys.push(k);
            }
            Ok(())
        })?;

        keys.sort_unstable();
        keys.dedup();

        for k in keys {
            let _ = self.remove(&k);
        }
        Ok(())
    }
}

impl<K: Pod + Ord, V: Pod> XdpMapAbstraction<K, V> for HashMap<MapData, K, V> {
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

    fn remove(&mut self, key: &K) -> Result<(), anyhow::Error> {
        self.remove(key).map_err(|e| e.into())
    }
}

impl<K: Pod + Ord, V: Pod> XdpMapAbstraction<K, V> for PerCpuHashMap<MapData, K, V> {
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

    fn remove(&mut self, key: &K) -> Result<(), anyhow::Error> {
        self.remove(key).map_err(|e| e.into())
    }
}