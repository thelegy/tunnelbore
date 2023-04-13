use anyhow::{anyhow, Result};
use blake2::{Blake2s256, Digest};
use hashbrown::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref MAC1_HASHER: Blake2s256 = Blake2s256::new_with_prefix(b"mac1----");
}

pub mod config;
pub mod drophook;
pub mod protocol;
pub mod pubkey;
pub mod session;

pub use config::Config;
pub use pubkey::Pubkey;

pub fn fmt_option_display<T: std::fmt::Display>(opt: &Option<T>) -> String {
    match opt {
        Some(val) => std::format!("Some({})", val),
        None => "None".into(),
    }
}

pub trait LockResultExt {
    type Guard;
    fn unpoisoned(self) -> Result<Self::Guard>;
}
impl<Guard> LockResultExt for std::sync::LockResult<Guard> {
    type Guard = Guard;
    fn unpoisoned(self) -> Result<Self::Guard> {
        self.map_err(|_| anyhow!("PoisonError"))
    }
}

pub trait FromKey<K> {
    fn from_key(key: &K) -> Self;
}
impl<K, T> FromKey<K> for std::sync::Arc<T>
where
    T: FromKey<K>,
{
    fn from_key(key: &K) -> Self {
        std::sync::Arc::new(T::from_key(key))
    }
}
impl<K, T> FromKey<K> for std::sync::Mutex<T>
where
    T: FromKey<K>,
{
    fn from_key(key: &K) -> Self {
        std::sync::Mutex::new(T::from_key(key))
    }
}

#[derive(Debug)]
pub struct LockedHashMap<K, V>(RwLock<HashMap<K, V>>);

impl<K, V> LockedHashMap<K, V> {
    pub fn new() -> Self {
        LockedHashMap(Default::default())
    }
    pub fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, HashMap<K, V>>> {
        self.0.read().unpoisoned()
    }
    pub fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<K, V>>> {
        self.0.write().unpoisoned()
    }
}
impl<K, V> LockedHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn get_or<F>(&self, k: &K, f: F) -> Result<V>
    where
        F: FnOnce(&K) -> V,
    {
        if let Some(x) = self.read()?.get(k) {
            return Ok(x.clone());
        }
        let mut lock = self.write()?;
        Ok(lock.entry(k.clone()).or_insert_with(|| f(k)).clone())
    }
}
impl<K, V> Default for LockedHashMap<K, V> {
    fn default() -> Self {
        LockedHashMap::new()
    }
}
impl<K, V> LockedHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Default + Clone,
{
    pub fn get_or_default(&self, k: &K) -> Result<V> {
        self.get_or(k, |_| Default::default())
    }
}
impl<K, V> LockedHashMap<K, V>
where
    K: Eq + Hash + Clone,
    V: FromKey<K> + Clone,
{
    pub fn get_or_new(&self, k: &K) -> Result<V> {
        self.get_or(k, V::from_key)
    }
}
