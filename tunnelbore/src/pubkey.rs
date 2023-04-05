use crate::MAC1_HASHER;
use anyhow::{anyhow, Result};
use base64::Engine;
use blake2::Blake2sMac;
use blake2::Digest;
use digest::FixedOutput;
use digest::Update;
use serde::{Deserialize, Serialize};

type Blake2sMac128 = Blake2sMac<digest::consts::U16>;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

mod quote_helpers {
    use proc_macro2::{Delimiter, Group, Punct, Spacing, TokenStream};
    use quote::{quote, ToTokens, TokenStreamExt};

    use super::Pubkey;

    fn array_literal<T: quote::ToTokens, const N: usize>(x: &[T; N]) -> Group {
        let mut tokens = TokenStream::new();
        tokens.append_separated(x.iter(), Punct::new(',', Spacing::Alone));
        Group::new(Delimiter::Bracket, tokens)
    }
    impl ToTokens for Pubkey {
        fn to_tokens(&self, tokens: &mut TokenStream) {
            let key = self.key;
            let key = array_literal(&key);
            let mac1_hash = self.mac1_hash;
            let mac1_hash = array_literal(&mac1_hash);
            tokens.extend(quote!(tunnelbore::Pubkey::from_raw(#key, #mac1_hash)));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey {
    key: [u8; 32],
    mac1_hash: [u8; 32],
}
impl Pubkey {
    pub const fn from_raw(key: [u8; 32], mac1_hash: [u8; 32]) -> Pubkey {
        Pubkey { key, mac1_hash }
    }
    pub fn verify_mac1(&self, mac1: &[u8; 16], x: &[u8]) -> Result<bool> {
        let blake = Blake2sMac128::new_with_salt_and_personal(&self.mac1_hash[..], &[], &[])?;
        let computed_mac1 = blake.chain(x).finalize_fixed();
        Ok(mac1 == &computed_mac1[..])
    }
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_str(&String::from(self))
    }
}

impl From<[u8; 32]> for Pubkey {
    fn from(key: [u8; 32]) -> Self {
        let mac1_hash = MAC1_HASHER.clone().chain_update(key).finalize().into();
        Pubkey::from_raw(key, mac1_hash)
    }
}
impl TryFrom<Vec<u8>> for Pubkey {
    type Error = anyhow::Error;
    fn try_from(key: Vec<u8>) -> Result<Self, Self::Error> {
        match <[u8; 32]>::try_from(key) {
            Ok(array) => Ok(array.into()),
            _ => Err(anyhow!("Length mismatch")),
        }
    }
}
impl TryFrom<&str> for Pubkey {
    type Error = anyhow::Error;
    fn try_from(key: &str) -> Result<Self, Self::Error> {
        Pubkey::try_from(&String::from(key))
    }
}
impl TryFrom<&String> for Pubkey {
    type Error = anyhow::Error;
    fn try_from(key: &String) -> Result<Self, Self::Error> {
        Pubkey::try_from(BASE64.decode(key)?)
    }
}

impl From<&Pubkey> for [u8; 32] {
    fn from(key: &Pubkey) -> [u8; 32] {
        key.key
    }
}
impl From<&Pubkey> for String {
    fn from(key: &Pubkey) -> String {
        BASE64.encode(key.key)
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        Pubkey::try_from(&key).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Pubkey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        String::from(self).serialize(serializer)
    }
}
