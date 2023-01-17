use crate::MAC1_HASHER;
use anyhow::{anyhow, Result};
use blake2::Blake2sMac;
use blake2::Digest;
use digest::FixedOutput;
use digest::Update;

type Blake2sMac128 = Blake2sMac<digest::consts::U16>;

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
        formatter.write_str(&base64::encode(self.key))
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
        Pubkey::try_from(base64::decode(key)?)
    }
}
