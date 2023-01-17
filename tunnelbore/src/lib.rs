use anyhow::{anyhow, Result};
use blake2::{Blake2s256, Digest};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref MAC1_HASHER: Blake2s256 = Blake2s256::new_with_prefix(b"mac1----");
}

mod quote_helpers {
    use crate::*;
    use proc_macro2::{Delimiter, Group, Punct, Spacing, TokenStream};
    use quote::{quote, ToTokens, TokenStreamExt};

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
            tokens.extend(quote!(tunnelbore::Pubkey{key: #key, mac1_hash: #mac1_hash}));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pubkey {
    pub key: [u8; 32],
    pub mac1_hash: [u8; 32],
}

impl std::fmt::Display for Pubkey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_str(&base64::encode(self.key))
    }
}

impl From<[u8; 32]> for Pubkey {
    fn from(key: [u8; 32]) -> Self {
        let mac1_hash = MAC1_HASHER.clone().chain_update(key).finalize().into();
        Pubkey { key, mac1_hash }
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
