use crate::Pubkey;
use figment::{Figment, Provider, Error, Metadata, Profile};
use serde::{Serialize, Deserialize};


#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerConfig {
    pub pubkey: Pubkey,
    pub address: String,
}


#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub own_pubkey: Pubkey,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

impl Config {
    // Allow the configuration to be extracted from any `Provider`.
    pub fn from<T: Provider>(provider: T) -> Result<Config, Error> {
        Figment::from(provider).extract()
    }

    // Provide a default provider, a `Figment`.
    pub fn figment() -> Figment {
        use figment::providers::{Env, Serialized};

        Figment::from(Serialized::<Vec<PeerConfig>>::default("peers", Vec::new())).merge(Env::prefixed("TUNNELBORE_"))
    }
}

use figment::value::{Map, Dict};

// Make `Config` a provider itself for composability.
impl Provider for Config {
    fn metadata(&self) -> Metadata {
        Metadata::named("Library Config")
    }

    fn data(&self) -> Result<Map<Profile, Dict>, Error>  {
        figment::providers::Serialized::<Vec<PeerConfig>>::default("peers", Vec::new()).data()
    }

    fn profile(&self) -> Option<Profile> {
        Option::None
    }
}
