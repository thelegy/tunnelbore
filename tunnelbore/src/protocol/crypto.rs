use super::DatagramConnection;
use async_trait::async_trait;
use blake2::{Blake2s256, Blake2sMac, Digest};
use digest::{FixedOutput, Mac, Update};
use snow::{
    error::InitStage,
    params::{DHChoice, NoiseParams},
    resolvers::{CryptoResolver, DefaultResolver},
    Builder,
};
use snow::{Keypair, TransportState};
use tai64::Tai64N;
use thiserror::Error;

pub const NOISE_PARAMS_SPEC: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_PROLOGUE: &str = "Tunnelbore v1";

pub const FIRST_MESSAGE_NOISE_OVERHEAD: usize = 96;
pub const SECOND_MESSAGE_NOISE_OVERHEAD: usize = 48;

pub type Blake2sMac128 = Blake2sMac<digest::consts::U16>;

lazy_static! {
    pub static ref NOISE_PARAMS: NoiseParams = NOISE_PARAMS_SPEC.parse().unwrap();
    pub static ref MAC_HASHER: Blake2s256 = Blake2s256::new_with_prefix(b"mac----");
    static ref CRYPTO_RESOLVER: Box<dyn CryptoResolver + Send + Sync> =
        Box::new(DefaultResolver::default());
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("NoiseProtocolError: {0}")]
    NoiseProtocolError(#[from] snow::error::Error),

    #[error("InvalidLength: {0}")]
    InvalidLength(#[from] digest::InvalidLength),

    #[error("UnexpectedLength")]
    UnexpectedLength(),

    #[error("TryFromSliceError")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error("TaiError")]
    TaiError(#[from] tai64::Error),

    #[error("MacError")]
    MacError(#[from] digest::MacError),

    #[error("BadPeer")]
    BadPeer(),

    #[error("ProtocolError")]
    ProtocolError(#[from] Box<super::Error>),

    #[error("InternalError")]
    InternalError(),
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::ProtocolError(Box::new(e))
    }
}

pub type Result<A, E = Error> = std::result::Result<A, E>;

pub struct Connection {
    sock: Box<dyn DatagramConnection + Send>,
    transport_state: TransportState,
}
impl Connection {
    pub const FIRST_MESSAGE_MAC_OFFSET: usize = FIRST_MESSAGE_NOISE_OVERHEAD + 12;
    pub const FIRST_MESSAGE_LENGTH: usize = Self::FIRST_MESSAGE_MAC_OFFSET + 16;
    pub const SECOND_MESSAGE_MAC_OFFSET: usize = SECOND_MESSAGE_NOISE_OVERHEAD;
    pub const SECOND_MESSAGE_LENGTH: usize = SECOND_MESSAGE_NOISE_OVERHEAD + 16;

    pub async fn new_initator(
        mut sock: Box<dyn DatagramConnection + Send>,
        psk: &[u8],
        local_priv_key: &[u8],
        local_mac_hash: &[u8],
        remote_pub_key: &[u8],
        remote_mac_hash: &[u8],
    ) -> Result<Self> {
        let mut handshake_state = Self::new_noise_builder()
            .psk(2, psk)
            .local_private_key(local_priv_key)
            .remote_public_key(remote_pub_key)
            .build_initiator()?;

        // Construct first message
        let mut msg = MacedMessage::<{ Self::FIRST_MESSAGE_LENGTH }>::new(&remote_mac_hash);
        let payload = tai64::Tai64N::now().to_bytes();
        if FIRST_MESSAGE_NOISE_OVERHEAD + payload.len()
            != handshake_state.write_message(&payload, msg.data())?
        {
            unreachable!()
        }
        let msg = msg.finalize()?;
        //println!("sending first message: {:}", base64::encode(&msg));
        sock.write_packet(&msg).await?;

        // Consume second message
        let mut msg = [0u8; Self::SECOND_MESSAGE_LENGTH];
        let len = sock.read_packet(&mut msg).await?;
        if len != Self::SECOND_MESSAGE_LENGTH {
            return Err(Error::UnexpectedLength());
        }
        //println!("received second message: {:}", base64::encode(&msg));
        let msg = MacedMessage::verify(&local_mac_hash, &mut msg)?;
        handshake_state.read_message(&msg, &mut [])?;

        let transport_state = handshake_state.into_transport_mode()?;

        Ok(Connection {
            sock,
            transport_state,
        })
    }

    pub async fn new_responder<V>(
        mut sock: Box<dyn DatagramConnection + Send>,
        psk: &[u8],
        local_priv_key: &[u8],
        local_mac_hash: &[u8],
        verify_pubkey_and_tai: V,
    ) -> Result<Self>
    where
        V: FnOnce([u8; 32], Tai64N) -> Result<bool>,
    {
        // Consume first message
        let mut msg = [0u8; Self::FIRST_MESSAGE_LENGTH];
        let len = sock.read_packet(&mut msg).await?;
        if len != Self::FIRST_MESSAGE_LENGTH {
            return Err(Error::UnexpectedLength());
        }
        let mut handshake_state = Self::new_noise_builder()
            .psk(2, psk)
            .local_private_key(local_priv_key)
            .build_responder()?;
        //println!("received first message: {:}", base64::encode(&msg));
        let msg = MacedMessage::verify(local_mac_hash, &mut msg)?;
        let mut payload = [0u8; 12];
        let len = handshake_state.read_message(&msg, &mut payload)?;
        if len != 12 {
            return Err(Error::UnexpectedLength());
        }
        let remote_pub_key = handshake_state
            .get_remote_static()
            .ok_or(Error::InternalError())?;
        let tai = Tai64N::from_slice(&payload)?;
        if !verify_pubkey_and_tai(remote_pub_key.try_into()?, tai)? {
            return Err(Error::BadPeer());
        }
        let remote_mac_hash = precalculate_mac_hash(remote_pub_key);

        // Construct second message
        let mut msg = MacedMessage::<{ Self::SECOND_MESSAGE_LENGTH }>::new(&remote_mac_hash);
        if SECOND_MESSAGE_NOISE_OVERHEAD != handshake_state.write_message(&[], msg.data())? {
            unreachable!()
        }
        let msg = msg.finalize()?;
        //println!("sending second message: {:}", base64::encode(&msg));
        sock.write_packet(&msg).await?;

        let transport_state = handshake_state.into_transport_mode()?;
        Ok(Connection {
            sock,
            transport_state,
        })
    }

    fn new_noise_builder<'builder>() -> Builder<'builder> {
        //Builder::with_resolver(NOISE_PARAMS.clone(), new_resolver()).prologue(NOISE_PROLOGUE.as_bytes())
        Builder::new(NOISE_PARAMS.clone()).prologue(NOISE_PROLOGUE.as_bytes())
    }
}
#[async_trait]
impl DatagramConnection for Connection {
    async fn read_packet(&mut self, payload: &mut [u8]) -> super::Result<usize> {
        let mut buf = [0u8; 65536];
        let len = self.sock.read_packet(&mut buf).await?;
        Ok(self.transport_state.read_message(&buf[..len], payload)?)
    }
    async fn write_packet(&mut self, payload: &[u8]) -> super::Result<()> {
        let mut buf = [0u8; 65536];
        let len = self.transport_state.write_message(payload, &mut buf)?;
        self.sock.write_packet(&buf[..len]).await
    }
}

pub struct MacedMessage<'message, const N: usize> {
    data: [u8; N],
    key: &'message [u8],
}
impl<'message, const N: usize> MacedMessage<'message, N> {
    pub fn new(key: &'message [u8]) -> Self {
        Self {
            data: [0u8; N],
            key,
        }
    }
    pub fn verify<'a>(key: &[u8], data: &'a mut [u8; N]) -> Result<&'a mut [u8]> {
        let len = data.len();
        let blake = Blake2sMac128::new_with_salt_and_personal(&key, &[], &[])?;
        let mac = &data[len - 16..];
        blake.chain(&data[..len - 16]).verify_slice(mac)?;
        Ok(&mut data[..len - 16])
    }
    pub fn data(&mut self) -> &mut [u8] {
        let len = self.data.len();
        &mut self.data[..len - 16]
    }
    pub fn finalize(mut self) -> Result<[u8; N]> {
        let len = self.data.len();
        let blake = Blake2sMac128::new_with_salt_and_personal(&self.key, &[], &[])?;
        let mac = blake.chain(&self.data[..len - 16]).finalize_fixed();
        self.data[len - 16..].clone_from_slice(&mac);
        Ok(self.data)
    }
}

pub trait KeypairExt: Sized {
    fn from_privkey(choice: &DHChoice, privkey: &[u8]) -> Result<Self>;
}
impl KeypairExt for Keypair {
    fn from_privkey(choice: &DHChoice, privkey: &[u8]) -> Result<Self> {
        // TODO: check length of slice?
        let mut dh = CRYPTO_RESOLVER
            .resolve_dh(choice)
            .ok_or(snow::Error::from(InitStage::GetDhImpl))?;
        let mut private = vec![0u8; dh.priv_len()];
        let mut public = vec![0u8; dh.pub_len()];
        dh.set(privkey);
        private.copy_from_slice(dh.privkey());
        public.copy_from_slice(dh.pubkey());
        Ok(Keypair { private, public })
    }
}

pub fn derive_pubkey(priv_key: &[u8]) -> Result<[u8; 32]> {
    Ok(Keypair::from_privkey(&NOISE_PARAMS.dh, priv_key)?
        .public
        .as_slice()
        .try_into()?)
}

pub fn precalculate_mac_hash(pub_key: &[u8]) -> [u8; 32] {
    MAC_HASHER.clone().chain(pub_key).finalize().into()
}
