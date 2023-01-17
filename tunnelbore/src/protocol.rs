use async_trait::async_trait;
use std::{io, num::TryFromIntError};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("CryptoError")]
    CryptoError(#[from] crypto::Error),

    #[error("IOError: {0}")]
    IOError(#[from] io::Error),

    #[error("NoiseProtocolError: {0}")]
    NoiseProtocolError(#[from] snow::error::Error),

    #[error("TryFromIntError")]
    TryFromIntError(#[from] TryFromIntError),

    #[error("BufferOverflowError")]
    BufferOverflowError(),
}

pub type Result<A, E = Error> = std::result::Result<A, E>;

#[async_trait]
pub trait DatagramConnection {
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn write_packet(&mut self, buf: &[u8]) -> Result<()>;
}

#[async_trait]
impl DatagramConnection for TcpStream {
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = self.read_u16().await?.into();
        if len > buf.len() {
            return Err(Error::BufferOverflowError());
        }
        self.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }

    async fn write_packet(&mut self, msg: &[u8]) -> Result<()> {
        self.write_u16(msg.len().try_into()?).await?;
        self.write_all(msg).await?;
        Ok(())
    }
}

pub mod crypto;

pub mod client {

    use super::*;
    use tokio::net::{TcpStream, ToSocketAddrs};

    pub struct Client {
        conn: crypto::Connection,
    }
    impl Client {
        pub async fn new<A: ToSocketAddrs>(
            addr: A,
            local_priv_key: &[u8],
            remote_pub_key: &[u8],
        ) -> Result<Self> {
            let sock = TcpStream::connect(addr).await?;
            let local_pub_key = crypto::derive_pubkey(local_priv_key)?;
            let local_mac_hash = crypto::precalculate_mac_hash(&local_pub_key);
            let remote_mac_hash = crypto::precalculate_mac_hash(&remote_pub_key);
            let conn = crypto::Connection::new_initator(
                Box::new(sock),
                &[0u8; 32],
                local_priv_key,
                &local_mac_hash,
                remote_pub_key,
                &remote_mac_hash,
            )
            .await?;
            println!("connected");
            Ok(Client { conn })
        }
    }
}

pub mod server {

    use super::*;
    use tokio::{
        net::{TcpListener, TcpStream, ToSocketAddrs},
        task::JoinSet,
    };
    use void::Void;

    #[derive(Debug)]
    pub struct Server {
        listener: TcpListener,
        tasks: JoinSet<()>,
    }
    impl Server {
        pub async fn new<A: ToSocketAddrs>(addr: A) -> Result<Server> {
            let listener = TcpListener::bind(addr).await?;
            let tasks = JoinSet::new();
            Ok(Server { listener, tasks })
        }
        pub async fn run(&mut self, local_priv_key: &[u8]) -> Result<Void> {
            let local_pub_key = crypto::derive_pubkey(local_priv_key)?;
            let local_mac_hash = crypto::precalculate_mac_hash(&local_pub_key);
            loop {
                let (sock, addr) = self.listener.accept().await?;
                let local_priv_key = Vec::from(local_priv_key);
                self.tasks.spawn(async move {
                    Self::handle_socket(sock, addr, local_priv_key, local_mac_hash)
                        .await
                        .unwrap_or_else(|e: Error| {
                            println!(
                                "Error occured in handling connection with {:}: {:}",
                                addr, e
                            )
                        })
                });
            }
        }
        async fn handle_socket(
            sock: TcpStream,
            addr: std::net::SocketAddr,
            local_priv_key: Vec<u8>,
            local_mac_hash: [u8; 32],
        ) -> Result<()> {
            println!("New connection: {:}", addr);

            let verify = |pubkey, tai| {
                println!("Verify: {:}, {:?}", base64::encode(pubkey), tai);
                Ok(true)
            };

            let connection = crypto::Connection::new_responder(
                Box::new(sock),
                &[0u8; 32],
                &local_priv_key,
                &local_mac_hash,
                verify,
            )
            .await?;
            println!("connected");

            println!("Not Implemented");
            Ok(())
        }
    }
}
