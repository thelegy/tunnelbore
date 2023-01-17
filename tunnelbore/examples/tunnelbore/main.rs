use anyhow::{anyhow, Result};
use blake2::{Blake2s256, Blake2sMac, Digest};
use digest::FixedOutput;
use digest::Update;
use std::vec::Vec;
use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tokio::{net::UdpSocket, spawn};

use tunnelbore::*;
use tunnelbore_macros::*;

type Blake2sMac128 = Blake2sMac<digest::consts::U16>;

#[macro_use]
extern crate lazy_static;

const OWN_PUBKEY: Pubkey = pubkey!("<redacted>");
const ROBOROCK_PUBKEY: Pubkey = pubkey!("<redacted>");

lazy_static! {
    static ref MAC1_HASHER: Blake2s256 = Blake2s256::new_with_prefix(b"mac1----");
    static ref PUBKEYS: RwLock<HashSet<Pubkey>> = RwLock::new(HashSet::new());
}

#[derive(Debug, Clone)]
struct Foo {
    local_socket: Arc<UdpSocket>,
    remote_socket: Arc<UdpSocket>,
}

impl Foo {
    async fn new() -> Result<Self> {
        let local_socket = Arc::new(UdpSocket::bind("::1:2222").await?);
        let remote_socket = Arc::new(UdpSocket::bind(":::2223").await?);
        Ok(Self {
            local_socket,
            remote_socket,
        })
    }

    async fn local_listen_loop(self) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 1500];
            let (len, addr) = self.local_socket.recv_from(&mut buf).await?;
            buf.resize(len, 0);
            match buf[0] {
                1 => handle_first(vec_to_array(buf)?, addr, &self.remote_socket).await?,
                2 => handle_second(buf, addr, &self.remote_socket).await?,
                4 => handle_data(buf, addr, &self.remote_socket).await?,
                3 => handle_cookie(buf, addr, &self.remote_socket).await?,
                _ => println!("Unhandled message from \"{}\": {:x?}", addr, buf.as_slice()),
            }
        }
    }

    async fn remote_listen_loop(self) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 1500];
            let (len, _addr) = self.remote_socket.recv_from(&mut buf).await?;
            buf.resize(len, 0);
            self.local_socket
                .send_to(buf.as_slice(), "::1:1347")
                .await?;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut pubkeys = PUBKEYS.write().await;
    pubkeys.insert(OWN_PUBKEY);
    pubkeys.insert(ROBOROCK_PUBKEY);
    drop(pubkeys);
    println!("Found the following pubkeys:");
    for pubkey in PUBKEYS.read().await.iter() {
        println!("- {}", pubkey);
    }
    //println!("Pubkeys: {:?}", PUBKEYS.read().await);
    let foo = Foo::new().await?;

    let x = spawn(foo.clone().local_listen_loop());
    let y = spawn(foo.remote_listen_loop());

    x.await??;
    y.await??;

    Ok(())
}

async fn fwd(buf: &[u8], from: SocketAddr, sock: &UdpSocket) -> Result<()> {
    let peer_addr = "[::ffff:192.168.1.19]:1347".parse()?;
    let sent_bytes;
    if from == peer_addr {
        sent_bytes = sock.send_to(buf, "localhost:1347").await?;
    } else {
        sent_bytes = sock.send_to(buf, peer_addr).await?;
    };
    if sent_bytes == buf.len() {
        Ok(())
    } else {
        Err(anyhow!("Forwarded length mismatched"))
    }
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N]> {
    v.try_into()
        .map_err(|v: Vec<T>| anyhow!("Length mismatch: Expected length {}, Got {}", N, v.len()))
}

async fn handle_first(buf: [u8; 148], from: SocketAddr, sock: &UdpSocket) -> Result<()> {
    let mac1 = &buf[116..132];
    println!("First from {} with mac1 {:x?}", from, mac1);
    for pubkey in PUBKEYS.read().await.iter() {
        let blake = Blake2sMac128::new_with_salt_and_personal(&pubkey.mac1_hash[..], &[], &[])?;
        let computed_mac1 = blake.chain(&buf[0..116]).finalize_fixed();
        //println!("Testing Pubkey {:}: Mac: {:?}, Computed: {:?}", pubkey, mac1, computed_mac1);
        if mac1 == &computed_mac1[..] {
            println!("Matching Pubkey: {:}", pubkey);
            return Ok(());
        }
    }
    Err(anyhow!("No matching pubkey was found to validate mac1"))
    //fwd(buf.as_slice(), from, sock).await
}

async fn handle_second(buf: Vec<u8>, from: SocketAddr, sock: &UdpSocket) -> Result<()> {
    println!("Second from {}", from);
    fwd(buf.as_slice(), from, sock).await
}

async fn handle_data(buf: Vec<u8>, from: SocketAddr, sock: &UdpSocket) -> Result<()> {
    println!("Data from {}", from);
    fwd(buf.as_slice(), from, sock).await
}

async fn handle_cookie(buf: Vec<u8>, from: SocketAddr, sock: &UdpSocket) -> Result<()> {
    println!("Cookie from {}", from);
    fwd(buf.as_slice(), from, sock).await
}
