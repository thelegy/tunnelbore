use anyhow::{anyhow, Result};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::{Mutex, Weak};
use std::vec::Vec;
use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::{spawn, try_join};

use tunnelbore::session::*;
use tunnelbore::*;
use tunnelbore_macros::*;

#[macro_use]
extern crate lazy_static;

const OWN_PUBKEY: Pubkey = pubkey!("<redacted>");
const ROBOROCK_PUBKEY: Pubkey = pubkey!("<redacted>");

lazy_static! {
    /// Ipv4 because there we have a whole /8 net of local ips to choose
    static ref LOCAL_ADDRESS: SocketAddr = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 1347);

    static ref PUBKEYS: RwLock<HashSet<Pubkey>> = RwLock::new(HashSet::new());
    static ref ADDRESSES: RwLock<HashMap<Pubkey, SocketAddr>> = RwLock::new(HashMap::new());
    static ref SESSIONS: SessionManager = SessionManager::new();
    static ref RECENT_SESSIONS: LockedHashMap<Pubkey, Arc<RecentSessionStore<3>>> =
        Default::default();
    static ref PEERS: LockedHashMap<Pubkey, Arc<Mutex<PeerInfo>>> = Default::default();

    static ref CORE: Core = Core::new().unwrap();
}

#[derive(Debug)]
struct PeerInfo {
    socket: Option<Weak<UdpSocket>>,
    pubkey: Pubkey,
}
impl FromKey<Pubkey> for PeerInfo {
    fn from_key(key: &Pubkey) -> Self {
        PeerInfo {
            socket: Default::default(),
            pubkey: key.clone(),
        }
    }
}
impl PeerInfo {
    pub async fn socket(p: Arc<Mutex<Self>>) -> Result<Arc<UdpSocket>> {
        let mut peer = p.lock().unpoisoned()?;
        if let Some(sock) = peer.socket.as_ref().and_then(Weak::upgrade) {
            Ok(sock)
        } else {
            let ip = 0x7f000000 | thread_rng().gen_range(2..0xffffff);
            let addr = SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), 0);
            let socket = Arc::new(UdpSocket::bind_sync(addr)?);
            peer.socket = Some(Arc::downgrade(&socket));
            spawn(Self::run(p.clone(), socket.clone()));
            Ok(socket)
        }
    }
    fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }
    async fn run(p: Arc<Mutex<Self>>, sock: Arc<UdpSocket>) -> Result<()> {
        let pubkey = p.lock().unpoisoned()?.pubkey().clone();
        loop {
            {
                let mut buf = vec![0u8; 1500];
                let (len, addr) = sock.recv_from(&mut buf).await?;
                buf.resize(len, 0);

                match buf[0] {
                    1 => {
                        handle_outbound_first(vec_to_array(buf)?, &addr, &CORE.remote_socket).await
                    }
                    //1 => Err(anyhow!("Not implemented yet (outbound first)")),
                    2 => Err(anyhow!("Not implemented yet (outbound second)")),
                    3 => Err(anyhow!("Not implemented yet (outbound cookie)")),
                    //4 => Err(anyhow!("Not implemented yet (outbound data)")),
                    4 => handle_outbound_data(&buf[..], &addr, &pubkey, &CORE.remote_socket).await,
                    _ => Err(anyhow!(
                        "Unhandled message from \"{}\": {:x?}",
                        addr,
                        buf.as_slice()
                    )),
                }
            }
            .unwrap_or_else(|err| println!("[Err]: {}", err))
        }
    }
}

#[derive(Debug, Clone)]
struct Core {
    local_socket: Arc<UdpSocket>,
    remote_socket: Arc<UdpSocket>,
}

impl Core {
    fn new() -> Result<Self> {
        let local_socket = Arc::new(UdpSocket::bind_sync("::1:2222")?);
        let remote_socket = Arc::new(UdpSocket::bind_sync(":::2223")?);
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
            //println!("Received {} bytes from {} on socket {}", len, addr, self.local_socket.local_addr()?);
            match buf[0] {
                1 => handle_outbound_first(vec_to_array(buf)?, &addr, &self.remote_socket).await,
                //2 => Err(anyhow!("Not implemented yet (outbound second)")),
                //3 => Err(anyhow!("Not implemented yet (outbound cookie)")),
                //4 => Err(anyhow!("Not implemented yet (outbound data)")),
                //4 => fwd_outbound(&buf, &addr, &self.remote_socket).await,
                //2 => handle_second(buf, addr, &self.remote_socket).await,
                //4 => handle_data(buf, addr, &self.remote_socket).await,
                //3 => handle_cookie(buf, addr, &self.remote_socket).await,
                //_ => Err(anyhow!(
                //    "Unhandled message from \"{}\": {:x?}",
                //    addr,
                //    buf.as_slice()
                //)),
                _ => Ok(()), // drop everything else
            }
            .unwrap_or_else(|err| println!("[Err]: {}", err))
        }
    }

    async fn remote_listen_loop(self) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 1500];
            // TODO: smtg is broken here... recv_from never finishes
            let (len, addr) = self.remote_socket.recv_from(&mut buf).await?;
            buf.resize(len, 0);
            println!(
                "Received {} bytes from {} on socket {}",
                len,
                addr,
                self.remote_socket.local_addr()?
            );
            match buf[0] {
                1 => Err(anyhow!("Not implemented yet (inbound first)")),
                2 => handle_inbound_second(vec_to_array(buf)?, &addr).await,
                3 => Err(anyhow!("Not implemented yet (inbound cookie)")),
                //4 => Err(anyhow!("Not implemented yet (inbound data)")),
                4 => handle_inbound_data(&buf[..], &addr).await,
                //4 => fwd_inbound(&buf, &addr, &self.local_socket).await,
                _ => Err(anyhow!(
                    "Unhandled message from \"{}\": {:x?}",
                    addr,
                    buf.as_slice()
                )),
            }
            .unwrap_or_else(|err| println!("[Err]: {}", err))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |p| {
        panic_hook(p);
        std::process::exit(1);
    }));

    let client = tunnelbore::protocol::client::Client::new(
        "127.0.0.1:1347",
        b64!("<redacted>"),
        b64!("<redacted>"),
    )
    .await?;
    //println!("{:?}", client);

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    println!("Exit");
    return Ok(());

    let mut pubkeys = PUBKEYS.write().await;
    pubkeys.insert(OWN_PUBKEY);
    pubkeys.insert(ROBOROCK_PUBKEY);
    drop(pubkeys);
    let mut addresses = ADDRESSES.write().await;
    addresses.insert(OWN_PUBKEY, *LOCAL_ADDRESS);
    addresses.insert(ROBOROCK_PUBKEY, "[::ffff:192.168.1.19]:1347".parse()?);
    //addresses.insert(ROBOROCK_PUBKEY, "192.168.1.19:1347".parse()?);
    drop(addresses);
    println!("Found the following pubkeys:");
    for pubkey in PUBKEYS.read().await.iter() {
        println!("- {}", pubkey);
    }
    //println!("Pubkeys: {:?}", PUBKEYS.read().await);

    //let x = spawn(foo.clone().local_listen_loop());
    //let y = spawn(foo.remote_listen_loop());

    try_join!(
        CORE.clone().local_listen_loop(),
        CORE.clone().remote_listen_loop()
    )?;

    Ok(())
}

//async fn fwd_outbound(buf: &[u8], from: &SocketAddr, sock: &UdpSocket) -> Result<()> {
//    if buf.len() < 32 {
//        return Err(anyhow!("Too small for a valid wg data packet"));
//    };
//    let receiver_id = SessionId::new(u32::from_le_bytes(*buf.subarray_unchecked(4)), *from);
//    println!("outbound local_id: {}", receiver_id);
//    if let Some(s) = SESSIONS.find_session_by_remote_id(&receiver_id)? {
//        let session = s.lock().unpoisoned()?;
//        println!("outbound found session: {:x?}", session);
//    }
//    Err(anyhow!("Not implemented (outbound data)"))
//}
//async fn fwd_inbound(buf: &[u8], from: &SocketAddr, sock: &UdpSocket) -> Result<()> {
//    Err(anyhow!("Not implemented (inbound data)"))
//}
//async fn fwd(buf: &[u8], from: &SocketAddr, sock: &UdpSocket) -> Result<()> {
//    let peer_addr = &"[::ffff:192.168.1.19]:1347".parse()?;
//    if from == peer_addr {
//        send_bytes(sock, buf, &LOCAL_ADDRESS).await
//    } else {
//        send_bytes(sock, buf, peer_addr).await
//    }
//    Err(anyhow!("Not implemented"))
//}

async fn send_bytes(sock: &UdpSocket, buf: &[u8], addr: &SocketAddr) -> Result<()> {
    println!(
        "Send {} bytes to {} on socket {}",
        buf.len(),
        addr,
        sock.local_addr()?
    );
    let sent_bytes = sock.send_to(buf, addr).await?;
    if sent_bytes == buf.len() {
        Ok(())
    } else {
        Err(anyhow!("Sent length mismatched"))
    }
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N]> {
    v.try_into()
        .map_err(|v: Vec<T>| anyhow!("Length mismatch: Expected length {}, Got {}", N, v.len()))
}

async fn handle_outbound_first(msg: [u8; 148], from: &SocketAddr, sock: &UdpSocket) -> Result<()> {
    let mac1 = msg.subarray(116);
    println!("Outbound first from {} with mac1 {:x?}", from, mac1);
    for pubkey in PUBKEYS.read().await.iter() {
        if pubkey.verify_mac1(mac1, &msg[0..116])? {
            let session_id =
                SessionId::new(u32::from_le_bytes(msg.subarray(4).clone()), *LOCAL_ADDRESS);
            println!("Matching Pubkey: {} for sender {:}", pubkey, session_id);
            let session = SESSIONS.new_outbound_session(session_id, pubkey)?;
            println!("New outbound session: {:?}", session.lock().unpoisoned()?);
            RECENT_SESSIONS.get_or_default(pubkey)?.store(session)?;
            return match ADDRESSES.read().await.get(pubkey) {
                Some(addr) => send_bytes(&sock, &msg, addr).await,
                None => Err(anyhow!("No target address was found")),
            };
        }
    }
    Err(anyhow!("No matching pubkey was found to validate mac1"))
}

async fn handle_outbound_data(
    buf: &[u8],
    _from: &SocketAddr,
    pubkey: &Pubkey,
    sock: &UdpSocket,
) -> Result<()> {
    match ADDRESSES.read().await.get(pubkey) {
        Some(addr) => send_bytes(sock, buf, addr).await,
        None => Err(anyhow!("No target address was found")),
    }
}

async fn handle_inbound_second(msg: [u8; 92], from: &SocketAddr) -> Result<()> {
    let id_sender = SessionId::new(u32::from_le_bytes(msg.subarray(4).clone()), *from);
    let id_receiver = SessionId::new(u32::from_le_bytes(msg.subarray(8).clone()), *LOCAL_ADDRESS);
    println!(
        "Inbound second from {} with sender {} and reveiver {}",
        from, id_sender, id_receiver
    );
    if let Some(session) = SESSIONS.find_session_by_local_id(&id_receiver)? {
        // TODO verify the sender
        SESSIONS.new_inbound_response(&session, id_sender)?;
        if let Some(pubkey) = session.lock().unpoisoned()?.pubkey() {
            println!("Found pubkey: {:x?}", pubkey);
            let peer = PEERS.get_or_new(&pubkey)?;
            println!("Peer: {:x?}", peer);
            //let mut peer = peer.lock().unpoisoned()?;
            //println!("Lookup result: {:x?}", peer);
            let sock = PeerInfo::socket(peer).await?;
            println!("Lookup socket: {:x?}", sock);
            send_bytes(&sock, &msg, &id_receiver.address()).await
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}
async fn handle_inbound_data(msg: &[u8], _from: &SocketAddr) -> Result<()> {
    if msg.len() < 32 {
        return Err(anyhow!("Too small for a valid wg data packet"));
    };
    let id_receiver = SessionId::new(
        u32::from_le_bytes(*msg.subarray_unchecked(4)),
        *LOCAL_ADDRESS,
    );
    if let Some(session) = SESSIONS.find_session_by_local_id(&id_receiver)? {
        if let Some(pubkey) = session.lock().unpoisoned()?.pubkey() {
            println!("Found pubkey: {:x?}", pubkey);
            let peer = PEERS.get_or_new(&pubkey)?;
            println!("Peer: {:x?}", peer);
            let sock = PeerInfo::socket(peer).await?;
            println!("Lookup socket: {:x?}", sock);
            send_bytes(&sock, &msg, &id_receiver.address()).await
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

trait SliceExt<T> {
    fn subarray_unchecked<const M: usize>(&self, offset: usize) -> &[T; M];
    fn subarray<const M: usize>(&self, offset: usize) -> Option<&[T; M]>;
}
impl<T> SliceExt<T> for &[T] {
    fn subarray_unchecked<const M: usize>(&self, offset: usize) -> &[T; M] {
        <&[T; M]>::try_from(&self[offset..offset + M]).unwrap()
    }

    fn subarray<const M: usize>(&self, offset: usize) -> Option<&[T; M]> {
        if offset + M > self.len() {
            None
        } else {
            Some(self.subarray_unchecked(offset))
        }
    }
}
trait ArrayExt<T, const N: usize> {
    fn subarray<const M: usize>(&self, offset: usize) -> &[T; M];
}
impl<T, const N: usize> ArrayExt<T, N> for [T; N] {
    fn subarray<const M: usize>(&self, offset: usize) -> &[T; M] {
        <&[T; M]>::try_from(&self[offset..offset + M]).unwrap()
    }
}

trait UdpSocketExt: Sized {
    fn bind_sync<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self>;
}
impl UdpSocketExt for UdpSocket {
    fn bind_sync<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self> {
        let sock = std::net::UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(UdpSocket::from_std(sock)?)
    }
}
