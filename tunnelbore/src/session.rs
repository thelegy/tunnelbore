//use crate::LockResultExt;
use crate::{fmt_option_display, LockResultExt, Pubkey};
use anyhow::{anyhow, Result};
use derive_debug::Dbg;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use std::hash::{BuildHasher, Hash};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock, Weak};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    session_id: u32,
    session_address: SocketAddr,
}
impl SessionId {
    pub fn new(id: u32, address: SocketAddr) -> Self {
        SessionId {
            session_id: id,
            session_address: address,
        }
    }
    pub fn address(&self) -> SocketAddr {
        self.session_address
    }
}
impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_fmt(format_args!(
            "{:X}@{}",
            self.session_id, self.session_address
        ))
    }
}

#[derive(Debug)]
pub struct SessionManager<S: 'static + Sync + Send = DefaultHashBuilder> {
    local_ids: Arc<RwLock<HashMap<SessionId, Weak<Mutex<Session>>, S>>>,
    remote_ids: Arc<RwLock<HashMap<SessionId, Weak<Mutex<Session>>, S>>>,
}

impl<S: Sync + Send + BuildHasher> Clone for SessionManager<S> {
    fn clone(&self) -> Self {
        let local_ids = self.local_ids.clone();
        let remote_ids = self.local_ids.clone();
        Self { local_ids, remote_ids }
    }
}

impl<S: Default + Sync + Send + BuildHasher> SessionManager<S> {
    pub fn new() -> Self {
        Self::with_hashers(Default::default(), Default::default())
    }
}
impl<S: Sync + Send + BuildHasher> SessionManager<S> {
    pub fn with_hashers(hash_builder1: S, hash_builder2: S) -> Self {
        let local_ids = Arc::new(RwLock::new(HashMap::with_hasher(hash_builder1)));
        let remote_ids = Arc::new(RwLock::new(HashMap::with_hasher(hash_builder2)));
        Self {
            local_ids,
            remote_ids,
        }
    }
    fn new_session(&self) -> Arc<Mutex<Session>> {
        let session = Session {
            drop_actions: vec![Box::new(|s| println!("Dropping {:x?}", s))],
            pubkey: None,
            local_id: None,
            remote_id: None,
        };
        Arc::new(Mutex::new(session))
    }
    fn add_local_id(
        &self,
        session: &mut Session,
        s: &Arc<Mutex<Session>>,
        id: SessionId,
    ) -> Result<()> {
        let sm = self.clone();
        session.drop_actions.push(Box::new(move| session| {
            if let Some(id) = &session.local_id {
                if let Ok(mut ids) = sm.local_ids.write() {
                    ids.remove(id);
                }
            }
        }));
        session.local_id = Some(id.clone());
        self.local_ids
            .write()
            .unpoisoned()?
            .insert(id, Arc::downgrade(&s));
        Ok(())
    }
    fn add_remote_id(
        &self,
        session: &mut Session,
        s: &Arc<Mutex<Session>>,
        id: SessionId,
    ) -> Result<()> {
        let sm = self.clone();
        session.drop_actions.push(Box::new(move |session| {
            if let Some(id) = &session.remote_id {
                if let Ok(mut ids) = sm.remote_ids.write() {
                    ids.remove(id);
                }
            }
        }));
        session.remote_id = Some(id.clone());
        self.local_ids
            .write()
            .unpoisoned()?
            .insert(id, Arc::downgrade(&s));
        Ok(())
    }
    pub fn find_session_by_local_id(&self, id: &SessionId) -> Result<Option<Arc<Mutex<Session>>>> {
        let local_ids = self.local_ids.read().unpoisoned()?;
        Ok(local_ids.get(id).and_then(Weak::upgrade))
    }
    pub fn find_session_by_remote_id(&self, id: &SessionId) -> Result<Option<Arc<Mutex<Session>>>> {
        let remote_ids = self.remote_ids.read().unpoisoned()?;
        Ok(remote_ids.get(id).and_then(Weak::upgrade))
    }
    pub fn new_outbound_session(&self, id: SessionId, pubkey: &Pubkey) -> Result<Arc<Mutex<Session>>> {
        let s = self.new_session();
        let mut session = s.lock().unpoisoned()?;
        self.add_local_id(&mut session, &s, id)?;
        session.pubkey = Some(*pubkey);
        drop(session);
        Ok(s)
    }
    pub fn new_inbound_response(
        &self,
        s: &Arc<Mutex<Session>>,
        id: SessionId,
    ) -> Result<()> {
        let mut session = s.lock().unpoisoned()?;
        if let Some(orig_id) = &session.remote_id {
            return Err(anyhow!(
                "There is already a session id of the remote ({}), cannot attach another one",
                orig_id
            ));
        }
        self.add_remote_id(&mut session, &s, id)
    }
}

#[derive(Dbg)]
pub struct Session {
    #[dbg(placeholder = "...")]
    drop_actions: Vec<Box<dyn FnOnce(&mut Session) + Sync + Send>>,
    #[dbg(formatter = "fmt_option_display")]
    pubkey: Option<Pubkey>,
    #[dbg(formatter = "fmt_option_display")]
    local_id: Option<SessionId>,
    #[dbg(formatter = "fmt_option_display")]
    remote_id: Option<SessionId>,
}
impl Session {
    pub fn local_id(&self) -> &Option<SessionId> {
        &self.local_id
    }
    pub fn remote_id(&self) -> &Option<SessionId> {
        &self.remote_id
    }

    pub fn pubkey(&self) -> Option<&Pubkey> {
        self.pubkey.as_ref()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        for action in std::mem::take(&mut self.drop_actions).drain(..) {
            action(self)
        }
    }
}

#[derive(Debug)]
pub struct RecentSessionStore<const N: usize> {
    store: Mutex<[Option<Arc<Mutex<Session>>>; N]>,
    ptr: Mutex<usize>,
}
impl<const N: usize> RecentSessionStore<N> {
    pub fn new() -> Self {
        RecentSessionStore {
            store: Mutex::new([(); N].map(|_| None)),
            ptr: Mutex::new(0),
        }
    }
    pub fn store(&self, s: Arc<Mutex<Session>>) -> Result<()> {
        let mut ptr = self.ptr.lock().unpoisoned()?;
        let mut store = self.store.lock().unpoisoned()?;
        if *ptr >= N {
            *ptr = 0;
        }
        store[*ptr] = Some(s);
        *ptr += 1;
        Ok(())
    }
}
impl<const N: usize> Default for RecentSessionStore<N> {
    fn default() -> Self {
        RecentSessionStore::new()
    }
}
