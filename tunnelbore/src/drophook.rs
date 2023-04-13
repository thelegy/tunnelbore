use crate::LockResultExt;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::sync::{Mutex, Arc};

pub trait AttachDropHook<T> {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce(&mut T) + Send + Sync>);
}

pub struct DropHooks<T>(Arc<Mutex<Vec<Box<dyn FnOnce(&mut T) + Send + Sync>>>>);
impl<T> AttachDropHook<T> for DropHooks<T> {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce(&mut T) + Send + Sync>) {
        let mut guard = self.0.lock().unwrap();
        guard.push(action);
    }
}
impl<T> Clone for DropHooks<T> {
    fn clone(&self) -> Self {
        DropHooks(self.0.clone())
    }
}
impl<T> Default for DropHooks<T> {
    fn default() -> Self {
        DropHooks(Default::default())
    }
}
impl<T> DropHooks<T> {
    pub fn call (&self, val: &mut T){
        if let Some(mut guard) = self.0.lock().unpoisoned().ok() {
            let actions = std::mem::take(guard.deref_mut());
            drop(guard);
            for action in actions {
                action(val)
            }
        }
    }
}
impl<T> Drop for DropHooks<T> {
    fn drop(&mut self) {
        if let Some(guard) = self.0.lock().unpoisoned().ok() {
            let length = guard.len();
            if length > 0 {
                panic!("{} DropHooks were not called while dropping!", length)
            }
        }
    }
}
impl<T> Debug for DropHooks<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let length = self.0.lock().unwrap().len();
        f.write_str("(")?;
        length.fmt(f)?;
        f.write_str(" DropActions)")
    }
}

#[derive(Default, Debug)]
pub struct AttachedDropHooks<T> {
    pub value: T,
    drop_actions: DropHooks<T>,
}
impl<T> Drop for AttachedDropHooks<T> {
    fn drop(&mut self) {
        self.drop_actions.call(&mut self.value)
    }
}
impl<T> AsRef<T> for AttachedDropHooks<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}
impl<T> AsMut<T> for AttachedDropHooks<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T> AttachedDropHooks<T> {
    pub fn new(value: T) -> AttachedDropHooks<T> {
        AttachedDropHooks {
            value,
            drop_actions: Default::default(),
        }
    }
}
impl<T> AttachDropHook<T> for AttachedDropHooks<T> {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce(&mut T) + Send + Sync>) {
        self.drop_actions.attach_drop_hook(action)
    }
}
