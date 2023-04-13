use crate::LockResultExt;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::sync::Mutex;

pub trait AttachDropHook {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce() + Send>);
}

#[derive(Default)]
pub struct DropHooks(Mutex<Vec<Box<dyn FnOnce() + Send>>>);
impl AttachDropHook for DropHooks {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce() + Send>) {
        let mut guard = self.0.lock().unwrap();
        guard.push(action);
    }
}
impl Drop for DropHooks {
    fn drop(&mut self) {
        if let Some(mut guard) = self.0.lock().unpoisoned().ok() {
            let actions = std::mem::take(guard.deref_mut());
            drop(guard);
            for action in actions {
                action()
            }
        }
    }
}
impl Debug for DropHooks {
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
    drop_actions: DropHooks,
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
impl<T> AttachDropHook for AttachedDropHooks<T> {
    fn attach_drop_hook(&self, action: Box<dyn FnOnce() + Send>) {
        self.drop_actions.attach_drop_hook(action)
    }
}
