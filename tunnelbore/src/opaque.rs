pub struct Opaque<T>
where
    T: ?Sized,
{
    pub val: Box<T>,
}
impl<T> Opaque<T>
where
    T: ?Sized,
{
    pub fn new(x: Box<T>) -> Self {
        Opaque { val: x }
    }
}
impl<T> std::fmt::Debug for Opaque<T>
where
    T: ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str("<opaque>")
    }
}
impl<T> std::ops::Deref for Opaque<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &*self.val
    }
}
impl<T> std::ops::DerefMut for Opaque<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.val
    }
}
impl<T> From<Box<T>> for Opaque<T>
where
    T: ?Sized,
{
    fn from(x: Box<T>) -> Self {
        Self::new(x)
    }
}

#[macro_export]
macro_rules! opaque {
    ($x:expr) => {
        Opaque::new(Box::new($x))
    };
}
