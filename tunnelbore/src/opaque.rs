struct Opaque<T>(Box<T>)
where
    T: ?Sized;
impl<T> Opaque<T>
where
    T: ?Sized,
{
    pub fn new(x: Box<T>) -> Self {
        Opaque(x)
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

macro_rules! opaque {
    ($x:expr) => {
        Opaque::new(Box::new($x))
    };
}


