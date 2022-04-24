use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

// TODO: support secret service errors
// https://specifications.freedesktop.org/secret-service/latest/ch15.html
#[derive(Debug)]
pub enum Error {
    Zbus(zbus::Error),
    Deleted,
    Dismissed,
}

impl From<zbus::Error> for Error {
    fn from(e: zbus::Error) -> Self {
        Self::Zbus(e)
    }
}
impl From<zbus::fdo::Error> for Error {
    fn from(e: zbus::fdo::Error) -> Self {
        Self::Zbus(zbus::Error::FDO(Box::new(e)))
    }
}

impl From<zbus::zvariant::Error> for Error {
    fn from(e: zbus::zvariant::Error) -> Self {
        Self::Zbus(zbus::Error::Variant(e))
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zbus(err) => write!(f, "zbus error {err}"),
            Self::Deleted => write!(f, "Item/Collection was deleted, can no longer be used"),
            Self::Dismissed => write!(f, "Prompt was dismissed"),
        }
    }
}
