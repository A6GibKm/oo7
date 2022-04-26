use std::collections::HashMap;

use async_std::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    dbus::{self, Algorithm, DEFAULT_COLLECTION},
    portal, Result,
};

/// A [Secret Service](crate::dbus) or [file](crate::portal) backed keyring implementation.
///
/// It will automatically use the file backend if the application is sandboxed
/// and otherwise falls back to the DBus service.
///
/// The File backend requires a [`org.freedesktop.portal.Secret`](https://flatpak.github.io/xdg-desktop-portal/#gdbus-org.freedesktop.portal.Secret) implementation
/// to retrieve the key that will be used to encrypt the backend file.
pub enum Keyring {
    #[doc(hidden)]
    File(portal::Keyring),
    #[doc(hidden)]
    DBus(dbus::Collection<'static>),
}

impl Keyring {
    /// Create a new instance of the Keyring.
    pub async fn new() -> Result<Self> {
        let is_sandboxed = crate::is_sandboxed();
        if is_sandboxed {
            Ok(Self::File(portal::Keyring::load_default().await?))
        } else {
            let service = dbus::Service::new(Algorithm::Encrypted).await?;
            let collection = match service.default_collection().await {
                Ok(Some(c)) => Ok(c),
                Ok(None) => {
                    service
                        .create_collection("Login", Some(DEFAULT_COLLECTION))
                        .await
                }
                Err(e) => Err(e),
            }?;
            Ok(Self::DBus(collection))
        }
    }

    /// Retrieve all the items.
    ///
    /// If using the Secret Service, it will retrieve all the items in the [`DEFAULT_COLLECTION`].
    pub async fn items(&self) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.items().await?;
                items.into_iter().map(Item::for_file).collect::<Vec<_>>()
            }
        };
        Ok(items)
    }

    /// Create a new item.
    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
    ) -> Result<()> {
        match self {
            Self::DBus(backend) => {
                backend
                    .create_item(label, attributes, secret, replace, "text/plain")
                    .await?;
            }
            Self::File(backend) => {
                backend
                    .create_item(label, attributes, secret, replace)
                    .await?;
            }
        };
        Ok(())
    }

    /// Find items based on their attributes.
    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item>> {
        let items = match self {
            Self::DBus(backend) => {
                let items = backend.search_items(attributes).await?;
                items.into_iter().map(Item::for_dbus).collect::<Vec<_>>()
            }
            Self::File(backend) => {
                let items = backend.search_items(attributes).await?;
                items.into_iter().map(Item::for_file).collect::<Vec<_>>()
            }
        };
        Ok(items)
    }
}

/// A generic secret with a label and attributes.
pub enum Item {
    #[doc(hidden)]
    File(Mutex<crate::portal::Item>),
    #[doc(hidden)]
    DBus(dbus::Item<'static>),
}

impl Item {
    fn for_file(item: portal::Item) -> Self {
        Self::File(Mutex::new(item))
    }

    fn for_dbus(item: dbus::Item<'static>) -> Self {
        Self::DBus(item)
    }

    /// The item label.
    pub async fn label(&self) -> Result<String> {
        let label = match self {
            Self::File(item) => item.lock().await.label().to_owned(),
            Self::DBus(item) => item.label().await?,
        };
        Ok(label)
    }

    /// Sets the item label.
    pub async fn set_label(&self, label: &str) -> Result<()> {
        match self {
            Self::File(item) => item.lock().await.set_label(label),
            Self::DBus(item) => item.set_label(label).await?,
        };
        Ok(())
    }

    /// Retrieve the item attributes.
    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        let attributes = match self {
            Self::File(item) => item
                .lock()
                .await
                .attributes()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            Self::DBus(item) => item.attributes().await?,
        };
        Ok(attributes)
    }

    /// Sets a new secret.
    pub async fn set_secret<P: AsRef<[u8]>>(&self, secret: P) -> Result<()> {
        match self {
            Self::File(item) => {
                item.lock().await.set_secret(secret);
            }
            Self::DBus(item) => item.set_secret(secret, "text/plain").await?,
        };
        Ok(())
    }

    /// Retrieves the stored secret.
    pub async fn secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        let secret = match self {
            Self::File(item) => item.lock().await.secret(),
            Self::DBus(item) => item.secret().await?,
        };
        Ok(secret)
    }
}
