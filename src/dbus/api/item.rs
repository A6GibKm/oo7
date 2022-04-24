use std::{collections::HashMap, fmt, hash::Hash, time::Duration};

use super::{secret::SecretInner, Prompt, Secret, Session, Unlockable, DESTINATION};
use crate::Result;
use serde::Serialize;
use zbus::zvariant::ObjectPath;

#[doc(alias = "org.freedesktop.Secret.Item")]
pub struct Item<'a>(zbus::Proxy<'a>);

impl<'a> Item<'a> {
    pub async fn new<P>(connection: &zbus::Connection, object_path: P) -> Result<Item<'a>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let inner = zbus::ProxyBuilder::new_bare(connection)
            .interface("org.freedesktop.Secret.Item")?
            .path(object_path)?
            .destination(DESTINATION)?
            .build()
            .await?;
        Ok(Self(inner))
    }

    pub(crate) async fn from_paths<P>(
        connection: &zbus::Connection,
        paths: Vec<P>,
    ) -> Result<Vec<Item<'a>>>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let mut items = Vec::with_capacity(paths.capacity());
        for path in paths.into_iter() {
            items.push(Self::new(connection, path).await?);
        }
        Ok(items)
    }

    pub fn inner(&self) -> &zbus::Proxy {
        &self.0
    }

    #[doc(alias = "Locked")]
    pub async fn is_locked(&self) -> Result<bool> {
        self.inner()
            .get_property("Locked")
            .await
            .map_err(From::from)
    }

    pub async fn label(&self) -> Result<String> {
        self.inner().get_property("Label").await.map_err(From::from)
    }

    pub async fn set_label(&self, label: &str) -> Result<()> {
        self.inner()
            .set_property("Label", label)
            .await
            .map_err::<zbus::fdo::Error, _>(From::from)?;
        Ok(())
    }

    pub async fn created(&self) -> Result<Duration> {
        let secs = self.inner().get_property::<u64>("Created").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn modified(&self) -> Result<Duration> {
        let secs = self.inner().get_property::<u64>("Modified").await?;
        Ok(Duration::from_secs(secs))
    }

    pub async fn attributes(&self) -> Result<HashMap<String, String>> {
        self.inner()
            .get_property("Attributes")
            .await
            .map_err(From::from)
    }

    pub async fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        self.inner()
            .set_property("Attributes", attributes)
            .await
            .map_err::<zbus::fdo::Error, _>(From::from)?;
        Ok(())
    }

    pub async fn delete(&self) -> Result<()> {
        let prompt_path = self
            .inner()
            .call_method("Delete", &())
            .await?
            .body::<zbus::zvariant::OwnedObjectPath>()?;
        if let Some(prompt) = Prompt::new(self.inner().connection(), prompt_path).await? {
            let _ = prompt.receive_completed().await?;
        }
        Ok(())
    }

    #[doc(alias = "GetSecret")]
    pub async fn secret(&self, session: &Session<'_>) -> Result<Secret<'_>> {
        let inner = self
            .inner()
            .call_method("GetSecret", &(session))
            .await?
            .body::<SecretInner>()?;
        Secret::from_inner(self.inner().connection(), inner).await
    }

    #[doc(alias = "SetSecret")]
    pub async fn set_secret(&self, secret: &Secret<'_>) -> Result<()> {
        self.inner().call_method("SetSecret", &(secret)).await?;
        Ok(())
    }
}

impl<'a> Serialize for Item<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ObjectPath::serialize(self.inner().path(), serializer)
    }
}

impl<'a> zbus::zvariant::Type for Item<'a> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        ObjectPath::signature()
    }
}

impl<'a> PartialEq for Item<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.inner().path() == other.inner().path()
    }
}

impl<'a> Eq for Item<'a> {}

impl<'a> Hash for Item<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner().path().hash(state);
    }
}

impl<'a> fmt::Debug for Item<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Item")
            .field(&self.inner().path().as_str())
            .finish()
    }
}

impl<'a> Unlockable for Item<'a> {}
