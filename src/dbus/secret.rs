use serde::{ser::SerializeTuple, Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, Type};

use super::Session;
use crate::Result;

#[derive(Debug, Serialize, Deserialize, Type)]
#[zvariant(signature = "(oayays)")]
pub(crate) struct SecretInner(pub OwnedObjectPath, pub Vec<u8>, pub Vec<u8>, pub String);

#[derive(Debug, Type)]
#[zvariant(signature = "(oayays)")]
pub struct Secret<'a> {
    pub(crate) session: Session<'a>,
    pub(crate) parameteres: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) content_type: String,
}

impl<'a> Secret<'a> {
    pub(crate) async fn from_inner(
        cnx: &zbus::Connection,
        inner: SecretInner,
    ) -> Result<Secret<'_>> {
        let secret = Secret {
            session: Session::new(cnx, inner.0).await?,
            parameteres: inner.1,
            value: inner.2,
            content_type: inner.3,
        };
        Ok(secret)
    }

    /// Session used to encode the secret
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Algorithm dependent parameters for secret value encoding
    pub fn parameters(&self) -> &[u8] {
        &self.parameteres
    }

    /// Possibly encoded secret value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Content type of the secret
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

impl<'a> Serialize for Secret<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple_serializer = serializer.serialize_tuple(4)?;
        tuple_serializer.serialize_element(self.session().inner().path())?;
        tuple_serializer.serialize_element(self.parameters())?;
        tuple_serializer.serialize_element(self.value())?;
        tuple_serializer.serialize_element(self.content_type())?;
        tuple_serializer.end()
    }
}
