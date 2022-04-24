use std::{collections::HashMap, sync::Arc};

use futures::lock::Mutex;

use crate::{Algorithm, Result, Error};

use super::{api, Item};

pub struct Collection<'a> {
    collection: Arc<api::Collection<'a>>,
    session: Arc<api::Session<'a>>,
    algorithm: Arc<Algorithm>,
    /// Defines whether the Collection has been deleted or not
    available: Mutex<bool>,
}

impl<'a> Collection<'a> {
    pub(crate) fn new(
        session: Arc<api::Session<'a>>,
        algorithm: Arc<Algorithm>,
        collection: api::Collection<'a>,
    ) -> Collection<'a> {
        Self {
            collection: Arc::new(collection),
            session,
            algorithm,
            available: Mutex::new(true),
        }
    }

    pub(crate) async fn is_available(&self) -> bool {
        *self.available.lock().await
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let items = self.collection.search_items(attributes).await?;
            Ok(items
                .into_iter()
                .map(|item| Item::new(Arc::clone(&self.session), Arc::clone(&self.algorithm), item))
                .collect::<Vec<_>>())
        }
    }

    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Item<'_>> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            let secret = api::Secret::new(
                Arc::clone(&self.algorithm),
                Arc::clone(&self.session),
                secret,
                content_type,
            );

            let item = self
                .collection
                .create_item(label, attributes, &secret, replace)
                .await?;

            Ok(Item::new(
                Arc::clone(&self.session),
                Arc::clone(&self.algorithm),
                item,
            ))
        }
    }

    pub async fn delete(&self) -> Result<()> {
        if !self.is_available().await {
            Err(Error::Deleted)
        } else {
            self.collection.delete().await?;
            *self.available.lock().await = false;
            Ok(())
        }
    }
}
