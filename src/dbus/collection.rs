use std::{collections::HashMap, sync::Arc};

use crate::Result;

use super::{api, Item};

pub struct Collection<'a> {
    collection: Arc<api::Collection<'a>>,
    session: Arc<api::Session<'a>>,
}

impl<'a> Collection<'a> {
    pub(crate) fn new(
        session: Arc<api::Session<'a>>,
        collection: api::Collection<'a>,
    ) -> Collection<'a> {
        Self {
            collection: Arc::new(collection),
            session,
        }
    }

    pub async fn search_items(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Item<'_>>> {
        let items = self.collection.search_items(attributes).await?;
        Ok(items
            .into_iter()
            .map(|item| Item::new(self.session.clone(), item))
            .collect::<Vec<_>>())
    }

    /*
    pub async fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
    ) -> Result<Item<'_>> {
        let item = self.collection.create_item(label, attributes, secret, replace).await?;
        Ok(Item::new(item))
    }
    */
}
