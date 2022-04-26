/*!
Keyring

```ignore
# std::env::set_var("XDG_DATA_HOME", "/tmp/doctest");
# use oo7::keyring::{self, Error};
# use std::collections::HashMap;
# async_std::task::block_on(async {
#
keyring::insert_replace(&keyring::Item::new(
    "My Label",
    HashMap::from([("account", "alice")]),
    b"My Password",
))
.await?;

let items = keyring::lookup(HashMap::from([("account", "alice")])).await?;
assert_eq!(*items[0].password(), b"My Password");

keyring::remove(HashMap::from([("account", "alice")])).await?;
#
# Ok::<(), Error>(())
# }).unwrap()
```

*/
use async_std::prelude::*;

use async_std::path::{Path, PathBuf};
use async_std::{fs, io};
use std::collections::HashMap;

mod error;
mod helpers;
pub mod keyring;
pub use helpers::*;
mod secret;

pub(crate) use secret::retrieve;

pub use error::Error;

pub struct Keyring {
    keyring: keyring::Keyring,
    path: PathBuf,
    /// Times are stored before reading the file to detect
    /// file changes before writing
    mtime: Option<std::time::SystemTime>,
    key: crate::Key,
}

impl Keyring {
    /// Load from default keyring file
    pub async fn load_default() -> Result<Self, Error> {
        let secret = crate::portal::retrieve().await?;
        Self::load(keyring::Keyring::default_path()?, &secret).await
    }

    /// Load from a keyring file
    pub async fn load(path: impl AsRef<Path>, secret: &[u8]) -> Result<Self, Error> {
        let (mtime, keyring) = match fs::File::open(&path).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => (None, keyring::Keyring::new()),
            Err(err) => return Err(err.into()),
            Ok(mut file) => {
                let mtime = file.metadata().await?.modified().ok();

                let mut content = Vec::new();
                file.read_to_end(&mut content).await?;

                let keyring = keyring::Keyring::try_from(content.as_slice())?;

                (mtime, keyring)
            }
        };

        let key = keyring.derive_key(secret);

        Ok(Self {
            keyring,
            path: path.as_ref().to_path_buf(),
            mtime,
            key,
        })
    }

    pub async fn write(self) -> Result<(), Error> {
        self.keyring.dump(self.path, self.mtime).await
    }
}
