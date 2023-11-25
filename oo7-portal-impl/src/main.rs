use std::{
    collections::HashMap,
    future::pending,
    os::fd::{AsRawFd, FromRawFd},
    sync::{Arc, Mutex},
};

use async_std::io::WriteExt;
use futures::FutureExt;
use oo7::{
    dbus::{Algorithm, Service},
    zbus::{self, dbus_interface, zvariant, zvariant::Type},
};
use ring::rand::SecureRandom;
use serde::Serialize;
use zvariant::OwnedObjectPath;

const PORTAL_SECRET_SIZE: usize = 64;
const NAME: &str = "org.freedesktop.impl.portal.desktop.oo7";
const PATH: &str = "/org/freedesktop/portal/desktop";

#[derive(Serialize, PartialEq, Eq, Debug, Type)]
#[doc(hidden)]
enum ResponseType {
    Success = 0,
    Cancelled = 1,
    Other = 2,
}

#[derive(zbus::DBusError, Debug)]
enum Error {
    Msg(String),
}

impl Error {
    fn new(msg: &str) -> Error {
        Error::Msg(msg.to_string())
    }
}

impl From<oo7::dbus::Error> for Error {
    fn from(err: oo7::dbus::Error) -> Self {
        Error::new(&err.to_string())
    }
}

struct Secret;

#[dbus_interface(name = "org.freedesktop.impl.portal.Secret")]
impl Secret {
    #[dbus_interface(property, name = "version")]
    fn version(&self) -> u32 {
        0
    }

    #[dbus_interface(out_args("response", "results"))]
    async fn retrieve_secret(
        &self,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
        handle: OwnedObjectPath,
        app_id: &str,
        fd: zvariant::Fd,
        _options: HashMap<&str, zvariant::Value<'_>>,
    ) -> Result<(ResponseType, HashMap<&str, zvariant::OwnedValue>), Error> {
        tracing::debug!("Got request from {app_id} with options: {_options:?}");

        let (sender, receiver) = futures_channel::oneshot::channel();

        if let Err(err) = Request::serve(object_server, handle.clone(), sender).await {
            tracing::error!("Could not register object {handle}: {err}");
        }

        let fut_1 = async move {
            let res = match retrieve_secret_inner(app_id, fd).await {
                Ok(res) => Ok((ResponseType::Success, res)),
                Err(err) => {
                    tracing::error!("could not retrieve secret: {err}");
                    Ok((ResponseType::Other, HashMap::new()))
                }
            };

            // We do not accept Close request anymore here.
            tracing::debug!("Object {handle} handled");
            object_server
                .remove::<Request, &zvariant::OwnedObjectPath>(&handle)
                .await
                .unwrap();

            res
        };

        let fut_2 = async move {
            receiver.await.unwrap();
            Ok((ResponseType::Cancelled, HashMap::new()))
        };

        let t1 = fut_1.fuse();
        let t2 = fut_2.fuse();

        futures::pin_mut!(t1, t2);

        futures::select! {
            fut_1_res = t1 => fut_1_res,
            fut_2_res = t2 => fut_2_res,
        }
    }
}

fn generate_secret() -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut secret = [0; PORTAL_SECRET_SIZE];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(&mut secret)
        .map_err(|err| Error::new(&err.to_string()))?;
    Ok(zeroize::Zeroizing::new(secret.to_vec()))
}

async fn retrieve_secret_inner(
    app_id: &str,
    fd: zvariant::Fd,
) -> Result<HashMap<&'static str, zvariant::OwnedValue>, Error> {
    let service = Service::new(Algorithm::Encrypted)
        .await
        .or(Service::new(Algorithm::Plain).await)?;
    let collection = service.default_collection().await?;
    let attributes = HashMap::from([("app_id", app_id)]);

    let secret = if let Some(item) = collection
        .search_items(attributes.clone())
        .await
        .map_err(|err| Error::new(&err.to_string()))?
        .first()
    {
        item.secret().await?
    } else {
        tracing::debug!("Could not find secret for {app_id}, creating one");
        let secret = generate_secret()?;
        collection
            .create_item(
                &format!("Secret Portal token for {app_id}"),
                attributes,
                &secret,
                true,
                // TODO Find a better one.
                "text/plain",
            )
            .await?;

        secret
    };

    // Write the secret to the FD.
    let raw_fd = fd.as_raw_fd();
    let mut stream = unsafe { async_std::os::unix::net::UnixStream::from_raw_fd(raw_fd) };
    stream
        .write_all(&secret)
        .await
        .map_err(|e| Error::new(&e.to_string()))?;

    Ok(HashMap::new())
}

#[async_std::main]
async fn main() -> Result<(), zbus::Error> {
    tracing_subscriber::fmt::init();

    let backend = Secret;
    let cnx = zbus::ConnectionBuilder::session()?
        // .name(NAME)?
        .serve_at(PATH, backend)?
        .build()
        .await?;
    // NOTE For debugging.
    let flags = zbus::fdo::RequestNameFlags::ReplaceExisting
        | zbus::fdo::RequestNameFlags::AllowReplacement;
    cnx.request_name_with_flags(NAME, flags).await?;

    loop {
        pending::<()>().await;
    }
}

struct Request {
    handle_path: zvariant::OwnedObjectPath,
    sender: Arc<Mutex<Option<futures_channel::oneshot::Sender<()>>>>,
}

#[dbus_interface(name = "org.freedesktop.impl.portal.Request")]
impl Request {
    async fn close(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("Object {} closed", self.handle_path);
        server
            .remove::<Self, &zvariant::OwnedObjectPath>(&self.handle_path)
            .await?;

        if let Ok(mut guard) = self.sender.lock() {
            if let Some(sender) = (*guard).take() {
                // This will Err out if the receiver has been dropped.
                let _ = sender.send(());
            }
        }

        Ok(())
    }
}

impl Request {
    async fn serve(
        object_server: &zbus::ObjectServer,
        handle_path: OwnedObjectPath,
        sender: futures_channel::oneshot::Sender<()>,
    ) -> zbus::fdo::Result<()> {
        tracing::debug!("Handling object {:?}", handle_path.as_str());

        let iface = Request {
            handle_path: handle_path.clone(),
            sender: Arc::new(Mutex::new(Some(sender))),
        };

        object_server.at(handle_path, iface).await?;

        Ok(())
    }
}
