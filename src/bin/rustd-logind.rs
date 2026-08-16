// SPDX-License-Identifier: LGPL-2.1-or-later
//! `org.freedesktop.login1` compatibility daemon for RustD.

#![allow(clippy::unused_self, clippy::needless_pass_by_value)]

use std::sync::atomic::{AtomicU64, Ordering};

use rustd::logind::{self, Session};
use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

const BUS_NAME: &str = "org.freedesktop.login1";
const ROOT: &str = "/org/freedesktop/login1";

fn path(path: String) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(path).map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
}

fn dbus_error(error: std::io::Error) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(error.to_string())
}

#[derive(Default)]
struct Manager {
    next_session: AtomicU64,
}

type SessionListEntry = (String, u32, String, String, String, OwnedObjectPath);

#[interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn list_sessions(&self) -> zbus::fdo::Result<Vec<SessionListEntry>> {
        logind::sessions()
            .into_iter()
            .map(|session| {
                Ok((
                    session.id.clone(),
                    session.uid,
                    session.user,
                    session.seat,
                    session.tty,
                    path(logind::session_path(&session.id))?,
                ))
            })
            .collect()
    }

    fn list_users(&self) -> zbus::fdo::Result<Vec<(u32, String, OwnedObjectPath)>> {
        let mut output = Vec::new();
        for session in logind::sessions() {
            if !output.iter().any(|(uid, _, _)| *uid == session.uid) {
                output.push((
                    session.uid,
                    session.user,
                    path(logind::user_path(session.uid))?,
                ));
            }
        }
        Ok(output)
    }

    fn list_seats(&self) -> zbus::fdo::Result<Vec<(String, OwnedObjectPath)>> {
        let mut output = Vec::new();
        for session in logind::sessions() {
            if !output.iter().any(|(seat, _)| *seat == session.seat) {
                output.push((
                    session.seat.clone(),
                    path(logind::seat_path(&session.seat))?,
                ));
            }
        }
        Ok(output)
    }

    fn get_session(&self, id: String) -> zbus::fdo::Result<OwnedObjectPath> {
        logind::session(&id).ok_or_else(|| zbus::fdo::Error::Failed("No such session".into()))?;
        path(logind::session_path(&id))
    }

    fn get_user(&self, uid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        logind::sessions()
            .iter()
            .any(|session| session.uid == uid)
            .then(|| path(logind::user_path(uid)))
            .ok_or_else(|| zbus::fdo::Error::Failed("No such user".into()))?
    }

    fn get_seat(&self, seat: String) -> zbus::fdo::Result<OwnedObjectPath> {
        logind::sessions()
            .iter()
            .any(|session| session.seat == seat)
            .then(|| path(logind::seat_path(&seat)))
            .ok_or_else(|| zbus::fdo::Error::Failed("No such seat".into()))?
    }

    /// Minimal `CreateSession` compatible entry point. The final `properties`
    /// array is accepted but currently ignored; PAM supplies the other fields.
    #[allow(clippy::too_many_arguments)]
    async fn create_session(
        &self,
        uid: u32,
        pid: u32,
        service: String,
        session_type: String,
        class: String,
        seat: String,
        vtnr: u32,
        tty: String,
        display: String,
        remote: bool,
        remote_user: String,
        remote_host: String,
        properties: Vec<(String, zbus::zvariant::OwnedValue)>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<(
        String,
        OwnedObjectPath,
        String,
        u32,
        String,
        OwnedObjectPath,
    )> {
        let _ = (
            pid,
            vtnr,
            display,
            remote,
            remote_user,
            remote_host,
            properties,
        );
        let number = self.next_session.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("rustd-{uid}-{number}");
        let user = passwd_name(uid).unwrap_or_else(|| uid.to_string());
        let session = Session {
            id: id.clone(),
            uid,
            gid: uid,
            user: user.clone(),
            seat: if seat.is_empty() {
                "seat0".into()
            } else {
                seat
            },
            tty,
            service,
            session_type: if session_type.is_empty() {
                "unspecified".into()
            } else {
                session_type
            },
            class: if class.is_empty() {
                "user".into()
            } else {
                class
            },
            leader: std::process::id(),
            state: "active".into(),
            locked: false,
        };
        logind::save(&session).map_err(dbus_error)?;
        let object = path(logind::session_path(&id))?;
        connection
            .object_server()
            .at(object.clone(), SessionObject { id: id.clone() })
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        let _ = connection
            .object_server()
            .at(
                logind::user_path(session.uid),
                UserObject { uid: session.uid },
            )
            .await;
        let _ = connection
            .object_server()
            .at(
                logind::seat_path(&session.seat),
                SeatObject {
                    id: session.seat.clone(),
                },
            )
            .await;
        Ok((
            id,
            object,
            user,
            0,
            String::new(),
            path(logind::seat_path(&session.seat))?,
        ))
    }

    async fn terminate_session(
        &self,
        id: String,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        let object = path(logind::session_path(&id))?;
        logind::remove(&id).map_err(dbus_error)?;
        let _ = connection
            .object_server()
            .remove::<SessionObject, _>(object)
            .await;
        Ok(())
    }

    fn activate_session(&self, id: String) -> zbus::fdo::Result<()> {
        if logind::session(&id).is_some() {
            Ok(())
        } else {
            Err(zbus::fdo::Error::Failed("No such session".into()))
        }
    }

    fn lock_session(&self, id: String) -> zbus::fdo::Result<()> {
        set_locked(&id, true)
    }
    fn unlock_session(&self, id: String) -> zbus::fdo::Result<()> {
        set_locked(&id, false)
    }
    fn inhibit(
        &self,
        what: String,
        who: String,
        why: String,
        mode: String,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        let _ = (what, who, why, mode);
        Err(zbus::fdo::Error::NotSupported(
            "inhibitor file descriptors are not implemented".into(),
        ))
    }
    fn can_power_off(&self) -> &str {
        "no"
    }
    fn can_reboot(&self) -> &str {
        "no"
    }
    fn can_suspend(&self) -> &str {
        "no"
    }
    fn can_hibernate(&self) -> &str {
        "no"
    }
    fn prepare_for_shutdown(&self, active: bool) {
        let _ = active;
    }
    fn prepare_for_sleep(&self, active: bool) {
        let _ = active;
    }
}

fn set_locked(id: &str, locked: bool) -> zbus::fdo::Result<()> {
    let mut session =
        logind::session(id).ok_or_else(|| zbus::fdo::Error::Failed("No such session".into()))?;
    session.locked = locked;
    logind::save(&session).map_err(dbus_error)
}

struct SessionObject {
    id: String,
}
#[interface(name = "org.freedesktop.login1.Session")]
impl SessionObject {
    #[zbus(property)]
    fn id(&self) -> String {
        self.id.clone()
    }
    #[zbus(property)]
    fn state(&self) -> String {
        logind::session(&self.id).map_or_else(|| "closing".into(), |s| s.state)
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        let session = logind::session(&self.id).unwrap_or_default();
        (
            session.uid,
            path(logind::user_path(session.uid)).expect("valid fixed object path"),
        )
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        let session = logind::session(&self.id).unwrap_or_default();
        (
            session.seat.clone(),
            path(logind::seat_path(&session.seat)).expect("valid escaped object path"),
        )
    }
    #[zbus(property)]
    fn tty(&self) -> String {
        logind::session(&self.id).map(|s| s.tty).unwrap_or_default()
    }
    #[zbus(property)]
    fn service(&self) -> String {
        logind::session(&self.id)
            .map(|s| s.service)
            .unwrap_or_default()
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        logind::session(&self.id).is_some_and(|s| s.locked)
    }
}

struct UserObject {
    uid: u32,
}
#[interface(name = "org.freedesktop.login1.User")]
impl UserObject {
    #[zbus(property)]
    fn uid(&self) -> u32 {
        self.uid
    }
    #[zbus(property)]
    fn name(&self) -> String {
        logind::sessions()
            .into_iter()
            .find(|s| s.uid == self.uid)
            .map(|s| s.user)
            .unwrap_or_default()
    }
    #[zbus(property)]
    fn state(&self) -> &str {
        "active"
    }
    #[zbus(property)]
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter(|s| s.uid == self.uid)
            .filter_map(|s| {
                path(logind::session_path(&s.id))
                    .ok()
                    .map(|object| (s.id, object))
            })
            .collect()
    }
}

struct SeatObject {
    id: String,
}
#[interface(name = "org.freedesktop.login1.Seat")]
impl SeatObject {
    #[zbus(property)]
    fn id(&self) -> String {
        self.id.clone()
    }
    #[zbus(property)]
    fn can_multi_session(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn can_tty(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn can_graphical(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn sessions(&self) -> Vec<(String, OwnedObjectPath)> {
        logind::sessions()
            .into_iter()
            .filter(|s| s.seat == self.id)
            .filter_map(|s| {
                path(logind::session_path(&s.id))
                    .ok()
                    .map(|object| (s.id, object))
            })
            .collect()
    }
}

fn passwd_name(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            fields
                .nth(1)?
                .parse::<u32>()
                .ok()
                .filter(|value| *value == uid)
                .map(|_| name.to_owned())
        })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    logind::prepare()?;
    let connection = zbus::Connection::system().await?;
    connection
        .object_server()
        .at(ROOT, Manager::default())
        .await?;
    for session in logind::sessions() {
        connection
            .object_server()
            .at(
                logind::session_path(&session.id),
                SessionObject {
                    id: session.id.clone(),
                },
            )
            .await?;
        let _ = connection
            .object_server()
            .at(
                logind::user_path(session.uid),
                UserObject { uid: session.uid },
            )
            .await;
        let _ = connection
            .object_server()
            .at(
                logind::seat_path(&session.seat),
                SeatObject { id: session.seat },
            )
            .await;
    }
    connection.request_name(BUS_NAME).await?;
    rustd::native::notify_ready()?;
    std::future::pending::<()>().await;
    Ok(())
}
