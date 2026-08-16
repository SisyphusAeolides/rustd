// SPDX-License-Identifier: LGPL-2.1-or-later
//! D-Bus caller credential lookup and authorization policy.
//!
//! Privileged manager methods resolve the unique sender name through
//! `org.freedesktop.DBus.GetConnectionUnixUser` and fail closed when the bus
//! cannot provide credentials. Root callers are allowed directly; other
//! callers are authorized through `PolicyKit` using the same system-bus-name
//! subject form used by the RustD manager.
//!
//! Upstream reference: `src/shared/bus-polkit.c` and `src/core/dbus-util.c`
//! (v261).

use std::collections::HashMap;

/// Resolve the Unix UID associated with the calling D-Bus connection.
///
/// # Errors
/// Returns `AccessDenied` when the message has no sender or the bus daemon
/// cannot provide trustworthy credentials for that sender.
pub async fn caller_uid(
    connection: &zbus::Connection,
    header: &zbus::MessageHeader<'_>,
) -> zbus::fdo::Result<u32> {
    let sender = header.sender().cloned().ok_or_else(|| {
        zbus::fdo::Error::AccessDenied("unable to determine D-Bus caller identity".into())
    })?;
    let proxy = zbus::fdo::DBusProxy::new(connection).await.map_err(|_| {
        zbus::fdo::Error::AccessDenied("unable to query D-Bus caller credentials".into())
    })?;
    proxy
        .get_connection_unix_user(sender.into())
        .await
        .map_err(|_| {
            zbus::fdo::Error::AccessDenied("unable to query D-Bus caller credentials".into())
        })
}

/// Return the `PolicyKit` action used by the current manager method.
#[allow(clippy::redundant_closure_for_method_calls)]
fn manager_action(header: &zbus::MessageHeader<'_>) -> &'static str {
    manager_action_for_member(header.member().map(|member| member.as_str()))
}

fn manager_action_for_member(member: Option<&str>) -> &'static str {
    match member {
        Some("Reload" | "Reexecute") => "io.rustd.manager.reload",
        Some("SetEnvironment" | "UnsetEnvironment" | "UnsetAndSetEnvironment") => {
            "io.rustd.manager.environment"
        }
        _ => "io.rustd.manager.units",
    }
}

/// Authorize a privileged D-Bus manager method for the actual caller.
///
/// Root is accepted without contacting `PolicyKit`. Non-root callers are checked through
/// `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` using the unique
/// D-Bus sender name as a `system-bus-name` subject. `PolicyKit` absence or an
/// authorization transport error fails closed.
///
/// # Errors
/// Returns `AccessDenied` for unknown credentials, unavailable `PolicyKit`, or
/// an authorization denial.
pub async fn authorize_privileged_caller(
    connection: &zbus::Connection,
    header: &zbus::MessageHeader<'_>,
) -> zbus::fdo::Result<()> {
    let uid = caller_uid(connection, header).await?;
    let manager_uid = crate::native::current_uid();
    if sender_has_manager_privilege(manager_uid, uid) {
        return Ok(());
    }

    let sender = header.sender().ok_or_else(|| {
        zbus::fdo::Error::AccessDenied("unable to determine D-Bus caller identity".into())
    })?;
    let proxy = zbus::Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|_| zbus::fdo::Error::AccessDenied("polkit service unavailable".into()))?;

    let mut subject_details = HashMap::new();
    subject_details.insert("name", zbus::zvariant::Value::from(sender.as_str()));
    let details: HashMap<&str, &str> = HashMap::new();
    let action = manager_action(header);
    let (authorized, challenge, _returned_details): (bool, bool, HashMap<String, String>) = proxy
        .call(
            "CheckAuthorization",
            &(
                ("system-bus-name", subject_details),
                action,
                details,
                1u32,
                "",
            ),
        )
        .await
        .map_err(|_| zbus::fdo::Error::AccessDenied("polkit authorization failed".into()))?;

    if authorized {
        Ok(())
    } else if challenge {
        Err(zbus::fdo::Error::AccessDenied(
            "polkit authorization challenge was not satisfied".into(),
        ))
    } else {
        Err(zbus::fdo::Error::AccessDenied(
            "polkit authorization denied".into(),
        ))
    }
}

fn sender_has_manager_privilege(manager_uid: u32, sender_uid: u32) -> bool {
    sender_uid == manager_uid || (manager_uid != 0 && sender_uid == 0)
}

/// Result of a local authorization fast-path check.
pub enum AuthResult {
    /// The call is permitted.
    Allow,
    /// The call requires external authorization.
    Deny,
}

/// Check whether `caller_uid` is authorized without `PolicyKit`.
///
/// * If `caller_uid` is 0 (root), the call is always allowed.
/// * If the operation is not `privileged`, it is allowed for any caller.
/// * Otherwise external authorization is required.
#[must_use]
pub fn check_caller_uid(caller_uid: u32, privileged: bool) -> AuthResult {
    if caller_uid == 0 {
        return AuthResult::Allow;
    }
    if !privileged {
        return AuthResult::Allow;
    }
    AuthResult::Deny
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_privilege_matches_v261_uid_rules() {
        assert!(sender_has_manager_privilege(0, 0));
        assert!(!sender_has_manager_privilege(0, 1000));
        assert!(sender_has_manager_privilege(1000, 1000));
        assert!(sender_has_manager_privilege(1000, 0));
        assert!(!sender_has_manager_privilege(1000, 1001));
    }

    #[test]
    fn root_always_allowed() {
        assert!(matches!(check_caller_uid(0, true), AuthResult::Allow));
        assert!(matches!(check_caller_uid(0, false), AuthResult::Allow));
    }

    #[test]
    fn non_root_unprivileged_allowed() {
        assert!(matches!(check_caller_uid(1000, false), AuthResult::Allow));
    }

    #[test]
    fn non_root_privileged_requires_external_authorization() {
        assert!(matches!(check_caller_uid(1000, true), AuthResult::Deny));
    }

    #[test]
    fn manager_methods_use_native_polkit_actions() {
        for member in [
            "SetEnvironment",
            "UnsetEnvironment",
            "UnsetAndSetEnvironment",
        ] {
            assert_eq!(
                manager_action_for_member(Some(member)),
                "io.rustd.manager.environment"
            );
        }
        for member in ["Reload", "Reexecute"] {
            assert_eq!(
                manager_action_for_member(Some(member)),
                "io.rustd.manager.reload"
            );
        }
        assert_eq!(
            manager_action_for_member(Some("StartUnit")),
            "io.rustd.manager.units"
        );
    }
}
