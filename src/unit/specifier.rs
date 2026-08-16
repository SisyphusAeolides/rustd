// SPDX-License-Identifier: LGPL-2.1-or-later
//! Specifier expansion for systemd unit file values.
//!
//! Expands `%`-prefixed tokens in unit file values before they are used by
//! the service manager.  All specifiers from the v261 `systemd.unit(5)` man
//! page are handled.
//!
//! Upstream reference: `src/shared/specifier.c specifier_printf()` (v261)

use std::path::{Path, PathBuf};

/// Context required to expand specifiers in a unit file value.
#[derive(Debug, Clone)]
pub struct SpecifierContext {
    /// Full unit name, e.g. `"getty@tty1.service"`.
    pub unit_name: String,
    /// Prefix (part before `@`), e.g. `"getty"`.
    pub prefix: String,
    /// Instance (part between `@` and `.`), e.g. `"tty1"`. Empty for non-template units.
    pub instance: String,
    /// Unit type suffix, e.g. `"service"`.
    pub suffix: String,
    /// Runtime directory base, e.g. `"/run"`.
    pub runtime_dir: PathBuf,
    /// State directory base, e.g. `"/var/lib"`.
    pub state_dir: PathBuf,
    /// Cache directory base, e.g. `"/var/cache"`.
    pub cache_dir: PathBuf,
    /// Logs directory base, e.g. `"/var/log"`.
    pub logs_dir: PathBuf,
    /// Configuration directory base, e.g. `"/etc"`.
    pub config_dir: PathBuf,
    /// Host machine-id (32 hex chars), read from `/etc/machine-id`.
    pub machine_id: String,
    /// Boot ID, read from `/proc/sys/kernel/random/boot_id`.
    pub boot_id: String,
    /// Hostname.
    pub hostname: String,
    /// Kernel release string from `uname -r`.
    pub kernel_release: String,
    /// User name of the manager process owner.
    pub user_name: String,
    /// UID of the manager process owner.
    pub uid: u32,
    /// Group name of the manager process owner.
    pub group_name: String,
    /// GID of the manager process owner.
    pub gid: u32,
    /// Home directory of the manager process owner.
    pub home_dir: PathBuf,
    /// Shell of the manager process owner.
    pub shell: PathBuf,
}

impl SpecifierContext {
    /// Build a `SpecifierContext` for the system manager (PID 1 / root).
    ///
    /// Reads machine-id, boot-id, hostname, and kernel-release from the live
    /// system.  Falls back to empty strings on read error.
    #[must_use]
    pub fn for_system_unit(unit_name: &str) -> Self {
        let (prefix, instance, suffix) = split_unit_name(unit_name);

        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_default()
            .trim()
            .replace('-', "");
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let kernel_release = {
            let mut u: libc::utsname = unsafe { std::mem::zeroed() };
            if unsafe { libc::uname(&mut u) } == 0 {
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(u.release.as_ptr().cast(), u.release.len())
                };
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end]).into_owned()
            } else {
                String::new()
            }
        };

        Self {
            unit_name: unit_name.to_owned(),
            prefix,
            instance,
            suffix,
            runtime_dir: PathBuf::from("/run"),
            state_dir: PathBuf::from("/var/lib"),
            cache_dir: PathBuf::from("/var/cache"),
            logs_dir: PathBuf::from("/var/log"),
            config_dir: PathBuf::from("/etc"),
            machine_id,
            boot_id,
            hostname,
            kernel_release,
            user_name: "root".to_owned(),
            uid: 0,
            group_name: "root".to_owned(),
            gid: 0,
            home_dir: PathBuf::from("/root"),
            shell: PathBuf::from("/bin/sh"),
        }
    }

    /// Build a `SpecifierContext` for a per-user manager.
    #[must_use]
    pub fn for_user_unit(unit_name: &str) -> Self {
        let mut ctx = Self::for_system_unit(unit_name);
        let uid = unsafe { libc::getuid() };
        let group_id = unsafe { libc::getgid() };
        let user_name = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| uid.to_string());
        let home_dir = std::env::var_os("HOME").map_or_else(
            || PathBuf::from(format!("/home/{user_name}")),
            PathBuf::from,
        );
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map_or_else(|| PathBuf::from(format!("/run/user/{uid}")), PathBuf::from);
        let state_dir = std::env::var_os("XDG_STATE_HOME")
            .map_or_else(|| home_dir.join(".local/state"), PathBuf::from);
        let cache_dir = std::env::var_os("XDG_CACHE_HOME")
            .map_or_else(|| home_dir.join(".cache"), PathBuf::from);
        let config_dir = std::env::var_os("XDG_CONFIG_HOME")
            .map_or_else(|| home_dir.join(".config"), PathBuf::from);
        let shell =
            std::env::var_os("SHELL").map_or_else(|| PathBuf::from("/bin/sh"), PathBuf::from);

        ctx.runtime_dir = runtime_dir;
        ctx.state_dir.clone_from(&state_dir);
        ctx.cache_dir = cache_dir;
        ctx.logs_dir = state_dir.join("log");
        ctx.config_dir = config_dir;
        ctx.user_name = user_name;
        ctx.uid = uid;
        ctx.group_name = group_id.to_string();
        ctx.gid = group_id;
        ctx.home_dir = home_dir;
        ctx.shell = shell;
        ctx
    }
}

/// Split a unit name into `(prefix, instance, suffix)`.
///
/// `"getty@tty1.service"` → `("getty", "tty1", "service")`
/// `"sshd.service"`       → `("sshd",  "",     "service")`
/// `"getty@.service"`     → `("getty", "",      "service")`
#[must_use]
pub fn split_unit_name(name: &str) -> (String, String, String) {
    let (base, suffix) = if let Some(dot) = name.rfind('.') {
        (&name[..dot], name[dot + 1..].to_owned())
    } else {
        (name, String::new())
    };

    if let Some(at) = base.find('@') {
        (base[..at].to_owned(), base[at + 1..].to_owned(), suffix)
    } else {
        (base.to_owned(), String::new(), suffix)
    }
}

/// Unescape a systemd unit name component: replace `-` with `/`.
///
/// Upstream: `src/basic/unit-name.c unit_name_path_unescape()` (v261)
fn unescape_name(s: &str) -> String {
    s.replace('-', "/")
}

/// Expand all `%`-specifiers in `value` using `ctx`.
///
/// Unknown specifiers pass through unchanged, matching upstream behaviour.
#[must_use]
pub fn expand(value: &str, ctx: &SpecifierContext) -> String {
    let mut result = String::with_capacity(value.len() + 16);
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '%' || i + 1 >= chars.len() {
            result.push(chars[i]);
            i += 1;
            continue;
        }

        let spec = chars[i + 1];
        let replacement: Option<String> = match spec {
            'n' => Some(ctx.unit_name.clone()),
            'N' => Some(unescape_name(&ctx.unit_name)),
            'p' => Some(ctx.prefix.clone()),
            'P' => Some(unescape_name(&ctx.prefix)),
            'i' => Some(ctx.instance.clone()),
            'I' => Some(unescape_name(&ctx.instance)),
            'f' => {
                let base = if ctx.instance.is_empty() {
                    &ctx.prefix
                } else {
                    &ctx.instance
                };
                Some(format!("/{}", unescape_name(base)))
            }
            't' => Some(ctx.runtime_dir.display().to_string()),
            'S' => Some(ctx.state_dir.display().to_string()),
            'C' => Some(ctx.cache_dir.display().to_string()),
            'L' => Some(ctx.logs_dir.display().to_string()),
            'E' => Some(ctx.config_dir.display().to_string()),
            'm' => Some(ctx.machine_id.clone()),
            'b' => Some(ctx.boot_id.clone()),
            'H' => Some(ctx.hostname.clone()),
            'v' => Some(ctx.kernel_release.clone()),
            'u' => Some(ctx.user_name.clone()),
            'U' => Some(ctx.uid.to_string()),
            'g' => Some(ctx.group_name.clone()),
            'G' => Some(ctx.gid.to_string()),
            'h' => Some(ctx.home_dir.display().to_string()),
            's' => Some(ctx.shell.display().to_string()),
            '%' => Some("%".to_owned()),
            _ => None,
        };

        if let Some(s) = replacement {
            result.push_str(&s);
            i += 2;
        } else {
            result.push('%');
            i += 1;
        }
    }

    result
}

/// Expand specifiers and resolve the result as a path relative to `base`
/// if not already absolute.
#[must_use]
pub fn expand_path(value: &str, ctx: &SpecifierContext, base: &Path) -> PathBuf {
    let expanded = expand(value, ctx);
    let p = Path::new(&expanded);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(unit: &str) -> SpecifierContext {
        let (prefix, instance, suffix) = split_unit_name(unit);
        SpecifierContext {
            unit_name: unit.to_owned(),
            prefix,
            instance,
            suffix,
            runtime_dir: "/run".into(),
            state_dir: "/var/lib".into(),
            cache_dir: "/var/cache".into(),
            logs_dir: "/var/log".into(),
            config_dir: "/etc".into(),
            machine_id: "aabbcc".to_owned(),
            boot_id: "11223344".to_owned(),
            hostname: "myhost".to_owned(),
            kernel_release: "6.8.0".to_owned(),
            user_name: "root".to_owned(),
            uid: 0,
            group_name: "root".to_owned(),
            gid: 0,
            home_dir: "/root".into(),
            shell: "/bin/sh".into(),
        }
    }

    #[test]
    fn unit_name_specifiers() {
        let c = ctx("sshd.service");
        assert_eq!(expand("%n", &c), "sshd.service");
        assert_eq!(expand("%p", &c), "sshd");
        assert_eq!(expand("%i", &c), "");
    }

    #[test]
    fn template_instance() {
        let c = ctx("getty@tty1.service");
        assert_eq!(expand("%p", &c), "getty");
        assert_eq!(expand("%i", &c), "tty1");
        assert_eq!(expand("%n", &c), "getty@tty1.service");
    }

    #[test]
    fn user_dirs_follow_xdg_environment() {
        let home = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_state = std::env::var_os("XDG_STATE_HOME");
        let old_cache = std::env::var_os("XDG_CACHE_HOME");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("HOME", home.path());
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("XDG_STATE_HOME", home.path().join("state"));
        std::env::set_var("XDG_CACHE_HOME", home.path().join("cache"));
        std::env::set_var("XDG_CONFIG_HOME", home.path().join("config"));
        let ctx = SpecifierContext::for_user_unit("demo.service");
        assert_eq!(ctx.runtime_dir, runtime.path());
        assert_eq!(ctx.state_dir, home.path().join("state"));
        assert_eq!(ctx.cache_dir, home.path().join("cache"));
        assert_eq!(ctx.config_dir, home.path().join("config"));
        assert_eq!(ctx.home_dir, home.path());
        for (key, value) in [
            ("HOME", old_home),
            ("XDG_RUNTIME_DIR", old_runtime),
            ("XDG_STATE_HOME", old_state),
            ("XDG_CACHE_HOME", old_cache),
            ("XDG_CONFIG_HOME", old_config),
        ] {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn dirs() {
        let c = ctx("foo.service");
        assert_eq!(expand("%t", &c), "/run");
        assert_eq!(expand("%S", &c), "/var/lib");
        assert_eq!(expand("%C", &c), "/var/cache");
        assert_eq!(expand("%E", &c), "/etc");
    }

    #[test]
    fn double_percent() {
        let c = ctx("foo.service");
        assert_eq!(expand("100%%", &c), "100%");
        assert_eq!(expand("%%n", &c), "%n");
    }

    #[test]
    fn unknown_specifier_passthrough() {
        let c = ctx("foo.service");
        assert_eq!(expand("%z", &c), "%z");
    }

    #[test]
    fn split_names() {
        assert_eq!(
            split_unit_name("sshd.service"),
            ("sshd".into(), String::new(), "service".into())
        );
        assert_eq!(
            split_unit_name("getty@tty1.service"),
            ("getty".into(), "tty1".into(), "service".into())
        );
        assert_eq!(
            split_unit_name("getty@.service"),
            ("getty".into(), String::new(), "service".into())
        );
    }
}
