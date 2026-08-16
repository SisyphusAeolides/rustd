// SPDX-License-Identifier: LGPL-2.1-or-later
//! `org.freedesktop.hostname1` service compatible with systemd v261.

#![allow(clippy::unused_self)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use zbus::interface;

const BUS_NAME: &str = "org.freedesktop.hostname1";
const OBJECT_PATH: &str = "/org/freedesktop/hostname1";

fn hostname_path() -> PathBuf {
    std::env::var_os("SYSTEMD_ETC_HOSTNAME")
        .map_or_else(|| PathBuf::from("/etc/hostname"), PathBuf::from)
}

fn machine_info_path() -> PathBuf {
    std::env::var_os("SYSTEMD_ETC_MACHINE_INFO")
        .map_or_else(|| PathBuf::from("/etc/machine-info"), PathBuf::from)
}

fn os_release_path() -> PathBuf {
    std::env::var_os("SYSTEMD_OS_RELEASE").map_or_else(
        || {
            if Path::new("/etc/os-release").exists() {
                PathBuf::from("/etc/os-release")
            } else {
                PathBuf::from("/usr/lib/os-release")
            }
        },
        PathBuf::from,
    )
}

fn read_env(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

fn quote_env(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
    }) {
        value.to_owned()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn write_env(path: &Path, values: &BTreeMap<String, String>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = String::new();
    for (key, value) in values {
        output.push_str(key);
        output.push('=');
        output.push_str(&quote_env(value));
        output.push('\n');
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, output)?;
    fs::rename(tmp, path)
}

fn machine_info_get(key: &str) -> String {
    read_env(&machine_info_path())
        .remove(key)
        .unwrap_or_default()
}

fn machine_info_set(key: &str, value: &str) -> io::Result<()> {
    let path = machine_info_path();
    let mut info = read_env(&path);
    if value.is_empty() {
        info.remove(key);
    } else {
        info.insert(key.to_owned(), value.to_owned());
    }
    write_env(&path, &info)
}

fn machine_info_set_tags(tags: &[String]) -> io::Result<()> {
    let mut normalized = tags.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    for tag in &normalized {
        if tag.is_empty()
            || tag.len() > 255
            || !tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid machine tag",
            ));
        }
    }
    machine_info_set("TAGS", &normalized.join(":"))
}

fn static_hostname() -> String {
    fs::read_to_string(hostname_path())
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn kernel_hostname() -> String {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) == 0 {
            return CStr::from_ptr(uts.nodename.as_ptr())
                .to_string_lossy()
                .into_owned();
        }
    }
    String::new()
}

fn uname_field(field: UnameField) -> String {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return String::new();
        }
        let ptr = match field {
            UnameField::SysName => uts.sysname.as_ptr(),
            UnameField::Release => uts.release.as_ptr(),
            UnameField::Version => uts.version.as_ptr(),
        };
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

#[derive(Clone, Copy)]
enum UnameField {
    SysName,
    Release,
    Version,
}

fn set_kernel_hostname(value: &str) -> io::Result<()> {
    let value = CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname contains NUL"))?;
    let bytes = value.as_bytes();
    if bytes.len() > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname is too long",
        ));
    }
    let rc = unsafe { libc::sethostname(value.as_ptr(), bytes.len()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn default_hostname() -> String {
    read_env(&os_release_path())
        .remove("DEFAULT_HOSTNAME")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

fn effective_hostname(value: &str) -> String {
    if value.is_empty() {
        default_hostname()
    } else {
        value.to_owned()
    }
}

fn write_static_hostname(value: &str) -> io::Result<()> {
    let path = hostname_path();
    if value.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{value}\n"))
    }
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn hex_id(path: &str) -> Vec<u8> {
    let value = read_trimmed(path).replace('-', "");
    if value.len() != 32 {
        return Vec::new();
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

fn product_uuid() -> Vec<u8> {
    let value = read_trimmed("/sys/class/dmi/id/product_uuid").replace('-', "");
    if value.len() != 32 {
        return Vec::new();
    }
    (0..16)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

fn os_release(key: &str) -> String {
    read_env(&os_release_path()).remove(key).unwrap_or_default()
}

fn machine_info_value(field: &str) -> Option<String> {
    let value = match field {
        "Hostname" => kernel_hostname(),
        "StaticHostname" => static_hostname(),
        "PrettyHostname" => machine_info_get("PRETTY_HOSTNAME"),
        "DefaultHostname" => default_hostname(),
        "IconName" => machine_info_get("ICON_NAME"),
        "Chassis" => machine_info_get("CHASSIS"),
        "Deployment" => machine_info_get("DEPLOYMENT"),
        "Location" => machine_info_get("LOCATION"),
        "HardwareVendor" => read_trimmed("/sys/class/dmi/id/sys_vendor"),
        "HardwareModel" => read_trimmed("/sys/class/dmi/id/product_name"),
        "HardwareSKU" => read_trimmed("/sys/class/dmi/id/product_sku"),
        "HardwareVersion" => read_trimmed("/sys/class/dmi/id/product_version"),
        "FirmwareVersion" => read_trimmed("/sys/class/dmi/id/bios_version"),
        "FirmwareVendor" => read_trimmed("/sys/class/dmi/id/bios_vendor"),
        "ChassisAssetTag" => read_trimmed("/sys/class/dmi/id/chassis_asset_tag"),
        "KernelName" => uname_field(UnameField::SysName),
        "KernelRelease" => uname_field(UnameField::Release),
        "KernelVersion" => uname_field(UnameField::Version),
        "OperatingSystemPrettyName" => os_release("PRETTY_NAME"),
        "OperatingSystemFancyName" => os_release("PRETTY_NAME"),
        "OperatingSystemCPEName" => os_release("CPE_NAME"),
        "HomeURL" => os_release("HOME_URL"),
        "OperatingSystemImageID" => os_release("IMAGE_ID"),
        "OperatingSystemImageVersion" => os_release("IMAGE_VERSION"),
        _ => return None,
    };
    Some(value)
}

async fn authorize(
    connection: &zbus::Connection,
    header: &zbus::MessageHeader<'_>,
    action: &str,
    interactive: bool,
) -> zbus::fdo::Result<()> {
    let uid = rustd::dbus::auth::caller_uid(connection, header).await?;
    if uid == 0 {
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
    let flags = u32::from(interactive);
    let (authorized, challenge, _returned): (bool, bool, HashMap<String, String>) = proxy
        .call(
            "CheckAuthorization",
            &(
                ("system-bus-name", subject_details),
                action,
                details,
                flags,
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

fn io_to_dbus(error: io::Error) -> zbus::fdo::Error {
    if error.kind() == io::ErrorKind::InvalidInput {
        zbus::fdo::Error::InvalidArgs(error.to_string())
    } else {
        zbus::fdo::Error::Failed(error.to_string())
    }
}

#[derive(Default)]
struct HostnameService;

#[interface(name = "org.freedesktop.hostname1")]
impl HostnameService {
    async fn set_hostname(
        &self,
        hostname: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-hostname",
            interactive,
        )
        .await?;
        set_kernel_hostname(&effective_hostname(&hostname)).map_err(io_to_dbus)
    }

    async fn set_static_hostname(
        &self,
        hostname: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-static-hostname",
            interactive,
        )
        .await?;
        write_static_hostname(&hostname).map_err(io_to_dbus)?;
        set_kernel_hostname(&effective_hostname(&hostname)).map_err(io_to_dbus)
    }

    async fn set_pretty_hostname(
        &self,
        hostname: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            interactive,
        )
        .await?;
        machine_info_set("PRETTY_HOSTNAME", &hostname).map_err(io_to_dbus)
    }

    async fn set_icon_name(
        &self,
        icon: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            interactive,
        )
        .await?;
        machine_info_set("ICON_NAME", &icon).map_err(io_to_dbus)
    }

    async fn set_chassis(
        &self,
        chassis: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            interactive,
        )
        .await?;
        machine_info_set("CHASSIS", &chassis).map_err(io_to_dbus)
    }

    async fn set_deployment(
        &self,
        deployment: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            interactive,
        )
        .await?;
        machine_info_set("DEPLOYMENT", &deployment).map_err(io_to_dbus)
    }

    async fn set_location(
        &self,
        location: String,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            interactive,
        )
        .await?;
        machine_info_set("LOCATION", &location).map_err(io_to_dbus)
    }

    async fn set_tags(
        &self,
        tags: Vec<String>,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.set-machine-info",
            false,
        )
        .await?;
        machine_info_set_tags(&tags).map_err(io_to_dbus)
    }

    async fn get_product_uuid(
        &self,
        interactive: bool,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<Vec<u8>> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.get-product-uuid",
            interactive,
        )
        .await?;
        Ok(product_uuid())
    }

    async fn get_hardware_serial(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.get-hardware-serial",
            false,
        )
        .await?;
        Ok(read_trimmed("/sys/class/dmi/id/product_serial"))
    }

    async fn describe(
        &self,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.get-description",
            false,
        )
        .await?;
        let value = serde_json::json!({
            "Hostname": kernel_hostname(),
            "StaticHostname": static_hostname(),
            "PrettyHostname": machine_info_get("PRETTY_HOSTNAME"),
            "DefaultHostname": default_hostname(),
            "IconName": machine_info_get("ICON_NAME"),
            "Chassis": machine_info_get("CHASSIS"),
            "Deployment": machine_info_get("DEPLOYMENT"),
            "Location": machine_info_get("LOCATION"),
            "HardwareVendor": read_trimmed("/sys/class/dmi/id/sys_vendor"),
            "HardwareModel": read_trimmed("/sys/class/dmi/id/product_name"),
            "KernelName": uname_field(UnameField::SysName),
            "KernelRelease": uname_field(UnameField::Release),
            "OperatingSystemPrettyName": os_release("PRETTY_NAME"),
        });
        serde_json::to_string(&value).map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }

    async fn get_machine_info(
        &self,
        field: String,
        #[zbus(header)] header: zbus::MessageHeader<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        authorize(
            connection,
            &header,
            "org.freedesktop.hostname1.get-description",
            false,
        )
        .await?;
        machine_info_value(&field).ok_or_else(|| {
            zbus::fdo::Error::InvalidArgs(format!("unknown machine-info field: {field}"))
        })
    }

    #[zbus(property)]
    fn hostname(&self) -> String {
        kernel_hostname()
    }

    #[zbus(property)]
    fn static_hostname(&self) -> String {
        static_hostname()
    }

    #[zbus(property)]
    fn pretty_hostname(&self) -> String {
        machine_info_get("PRETTY_HOSTNAME")
    }

    #[zbus(property)]
    fn default_hostname(&self) -> String {
        default_hostname()
    }

    #[zbus(property)]
    fn hostname_source(&self) -> String {
        let current = kernel_hostname();
        let static_name = static_hostname();
        if !static_name.is_empty() && current == static_name {
            "static".to_owned()
        } else if current == default_hostname() {
            "default".to_owned()
        } else {
            "transient".to_owned()
        }
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        machine_info_get("ICON_NAME")
    }

    #[zbus(property)]
    fn chassis(&self) -> String {
        machine_info_get("CHASSIS")
    }

    #[zbus(property)]
    fn deployment(&self) -> String {
        machine_info_get("DEPLOYMENT")
    }

    #[zbus(property)]
    fn location(&self) -> String {
        machine_info_get("LOCATION")
    }

    #[zbus(property)]
    fn tags(&self) -> Vec<String> {
        machine_info_get("TAGS")
            .split(':')
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect()
    }

    #[zbus(property)]
    fn kernel_name(&self) -> String {
        uname_field(UnameField::SysName)
    }

    #[zbus(property)]
    fn kernel_release(&self) -> String {
        uname_field(UnameField::Release)
    }

    #[zbus(property)]
    fn kernel_version(&self) -> String {
        uname_field(UnameField::Version)
    }

    #[zbus(property)]
    fn operating_system_pretty_name(&self) -> String {
        os_release("PRETTY_NAME")
    }

    #[zbus(property)]
    fn operating_system_fancy_name(&self) -> String {
        os_release("PRETTY_NAME")
    }

    #[zbus(property)]
    fn operating_system_cpe_name(&self) -> String {
        os_release("CPE_NAME")
    }

    #[zbus(property)]
    fn operating_system_support_end(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn home_url(&self) -> String {
        os_release("HOME_URL")
    }

    #[zbus(property)]
    fn operating_system_image_id(&self) -> String {
        os_release("IMAGE_ID")
    }

    #[zbus(property)]
    fn operating_system_image_version(&self) -> String {
        os_release("IMAGE_VERSION")
    }

    #[zbus(property)]
    fn hardware_vendor(&self) -> String {
        read_trimmed("/sys/class/dmi/id/sys_vendor")
    }

    #[zbus(property)]
    fn hardware_model(&self) -> String {
        read_trimmed("/sys/class/dmi/id/product_name")
    }

    #[zbus(property)]
    fn hardware_sku(&self) -> String {
        read_trimmed("/sys/class/dmi/id/product_sku")
    }

    #[zbus(property)]
    fn hardware_version(&self) -> String {
        read_trimmed("/sys/class/dmi/id/product_version")
    }

    #[zbus(property)]
    fn firmware_version(&self) -> String {
        read_trimmed("/sys/class/dmi/id/bios_version")
    }

    #[zbus(property)]
    fn firmware_vendor(&self) -> String {
        read_trimmed("/sys/class/dmi/id/bios_vendor")
    }

    #[zbus(property)]
    fn firmware_date(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn machine_id(&self) -> Vec<u8> {
        hex_id("/etc/machine-id")
    }

    #[zbus(property)]
    fn boot_id(&self) -> Vec<u8> {
        hex_id("/proc/sys/kernel/random/boot_id")
    }

    #[zbus(property)]
    fn v_sock_cid(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn chassis_asset_tag(&self) -> String {
        read_trimmed("/sys/class/dmi/id/chassis_asset_tag")
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let connection = zbus::Connection::system().await?;
    connection
        .object_server()
        .at(OBJECT_PATH, HostnameService)
        .await?;
    connection.request_name(BUS_NAME).await?;
    let _ = rustd::native::notify_ready();
    std::future::pending::<()>().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn tags_use_v261_machine_info_key_and_format() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-info");
        std::env::set_var("SYSTEMD_ETC_MACHINE_INFO", &path);
        machine_info_set_tags(&["role.web".into(), "fleet-1".into(), "role.web".into()]).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, "TAGS=fleet-1:role.web\n");
        std::env::remove_var("SYSTEMD_ETC_MACHINE_INFO");
    }

    #[test]
    fn empty_static_hostname_removes_override_file() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hostname");
        fs::write(&path, "old\n").unwrap();
        std::env::set_var("SYSTEMD_ETC_HOSTNAME", &path);
        write_static_hostname("").unwrap();
        assert!(!path.exists());
        std::env::remove_var("SYSTEMD_ETC_HOSTNAME");
    }

    #[test]
    fn ids_are_exported_as_sixteen_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        fs::write(&path, "00112233-4455-6677-8899-aabbccddeeff\n").unwrap();
        assert_eq!(hex_id(path.to_str().unwrap()).len(), 16);
    }
}
