// SPDX-License-Identifier: LGPL-2.1-or-later

use std::ffi::CString;
use std::ptr;

use rustd::ffi::spawn::{
    configure_spawn_helper_from_self, rustd_spawn, SdSpawnParams, SdSpawnSandbox,
};
use rustd::sandbox::SecurityContext;
use rustd::unit::section_service::{ProtectSystem, ServiceSection};

fn wait_success(pid: libc::pid_t) {
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed: {}", std::io::Error::last_os_error());
    assert!(libc::WIFEXITED(status), "sandbox payload did not exit normally: {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "sandbox payload failed: {status}");
}

#[test]
fn production_spawn_strict_root_preserves_declared_writable_exception() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping privileged ReadWritePaths certification: requires uid 0");
        return;
    }

    configure_spawn_helper_from_self().expect("configure production spawn helper");

    let root = tempfile::tempdir().expect("temporary certification root");
    let writable = root.path().join("writable");
    let readonly = root.path().join("readonly");
    std::fs::create_dir(&writable).expect("create writable exception directory");
    std::fs::create_dir(&readonly).expect("create readonly sibling directory");

    let writable_path = writable.to_string_lossy().into_owned();
    let readonly_path = readonly.to_string_lossy().into_owned();
    let section = ServiceSection {
        protect_system: ProtectSystem::Strict,
        read_write_paths: vec![writable_path.clone()],
        ..Default::default()
    };
    let security = SecurityContext::from_service(&section).expect("resolve strict sandbox context");
    assert_eq!(security.protect_system, 3);
    assert_eq!(security.read_write_paths, [writable_path.clone()]);

    let root_exception = ServiceSection {
        read_write_paths: vec!["/".to_owned()],
        ..Default::default()
    };
    SecurityContext::from_service(&root_exception).expect("ReadWritePaths=/ must be accepted");
    // Restage the actual certification exception after the root-parity parser check.
    let security = SecurityContext::from_service(&section).expect("restage writable exception");

    let sandbox = SdSpawnSandbox {
        no_new_privs: libc::c_int::from(security.no_new_privileges),
        private_tmp: libc::c_int::from(security.private_tmp),
        private_devices: libc::c_int::from(security.private_devices),
        private_network: libc::c_int::from(security.private_network),
        private_mounts: libc::c_int::from(security.private_mounts),
        protect_system: libc::c_int::from(security.protect_system),
        protect_home: libc::c_int::from(security.protect_home),
        protect_kernel_tunables: libc::c_int::from(security.protect_kernel_tunables),
        protect_kernel_modules: libc::c_int::from(security.protect_kernel_modules),
        protect_kernel_logs: libc::c_int::from(security.protect_kernel_logs),
        protect_clock: libc::c_int::from(security.protect_clock),
        protect_control_groups: libc::c_int::from(security.protect_control_groups),
        restrict_suid_sgid: libc::c_int::from(security.restrict_suid_sgid),
        restrict_realtime: libc::c_int::from(security.restrict_realtime),
        restrict_namespaces: libc::c_int::from(security.restrict_namespaces),
        memory_deny_write_execute: libc::c_int::from(security.memory_deny_write_execute),
        ..Default::default()
    };

    let shell = CString::new("/bin/sh").unwrap();
    let script = CString::new(format!(
        "set -eu; printf writable > '{writable_path}/probe'; \
         if printf forbidden > '{readonly_path}/probe' 2>/dev/null; then exit 91; fi; \
         test \"$(cat '{writable_path}/probe')\" = writable"
    ))
    .unwrap();
    let arg0 = CString::new("sh").unwrap();
    let arg1 = CString::new("-c").unwrap();
    let argv_storage = [arg0, arg1, script];
    let argv = [
        argv_storage[0].as_ptr(),
        argv_storage[1].as_ptr(),
        argv_storage[2].as_ptr(),
        ptr::null(),
    ];

    let params = SdSpawnParams {
        path: shell.as_ptr(),
        argv: argv.as_ptr(),
        envp: ptr::null(),
        cwd: ptr::null(),
        cgroup_procs_path: ptr::null(),
        rlimits: ptr::null(),
        n_rlimits: 0,
        uid: libc::uid_t::MAX,
        gid: libc::gid_t::MAX,
        selinux_context: ptr::null(),
        selinux_context_ignore: 0,
        apparmor_profile: ptr::null(),
        apparmor_profile_ignore: 0,
        stdin_fd: -1,
        stdout_fd: -1,
        stderr_fd: -1,
        notify_fd: -1,
        watchdog_usec: 0,
        sandbox: ptr::addr_of!(sandbox),
        listen_fds: ptr::null(),
        n_listen_fds: 0,
        cap_bounding_set: u64::MAX,
        ambient_caps: 0,
        wait_for_exec: 1,
        idle_read_fd: -1,
        idle_write_fd: -1,
    };

    let pid = unsafe { rustd_spawn(ptr::addr_of!(params)) };
    assert!(pid > 0, "production spawn failed with errno {}", -pid);
    wait_success(pid);

    assert_eq!(
        std::fs::read_to_string(writable.join("probe")).unwrap(),
        "writable"
    );
    assert!(
        !readonly.join("probe").exists(),
        "ProtectSystem=strict leaked write access outside ReadWritePaths="
    );
}
