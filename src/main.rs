// SPDX-License-Identifier: LGPL-2.1-or-later
//! PID 1 / user-manager entry point.
//!
//! Parses the kernel command line, configures the `ManagerConfig`, starts the
//! manager, and handles the final `LoopResult` by invoking the appropriate
//! kernel transition (reboot / poweroff / halt / kexec / re-exec).
//!
//! Upstream reference: `src/core/main.c` (v261)

use rustd::cmdline::KernelCmdline;
use rustd::config::{ManagerConfig, ManagerScope};
use rustd::emergency::BootMode;
use rustd::event::loop_::LoopResult;
use rustd::manager::Manager;

const VERSION_OUTPUT: &str = concat!("RustD ", env!("CARGO_PKG_VERSION"), "\n");

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        print!("{VERSION_OUTPUT}");
        return Ok(());
    }
    if let Some(path) = bus_introspection_path(&args) {
        let path = match path {
            Ok(path) => path,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        };
        if path == "list" {
            print!("{}", rustd::dbus::introspection::interface_list());
            return Ok(());
        }
        match rustd::dbus::introspection::introspect_path(path)? {
            Some(xml) => {
                print!("{xml}");
                return Ok(());
            }
            None => {
                eprintln!("Object path {path} not found");
                std::process::exit(1);
            }
        }
    }

    // 1. Parse kernel command line.
    let cmdline = KernelCmdline::from_proc();

    // 2. Select system or per-user manager mode and an optional explicit target.
    let mut user_mode = false;
    let mut explicit_target: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--user" => user_mode = true,
            "--system" => user_mode = false,
            _ if arg.starts_with('-') => {}
            _ if explicit_target.is_none() => explicit_target = Some(arg),
            _ => {}
        }
    }

    let boot_mode = if cmdline.emergency {
        BootMode::Emergency
    } else if cmdline.rescue {
        BootMode::Rescue
    } else {
        BootMode::Normal
    };
    let target = explicit_target.unwrap_or_else(|| {
        if user_mode {
            "default.target".to_owned()
        } else {
            cmdline
                .default_unit()
                .unwrap_or_else(|| boot_mode.target_name())
                .to_owned()
        }
    });

    // 3. Build ManagerConfig. Kernel command-line manager overrides apply only to PID 1.
    let mut config = if user_mode {
        ManagerConfig::default_user()
    } else {
        ManagerConfig::default_system()
    };
    if !user_mode {
        if let Some(secs) = cmdline.default_timeout_start_sec {
            config.default_timeout_start_sec = secs;
        }
        if let Some(ref level) = cmdline.log_level {
            config.log_level.clone_from(level);
        } else if cmdline.debug {
            config.log_level = "debug".into();
        }
        if let Some(ref tgt) = cmdline.log_target {
            config.log_target.clone_from(tgt);
        }
    }

    // A production manager cannot promise process isolation without a
    // delegated cgroup v2 hierarchy. Test harnesses remain filesystem-backed,
    // while every bare-metal or container entry point fails at this boundary
    // instead of silently weakening supervision.
    if !user_mode && std::process::id() == 1 {
        let profile = if running_in_container() {
            "rootful container"
        } else {
            "bare-metal"
        };
        // A container manager inherits its API mounts from the runtime; on
        // bare metal PID 1 establishes them itself before anything reads them.
        if !running_in_container() {
            rustd::mount_setup::mount_api_filesystems()?;
        }
        rustd::cgroup::CgroupManager::for_scope(ManagerScope::System)
            .setup_delegated_root()
            .map_err(|error| {
                anyhow::anyhow!(
                    "rustd: {profile} profile requires delegated cgroup v2 cpu, io, memory, and pids controllers: {error}"
                )
            })?;
    } else if user_mode && running_in_container() {
        if std::env::var_os("RUSTD_CGROUP_ROOT").is_none() {
            anyhow::bail!(
                "rustd: rootless container profile requires RUSTD_CGROUP_ROOT to name a delegated cgroup v2 hierarchy"
            );
        }
        rustd::cgroup::CgroupManager::for_scope(ManagerScope::User)
            .setup_delegated_root()
            .map_err(|error| {
                anyhow::anyhow!(
                    "rustd: rootless container profile requires delegated cgroup v2 cpu, io, memory, and pids controllers: {error}"
                )
            })?;
    }

    // Install the spawn helper before Manager::new starts IPC / D-Bus threads.
    // After this point rustd_spawn never forks the manager process.
    rustd::ffi::spawn::configure_spawn_helper_from_self()?;

    // Materialize transient units before the loader snapshots the boot graph.
    // Generators are system-manager only; user managers have a separate
    // lifecycle and must not rewrite the machine boot transaction.
    if !user_mode {
        rustd::generator::run_system_generators()?;
    }

    // 4. Start the manager and install the supervisor watchdog, if one was
    // passed through the sd-daemon environment. A re-executed manager adopts
    // the exact supported live graph instead of replaying the boot transaction.
    let mut manager = Manager::new(config)?;
    if !user_mode {
        if let Some(timeout) = rustd::native::watchdog_enabled(true)? {
            rustd::native::install_watchdog(&mut manager.event_loop, timeout)?;
        }
    }
    let restored = match std::env::var_os("RUSTD_REEXEC_STATE") {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            rustd::reexec_state::restore_manager_state(&mut manager, &path).map_err(|error| {
                anyhow::anyhow!("rustd: failed to restore reexec state {}: {error}", path.display())
            })?;
            std::env::remove_var("RUSTD_REEXEC_STATE");
            true
        }
        None => false,
    };
    if !restored {
        manager.enqueue_start(&target)?;
    }

    // 5. Run until a terminal result.
    let result = manager.run()?;
    let exit_code = manager.exit_code();
    if result == LoopResult::Reexecute {
        let path = rustd::reexec_state::save_manager_state(&manager)?;
        std::env::set_var("RUSTD_REEXEC_STATE", path);
    }
    if result != LoopResult::Reexecute {
        if let Err(error) = rustd::native::notify_stopping() {
            eprintln!("rustd: stopping notification failed: {error}");
        }
    }

    // 6. Act on the result.
    handle_result(result, user_mode);
    std::process::exit(i32::from(exit_code));
}

fn bus_introspection_path(args: &[String]) -> Option<Result<&str, &'static str>> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(path) = arg.strip_prefix("--bus-introspect=") {
            return Some(Ok(path));
        }
        if arg == "--bus-introspect" {
            return Some(
                args.get(index + 1)
                    .map(String::as_str)
                    .ok_or("rustd: option '--bus-introspect' requires an argument"),
            );
        }
    }
    None
}

fn running_in_container() -> bool {
    std::env::var_os("container").is_some() || std::path::Path::new("/run/rustd/container").exists()
}

/// Backend used for machine-wide transitions after the manager loop exits.
///
/// Keeping the decision logic separate from the syscall boundary lets the
/// production entry point exercise the real kernel transitions while tests
/// verify every PID 1 terminal path without rebooting the CI machine.
trait TransitionBackend {
    fn reboot(&mut self) -> i32;
    fn poweroff(&mut self) -> i32;
    fn halt(&mut self) -> i32;
    fn kexec(&mut self) -> i32;
    fn reexecute(&mut self);
}

struct KernelTransitionBackend;

impl TransitionBackend for KernelTransitionBackend {
    fn reboot(&mut self) -> i32 {
        // SAFETY: the native wrapper performs the Linux reboot syscall with a
        // fixed reboot command and does not retain pointers.
        unsafe { rustd::ffi::kexec::rustd_reboot() }
    }

    fn poweroff(&mut self) -> i32 {
        // SAFETY: see `reboot` above.
        unsafe { rustd::ffi::kexec::rustd_poweroff() }
    }

    fn halt(&mut self) -> i32 {
        // SAFETY: see `reboot` above.
        unsafe { rustd::ffi::kexec::rustd_halt() }
    }

    fn kexec(&mut self) -> i32 {
        // SAFETY: see `reboot` above.
        unsafe { rustd::ffi::kexec::rustd_kexec() }
    }

    fn reexecute(&mut self) {
        reexecute();
    }
}

/// Perform the kernel transition implied by `result`.
fn handle_result(result: LoopResult, user_mode: bool) {
    let mut backend = KernelTransitionBackend;
    handle_result_with_backend(result, user_mode, &mut backend);
}

fn handle_result_with_backend(
    result: LoopResult,
    user_mode: bool,
    backend: &mut impl TransitionBackend,
) {
    match result {
        LoopResult::Exit | LoopResult::Continue => {}
        LoopResult::Reboot if user_mode => {
            eprintln!("rustd: user manager requested reboot; exiting without a machine transition");
        }
        LoopResult::Reboot => {
            eprintln!("rustd: initiating system reboot");
            let result = backend.reboot();
            if result < 0 {
                eprintln!("rustd: reboot failed: errno {}", -result);
            }
        }
        LoopResult::Poweroff if user_mode => {
            eprintln!(
                "rustd: user manager requested poweroff; exiting without a machine transition"
            );
        }
        LoopResult::Poweroff => {
            eprintln!("rustd: initiating system poweroff");
            let result = backend.poweroff();
            if result < 0 {
                eprintln!("rustd: poweroff failed: errno {}", -result);
            }
        }
        LoopResult::Halt if user_mode => {
            eprintln!("rustd: user manager requested halt; exiting without a machine transition");
        }
        LoopResult::Halt => {
            eprintln!("rustd: initiating system halt");
            let result = backend.halt();
            if result < 0 {
                eprintln!("rustd: halt failed: errno {}", -result);
            }
        }
        LoopResult::Kexec if user_mode => {
            eprintln!("rustd: user manager requested kexec; exiting without a machine transition");
        }
        LoopResult::Kexec => {
            eprintln!("rustd: initiating kexec");
            let result = backend.kexec();
            if result < 0 {
                eprintln!("rustd: kexec failed: errno {}", -result);
            }
        }
        LoopResult::Reexecute => {
            eprintln!("rustd: re-executing manager");
            backend.reexecute();
        }
    }
}

/// Re-execute the manager binary in-place (SIGUSR2 handling).
///
/// Upstream: `manager_reexecute()` in `src/core/main.c` (v261).
/// We exec `/proc/self/exe` with the original arguments, which on Linux
/// always points to the current executable regardless of argv[0].
fn reexecute() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Build argv from /proc/self/exe + original args.
    let exe_path = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rustd: re-exec: cannot read /proc/self/exe: {e}");
            return;
        }
    };

    let exe_cstr = match CString::new(exe_path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rustd: re-exec: NUL in path: {e}");
            return;
        }
    };

    let orig_args: Vec<CString> = std::env::args()
        .filter_map(|a| CString::new(a).ok())
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = orig_args.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // Safety: exe_cstr and argv_ptrs are valid pointers valid for this call.
    unsafe {
        libc::execv(exe_cstr.as_ptr(), argv_ptrs.as_ptr());
    }
    // execv only returns on failure.
    eprintln!(
        "rustd: re-exec: execv failed: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_introspection_accepts_joined_and_separate_arguments() {
        assert_eq!(
            bus_introspection_path(&["--bus-introspect=list".to_owned()]),
            Some(Ok("list"))
        );
        assert_eq!(
            bus_introspection_path(&[
                "--bus-introspect".to_owned(),
                "/io/rustd/Manager1".to_owned(),
            ]),
            Some(Ok("/io/rustd/Manager1"))
        );
        assert!(matches!(
            bus_introspection_path(&["--bus-introspect".to_owned()]),
            Some(Err(_))
        ));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecordedTransition {
        Reboot,
        Poweroff,
        Halt,
        Kexec,
        Reexecute,
    }

    #[derive(Default)]
    struct RecordingBackend {
        transitions: Vec<RecordedTransition>,
    }

    impl TransitionBackend for RecordingBackend {
        fn reboot(&mut self) -> i32 {
            self.transitions.push(RecordedTransition::Reboot);
            0
        }

        fn poweroff(&mut self) -> i32 {
            self.transitions.push(RecordedTransition::Poweroff);
            0
        }

        fn halt(&mut self) -> i32 {
            self.transitions.push(RecordedTransition::Halt);
            0
        }

        fn kexec(&mut self) -> i32 {
            self.transitions.push(RecordedTransition::Kexec);
            0
        }

        fn reexecute(&mut self) {
            self.transitions.push(RecordedTransition::Reexecute);
        }
    }

    #[test]
    fn pid1_terminal_results_route_to_exact_machine_transitions() {
        for (result, expected) in [
            (LoopResult::Reboot, RecordedTransition::Reboot),
            (LoopResult::Poweroff, RecordedTransition::Poweroff),
            (LoopResult::Halt, RecordedTransition::Halt),
            (LoopResult::Kexec, RecordedTransition::Kexec),
            (LoopResult::Reexecute, RecordedTransition::Reexecute),
        ] {
            let mut backend = RecordingBackend::default();
            handle_result_with_backend(result, false, &mut backend);
            assert_eq!(backend.transitions, vec![expected]);
        }
    }

    #[test]
    fn user_manager_never_performs_machine_wide_transitions() {
        for result in [
            LoopResult::Reboot,
            LoopResult::Poweroff,
            LoopResult::Halt,
            LoopResult::Kexec,
        ] {
            let mut backend = RecordingBackend::default();
            handle_result_with_backend(result, true, &mut backend);
            assert_eq!(backend.transitions, [] as [tests::RecordedTransition; 0]);
        }
    }

    #[test]
    fn normal_loop_results_do_not_request_transitions() {
        for result in [LoopResult::Continue, LoopResult::Exit] {
            let mut backend = RecordingBackend::default();
            handle_result_with_backend(result, false, &mut backend);
            assert_eq!(backend.transitions, [] as [tests::RecordedTransition; 0]);
        }
    }
}
