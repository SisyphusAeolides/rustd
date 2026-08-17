// SPDX-License-Identifier: LGPL-2.1-or-later
#![allow(warnings)]
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn command(program: &OsString, args: &[OsString]) -> ExitStatus {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {program:?}: {error}"));
    assert!(status.success(), "command {program:?} failed with {status}");
    status
}

fn object(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(format!("{name}.o"))
}

fn target_tool(variable: &str, target: &str, fallback: &str) -> OsString {
    let normalized = target.replace(['-', '.'], "_");
    for key in [
        format!("{variable}_{target}"),
        format!("{variable}_{normalized}"),
        format!("TARGET_{variable}"),
        variable.to_owned(),
    ] {
        if let Some(value) = env::var_os(&key) {
            if !value.is_empty() {
                return value;
            }
        }
    }

    if target != env::var("HOST").unwrap_or_default() {
        let prefix = match target {
            "aarch64-unknown-linux-gnu" => Some("aarch64-linux-gnu-"),
            "x86_64-unknown-linux-gnu" => Some("x86_64-linux-gnu-"),
            "armv7-unknown-linux-gnueabihf" => Some("arm-linux-gnueabihf-"),
            "powerpc64le-unknown-linux-gnu" => Some("powerpc64le-linux-gnu-"),
            "s390x-unknown-linux-gnu" => Some("s390x-linux-gnu-"),
            "riscv64gc-unknown-linux-gnu" => Some("riscv64-linux-gnu-"),
            _ => None,
        };
        if let Some(prefix) = prefix {
            let executable = match variable {
                "CC" => "gcc",
                "AR" => "ar",
                "FC" => "gfortran",
                _ => fallback,
            };
            return OsString::from(format!("{prefix}{executable}"));
        }
    }

    OsString::from(fallback)
}

fn compile_c(cc: &OsString, source: &str, output: &Path) {
    command(
        cc,
        &[
            OsString::from("-c"),
            // RustD's native FFI uses C11 language features. Keeping this at C11
            // supports a wider set of production cross toolchains without changing
            // the ABI or the hardening flags used by the native build.
            OsString::from("-std=c11"),
            OsString::from("-O2"),
            OsString::from("-fPIC"),
            OsString::from("-fstack-protector-strong"),
            OsString::from("-U_FORTIFY_SOURCE"),
            OsString::from("-D_FORTIFY_SOURCE=3"),
            OsString::from("-Wall"),
            OsString::from("-Wextra"),
            OsString::from("-Werror"),
            // -iquote rather than -I: ffi/spawn.h must not shadow <spawn.h>.
            OsString::from("-iquote"),
            OsString::from("ffi"),
            OsString::from(source),
            OsString::from("-o"),
            output.as_os_str().to_owned(),
        ],
    );
}

fn main() {
    println!("cargo:rerun-if-changed=ffi/native.c");
    println!("cargo:rerun-if-changed=ffi/native.h");
    println!("cargo:rerun-if-changed=ffi/notify.c");
    println!("cargo:rerun-if-changed=ffi/notify.h");
    println!("cargo:rerun-if-changed=ffi/interface.c");
    println!("cargo:rerun-if-changed=ffi/cgroup.c");
    println!("cargo:rerun-if-changed=ffi/signal.c");
    println!("cargo:rerun-if-changed=ffi/journal.c");
    println!("cargo:rerun-if-changed=ffi/sched.f90");
    println!("cargo:rerun-if-changed=ffi/event.c");
    println!("cargo:rerun-if-changed=ffi/event.h");
    println!("cargo:rerun-if-changed=ffi/spawn.c");
    println!("cargo:rerun-if-changed=ffi/spawn.h");
    println!("cargo:rerun-if-changed=ffi/spawn_helper.c");
    println!("cargo:rerun-if-changed=ffi/spawn_helper.h");
    println!("cargo:rerun-if-changed=ffi/spawn_wire.h");
    println!("cargo:rerun-if-changed=ffi/sandbox.c");
    println!("cargo:rerun-if-changed=ffi/sandbox.h");
    println!("cargo:rerun-if-changed=ffi/socket_activation.c");
    println!("cargo:rerun-if-changed=ffi/socket_activation.h");
    println!("cargo:rerun-if-changed=ffi/kexec.c");
    println!("cargo:rerun-if-changed=ffi/kexec.h");
    println!("cargo:rerun-if-changed=ffi/mute_console.c");
    println!("cargo:rerun-if-changed=ffi/mute_console.h");
    println!("cargo:rerun-if-changed=ffi/seccomp.c");
    println!("cargo:rerun-if-changed=ffi/seccomp.h");
    println!("cargo:rerun-if-changed=ffi/capability.c");
    println!("cargo:rerun-if-changed=ffi/capability.h");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS is set by cargo");
    assert!(target_os == "linux", "rustd currently supports Linux only");
    let target = env::var("TARGET").expect("TARGET is set by cargo");

    for variable in ["CC", "AR", "FC"] {
        println!("cargo:rerun-if-env-changed={variable}");
        println!("cargo:rerun-if-env-changed=TARGET_{variable}");
        println!("cargo:rerun-if-env-changed={variable}_{target}");
        println!(
            "cargo:rerun-if-env-changed={variable}_{}",
            target.replace(['-', '.'], "_")
        );
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::create_dir_all(&out_dir).expect("create build output directory");

    let cc = target_tool("CC", &target, "cc");
    let ar = target_tool("AR", &target, "ar");

    let native_obj = object(&out_dir, "rustd_native");
    let notify_obj = object(&out_dir, "rustd_notify");
    let interface_obj = object(&out_dir, "rustd_interface");
    let cgroup_obj = object(&out_dir, "rustd_cgroup");
    let signal_obj = object(&out_dir, "rustd_signal");
    let journal_obj = object(&out_dir, "rustd_journal");
    let event_obj = object(&out_dir, "rustd_event");
    let spawn_obj = object(&out_dir, "rustd_spawn");
    let spawn_helper_obj = object(&out_dir, "rustd_spawn_helper");
    let sandbox_obj = object(&out_dir, "rustd_sandbox");
    let socket_activation_obj = object(&out_dir, "rustd_socket_activation");
    let kexec_obj = object(&out_dir, "rustd_kexec");
    let mute_console_obj = object(&out_dir, "rustd_mute_console");
    let seccomp_obj = object(&out_dir, "rustd_seccomp");
    let capability_obj = object(&out_dir, "rustd_capability");

    compile_c(&cc, "ffi/native.c", &native_obj);
    compile_c(&cc, "ffi/notify.c", &notify_obj);
    compile_c(&cc, "ffi/interface.c", &interface_obj);
    compile_c(&cc, "ffi/cgroup.c", &cgroup_obj);
    compile_c(&cc, "ffi/signal.c", &signal_obj);
    compile_c(&cc, "ffi/journal.c", &journal_obj);
    compile_c(&cc, "ffi/event.c", &event_obj);
    compile_c(&cc, "ffi/spawn.c", &spawn_obj);
    compile_c(&cc, "ffi/spawn_helper.c", &spawn_helper_obj);
    compile_c(&cc, "ffi/sandbox.c", &sandbox_obj);
    compile_c(&cc, "ffi/socket_activation.c", &socket_activation_obj);
    compile_c(&cc, "ffi/kexec.c", &kexec_obj);
    compile_c(&cc, "ffi/mute_console.c", &mute_console_obj);
    compile_c(&cc, "ffi/seccomp.c", &seccomp_obj);
    compile_c(&cc, "ffi/capability.c", &capability_obj);

    let mut objects = vec![
        native_obj,
        notify_obj,
        interface_obj,
        cgroup_obj,
        signal_obj,
        journal_obj,
        event_obj,
        spawn_obj,
        spawn_helper_obj,
        sandbox_obj,
        socket_activation_obj,
        kexec_obj,
        mute_console_obj,
        seccomp_obj,
        capability_obj,
    ];

    let fortran_enabled = env::var_os("CARGO_FEATURE_FORTRAN_SCHED").is_some();
    if fortran_enabled {
        let fc = target_tool("FC", &target, "gfortran");
        let fc_available = Command::new(&fc)
            .arg("--version")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !fc_available {
            panic!(
                "Fortran compiler {:?} not found. Install gfortran or provide the target compiler through FC/FC_<target>.",
                fc
            );
        }
        let sched_obj = object(&out_dir, "rustd_sched");
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-std=f2018"),
                OsString::from("-O2"),
                OsString::from("-fPIC"),
                OsString::from("-fimplicit-none"),
                OsString::from("-Wall"),
                OsString::from("-Wextra"),
                OsString::from("-Werror"),
                OsString::from(format!("-J{}", out_dir.display())),
                OsString::from("ffi/sched.f90"),
                OsString::from("-o"),
                sched_obj.clone().into_os_string(),
            ],
        );
        objects.push(sched_obj);
        println!("cargo:rerun-if-changed=ffi/sched.f90");
    }

    if env::var_os("CARGO_FEATURE_KALMAN").is_some() {
        let fc = target_tool("FC", &target, "gfortran");
        let kalman_obj = object(&out_dir, "rustd_kalman_sched");
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-std=f2018"),
                OsString::from("-O3"),
                OsString::from("-fPIC"),
                OsString::from("-fimplicit-none"),
                OsString::from(format!("-J{}", out_dir.display())),
                OsString::from(format!("-I{}", out_dir.display())),
                OsString::from("ffi/kalman_sched.f90"),
                OsString::from("-o"),
                kalman_obj.clone().into_os_string(),
            ],
        );
        objects.push(kalman_obj);
        println!("cargo:rerun-if-changed=ffi/kalman_sched.f90");
    }

    let archive = out_dir.join("librustd_native.a");
    let mut args = vec![OsString::from("crs"), archive.clone().into_os_string()];
    args.extend(objects.into_iter().map(PathBuf::into_os_string));
    command(&ar, &args);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=rustd_native");
    println!("cargo:rustc-link-lib=dl");
    if fortran_enabled || env::var_os("CARGO_FEATURE_KALMAN").is_some() {
        println!("cargo:rustc-link-lib=gfortran");
    }
}
