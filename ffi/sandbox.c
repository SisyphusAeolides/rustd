/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * sandbox.c — in-child security sandbox helpers.
 *
 * All functions are called after fork() and before execve(), in the
 * single-threaded child context.
 *
 * Upstream reference: src/core/execute.c exec_child(),
 *   src/core/execute-security.c (v261)
 */

#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

/*
 * bind_ro: bind-mount src over dst in read-only mode.
 * Creates dst if it does not exist (as a directory or file to match src).
 * Returns 0 on success, -errno on failure.
 */
static int bind_ro(const char *src, const char *dst) {
    struct stat st;
    if (stat(src, &st) < 0)
        return -errno;

    /* Create mount-point if missing. */
    if (S_ISDIR(st.st_mode)) {
        mkdir(dst, 0755);
    } else {
        int fd = open(dst, O_RDONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0000);
        if (fd >= 0)
            close(fd);
    }

    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) < 0)
        return -errno;

    if (mount(NULL, dst, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC | MS_NODEV, NULL) < 0)
        return -errno;

    return 0;
}

/*
 * make_inaccessible: mount a read-only tmpfs that is mode 000 over path,
 * making it inaccessible.  Used for ProtectHome=yes.
 */
static int make_inaccessible(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0)
        return 0; /* path doesn't exist — nothing to protect */

    if (mount("tmpfs", path, "tmpfs",
              MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY,
              "mode=000") < 0)
        return -errno;

    return 0;
}

/* Bind /dev/null over an existing device node inside the private mount tree. */
static int mask_device(const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0)
        return errno == ENOENT ? 0 : -errno;

    if (mount("/dev/null", path, NULL, MS_BIND, NULL) < 0)
        return -errno;
    if (mount(NULL, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) < 0)
        return -errno;
    return 0;
}

/* ── rustd_sandbox_no_new_privs ─────────────────────────────────────────────── */

int rustd_sandbox_no_new_privs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -errno;
    return 0;
}

/* ── rustd_sandbox_mount_namespaces ─────────────────────────────────────────── */

/*
 * ProtectSystem levels:
 *   0 = no      — no protection
 *   1 = yes     — /usr, /boot, /efi read-only
 *   2 = full    — /usr, /boot, /efi, /etc read-only
 *   3 = strict  — entire tree read-only except API VFS mounts
 *
 * ProtectHome levels:
 *   0 = no         — no protection
 *   1 = yes        — /home, /root, /run/user inaccessible (mode 000 tmpfs)
 *   2 = read-only  — /home, /root, /run/user read-only bind-mounts
 *   3 = tmpfs      — empty tmpfs over /home, /root, /run/user
 */
int rustd_sandbox_mount_namespaces(int private_tmp,
                                int private_devices,
                                int private_network,
                                int protect_system,
                                int protect_home,
                                int force_mount_namespace) {
    /* Network namespace (does not require mount namespace). */
    if (private_network) {
        if (unshare(CLONE_NEWNET) < 0)
            return -errno;
        /* lo stays down; caller is responsible for ifup lo if needed. */
    }

    /* All remaining steps need a mount namespace. */
    int need_mntns = force_mount_namespace || private_tmp || private_devices
                     || (protect_system > 0) || (protect_home > 0);
    if (!need_mntns)
        return 0;

    if (unshare(CLONE_NEWNS) < 0)
        return -errno;

    /* Make the entire tree a slave so our mounts don't propagate back. */
    if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
        return -errno;

    /* PrivateTmp: mount a fresh tmpfs over /tmp and /var/tmp. */
    if (private_tmp) {
        if (mount("tmpfs", "/tmp", "tmpfs",
                  MS_NODEV | MS_STRICTATIME, "mode=1777,size=50%") < 0)
            return -errno;
        if (mount("tmpfs", "/var/tmp", "tmpfs",
                  MS_NODEV | MS_STRICTATIME, "mode=1777,size=50%") < 0)
            return -errno; /* non-fatal if /var/tmp missing */
    }

    /* PrivateDevices: mount a minimal /dev. */
    if (private_devices) {
        if (mount("devtmpfs", "/dev", "tmpfs",
                  MS_NOSUID | MS_STRICTATIME,
                  "mode=755,size=4m") < 0)
            return -errno;

        /* Re-create required device nodes via bind-mounts from the real /dev. */
        static const char *const devnodes[] = {
            "/dev/null", "/dev/zero", "/dev/full",
            "/dev/random", "/dev/urandom", "/dev/tty",
            NULL
        };
        for (int i = 0; devnodes[i]; i++) {
            /* Create empty file as mount point then bind-mount. */
            int fd = open(devnodes[i], O_RDONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0000);
            if (fd >= 0) close(fd);
            /* Best-effort — ignore errors for missing nodes. */
            (void)mount(devnodes[i], devnodes[i], NULL, MS_BIND, NULL);
        }
    }

    /* ProtectSystem. */
    if (protect_system >= 3) {
        /* strict: whole rootfs read-only */
        if (mount(NULL, "/", NULL,
                  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC | MS_NODEV, NULL) < 0)
            return -errno;
    } else if (protect_system >= 1) {
        /* yes / full: /usr, /boot, /efi read-only */
        (void)bind_ro("/usr", "/usr");
        (void)bind_ro("/boot", "/boot");
        (void)bind_ro("/efi", "/efi");
        if (protect_system >= 2) {
            /* full: additionally /etc */
            (void)bind_ro("/etc", "/etc");
        }
    }

    /* ProtectHome. */
    if (protect_home == 1) {
        /* inaccessible */
        (void)make_inaccessible("/home");
        (void)make_inaccessible("/root");
        (void)make_inaccessible("/run/user");
    } else if (protect_home == 2) {
        /* read-only */
        (void)bind_ro("/home", "/home");
        (void)bind_ro("/root", "/root");
        (void)bind_ro("/run/user", "/run/user");
    } else if (protect_home == 3) {
        /* tmpfs */
        (void)mount("tmpfs", "/home", "tmpfs",
                    MS_NODEV | MS_STRICTATIME, "mode=755");
        (void)mount("tmpfs", "/root", "tmpfs",
                    MS_NODEV | MS_STRICTATIME, "mode=700");
    }

    return 0;
}

/* ── rustd_sandbox_protect_paths ────────────────────────────────────────────── */

int rustd_sandbox_protect_paths(int protect_kernel_tunables,
                             int protect_kernel_modules,
                             int protect_kernel_logs,
                             int protect_clock,
                             int protect_control_groups,
                             int restrict_suid_sgid) {
    int ret = 0;

    if (protect_kernel_tunables) {
        int r;
        r = bind_ro("/proc/sys",  "/proc/sys");  if (r < 0) ret = r;
        r = bind_ro("/proc/sysrq-trigger", "/proc/sysrq-trigger"); (void)r;
        r = bind_ro("/sys",       "/sys");       if (r < 0) ret = r;
        r = bind_ro("/sys/fs",    "/sys/fs");    (void)r;
    }

    if (protect_kernel_modules) {
        int r;
        r = bind_ro("/lib/modules",      "/lib/modules");      (void)r;
        r = bind_ro("/usr/lib/modules",  "/usr/lib/modules");  (void)r;
        r = bind_ro("/proc/modules",     "/proc/modules");     (void)r;
    }

    if (protect_kernel_logs) {
        int r = mask_device("/dev/kmsg");
        if (r < 0 && r != -ENOENT)
            ret = r;
    }

    if (protect_clock) {
        static const char *const rtc_devices[] = {
            "/dev/rtc", "/dev/rtc0", "/dev/rtc1", NULL
        };
        for (size_t i = 0; rtc_devices[i]; i++) {
            int r = mask_device(rtc_devices[i]);
            if (r < 0 && r != -ENOENT)
                ret = r;
        }
    }

    if (protect_control_groups) {
        int r = bind_ro("/sys/fs/cgroup", "/sys/fs/cgroup");
        if (r < 0 && r != -ENOENT)
            ret = r;
    }

    if (restrict_suid_sgid) {
        /* Remount /dev and /tmp with nosuid to prevent SUID/SGID abuse. */
        (void)mount(NULL, "/dev", NULL, MS_REMOUNT | MS_NOSUID | MS_BIND, NULL);
        (void)mount(NULL, "/tmp", NULL, MS_REMOUNT | MS_NOSUID | MS_BIND, NULL);
    }

    return ret;
}

/* ── rustd_sandbox_restrict_realtime ────────────────────────────────────────── */

/*
 * Match upstream v261 RestrictRealtime= behavior for sched_setscheduler(2):
 * SCHED_OTHER, SCHED_BATCH, and SCHED_IDLE remain available, while all other
 * policies fail with EPERM. The scheduling policy is syscall argument 1.
 */
int rustd_sandbox_restrict_realtime(void) {
#ifndef __NR_sched_setscheduler
    return 0;
#else
#   define OFF_NR    (offsetof(struct seccomp_data, nr))
#   define OFF_ARCH  (offsetof(struct seccomp_data, arch))
#   define OFF_ARG1  (offsetof(struct seccomp_data, args[1]))

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
#   if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#   elif defined(__aarch64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#   else
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
#   endif
#   if defined(__x86_64__) || defined(__aarch64__)
#       if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 8),
#       else
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 8),
#       endif
#   else
        BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
#   endif
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sched_setscheduler, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SCHED_OTHER, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SCHED_BATCH, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SCHED_IDLE, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        if (errno == EINVAL || errno == ENOSYS)
            return 0;
        return -errno;
    }

    return 0;
#endif
}
