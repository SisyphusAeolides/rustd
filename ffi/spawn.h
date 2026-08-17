/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "capability.h"
#include "sandbox.h"
#include "seccomp.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    int resource;
    uint64_t soft;
    uint64_t hard;
} rustd_spawn_rlimit;

/*
 * spawn.h — process spawning parameters.
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

/*
 * rustd_spawn_sandbox: security sandbox parameters passed alongside
 * rustd_spawn_params.  NULL means no sandboxing.
 */
typedef struct {
    int no_new_privs;       /* boolean: set PR_SET_NO_NEW_PRIVS              */
    int private_tmp;        /* boolean: private tmpfs on /tmp, /var/tmp      */
    int private_devices;    /* boolean: minimal /dev in new mount namespace  */
    int private_network;    /* boolean: new empty network namespace          */
    int private_mounts;     /* boolean: force a private mount namespace       */
    int protect_system;     /* 0=no, 1=yes, 2=full, 3=strict                */
    int protect_home;       /* 0=no, 1=yes, 2=read-only, 3=tmpfs            */
    int protect_kernel_tunables; /* boolean: /proc/sys, /sys read-only       */
    int protect_kernel_modules;  /* boolean: /lib/modules read-only          */
    int protect_kernel_logs;     /* boolean: deny kmsg/syslog access         */
    int protect_clock;           /* boolean: deny clock/RTC modification     */
    int protect_control_groups; /* boolean: /sys/fs/cgroup read-only         */
    int restrict_suid_sgid; /* boolean: nosuid on /dev, /tmp                */
    int restrict_realtime;  /* boolean: seccomp-block RT scheduling         */
    int restrict_namespaces;/* boolean: block namespace changes              */
    int memory_deny_write_execute; /* boolean: block executable writable mappings */
    const rustd_seccomp_rule *syscall_filter_rules; /* compiled SystemCallFilter rules */
    size_t n_syscall_filter_rules;
    uint32_t syscall_filter_default_action;
    int syscall_filter_enabled;
    int restrict_native_syscalls; /* SystemCallArchitectures=native */
} rustd_spawn_sandbox;

typedef struct {
    const char         *path;   /* executable path, independent of argv[0]   */
    const char * const *argv;   /* NULL-terminated; argv[0] is the exec path  */
    const char * const *envp;   /* NULL-terminated; NULL = inherit parent env  */
    const char         *cwd;    /* working directory; NULL = inherit parent    */
    const char         *cgroup_procs_path; /* NULL = no pre-exec cgroup move    */
    const rustd_spawn_rlimit *rlimits; /* requested process resource limits    */
    size_t              n_rlimits; /* entries in rlimits                    */
    uid_t               uid;    /* (uid_t)-1 = do not switch                   */
    gid_t               gid;    /* (gid_t)-1 = do not switch                   */
    const char         *selinux_context; /* NULL = no SELinux exec transition */
    int                 selinux_context_ignore; /* ignore transition failure    */
    const char         *apparmor_profile; /* NULL = no AppArmor exec profile   */
    int                 apparmor_profile_ignore; /* ignore profile failure       */
    int                 stdin_fd;   /* -1 = redirect to /dev/null              */
    int                 stdout_fd;  /* -1 = inherit parent stdout              */
    int                 stderr_fd;  /* -1 = inherit parent stderr              */
    int                 notify_fd;  /* -1 = none; >=0 sets RUSTD_NOTIFY_SOCKET       */
    uint64_t            watchdog_usec; /* 0 = watchdog disabled                 */
    const rustd_spawn_sandbox *sandbox; /* NULL = no sandbox                      */
    /*
     * RUSTD_LISTEN_FDS pass-through:
     * listen_fds  — array of file descriptors to pass to the child.
     *               They are renumbered to start at fd 3 and RUSTD_LISTEN_FDS /
     *               RUSTD_LISTEN_PID env vars are set accordingly.
     * n_listen_fds — number of entries in listen_fds[]; 0 = none.
     */
    const int          *listen_fds;   /* NULL or array of fds to pass          */
    int                 n_listen_fds; /* number of entries; 0 = none           */
    /*
     * Capability bounding set and ambient capabilities.
     * cap_bounding_set: bitmask of capabilities to KEEP (others are dropped).
     *   UINT64_MAX = keep all (no change).  0 = drop all.
     * ambient_caps: bitmask of capabilities to raise as ambient.
     *   0 = none.
     */
    uint64_t            cap_bounding_set; /* UINT64_MAX = no change */
    uint64_t            ambient_caps;     /* 0 = none               */
    int                 wait_for_exec;    /* boolean: wait for exec handoff    */
    int                 idle_read_fd;     /* read side of Type=idle exec gate  */
    int                 idle_write_fd;    /* writer held by the manager        */
} rustd_spawn_params;

/* Return non-zero when the sandbox requires CLONE_NEWNS before mount changes. */
int rustd_spawn_sandbox_needs_mount_namespace(const rustd_spawn_sandbox *sandbox);

/*
 * rustd_spawn_helper_configure: install the executable rustd_spawn() launches
 * to perform child setup.  `executable_path` must be an absolute path to a
 * RustD image; that image applies the request from its ELF constructor when it
 * is started in helper mode and never reaches its own main().
 *
 * The manager must call this before it creates any thread, because rustd_spawn
 * refuses to run (-ENOSYS) until a helper is configured and because the stored
 * path is only safe to publish while the process is still single-threaded.
 *
 * Returns 0 on success, or a negative errno on failure.
 */
int rustd_spawn_helper_configure(const char *executable_path);

/* Return non-zero once a helper image has been installed. */
int rustd_spawn_helper_configured(void);

/*
 * rustd_spawn: start a child process with the given parameters.
 *
 * The manager does not fork: it posix_spawn()s the configured helper image,
 * which applies the parameters in a fresh single-threaded process and then
 * execs the requested executable in place.  The returned PID is therefore the
 * final service PID and a direct child of the caller.
 *
 * Returns the child PID on success, or a negative errno on failure.
 * With wait_for_exec set, child setup and exec errors are reported through
 * the return value. Otherwise those failures are reported by child exit status.
 */
pid_t rustd_spawn(const rustd_spawn_params *p);
