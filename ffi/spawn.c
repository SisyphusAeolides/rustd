/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * spawn.c — fork/execve with uid/gid/cwd/fd setup.
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

#include "capability.h"
#include "sandbox.h"
#include "seccomp.h"
#include "spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FD_SCAN 1024
#define RUSTD_LISTEN_FDS_START 3

static int security_module_present(const char *const *paths) {
    for (size_t i = 0; paths[i]; i++) {
        struct stat st;
        if (stat(paths[i], &st) == 0)
            return 1;
        if (errno != ENOENT && errno != ENOTDIR)
            return -errno;
    }
    return 0;
}

static int write_process_attribute(
        const char *const *paths,
        const void *payload,
        size_t payload_len) {
    int last_missing = ENOENT;

    for (size_t i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                last_missing = errno;
                continue;
            }
            return -errno;
        }

        const unsigned char *cursor = payload;
        size_t remaining = payload_len;
        while (remaining > 0) {
            ssize_t n = write(fd, cursor, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                int error = errno;
                close(fd);
                return -error;
            }
            if (n == 0) {
                close(fd);
                return -EIO;
            }
            cursor += (size_t)n;
            remaining -= (size_t)n;
        }

        if (close(fd) < 0)
            return -errno;
        return 0;
    }

    return -last_missing;
}

static int apply_selinux_exec_context(const char *context) {
    if (!context || context[0] == '\0')
        return 0;

    static const char *const enabled_paths[] = {
        "/sys/fs/selinux/enforce",
        "/sys/fs/selinux",
        NULL,
    };
    int enabled = security_module_present(enabled_paths);
    if (enabled <= 0)
        return enabled;

    static const char *const attr_paths[] = {
        "/proc/thread-self/attr/selinux/exec",
        "/proc/self/attr/selinux/exec",
        "/proc/thread-self/attr/exec",
        "/proc/self/attr/exec",
        NULL,
    };
    return write_process_attribute(attr_paths, context, strlen(context) + 1);
}

static int apparmor_is_enabled(void) {
    int fd = open("/sys/module/apparmor/parameters/enabled", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -errno;

    char value = '\0';
    ssize_t n;
    do {
        n = read(fd, &value, 1);
    } while (n < 0 && errno == EINTR);
    int saved = errno;
    close(fd);
    if (n < 0)
        return -saved;
    return n == 1 && (value == 'Y' || value == 'y' || value == '1');
}

static int apply_apparmor_exec_profile(const char *profile) {
    if (!profile || profile[0] == '\0')
        return 0;

    int enabled = apparmor_is_enabled();
    if (enabled <= 0)
        return enabled;

    size_t profile_len = strlen(profile);
    if (profile_len > SIZE_MAX - sizeof("exec "))
        return -EOVERFLOW;
    size_t payload_len = sizeof("exec ") - 1 + profile_len;
    char *payload = malloc(payload_len);
    if (!payload)
        return -ENOMEM;
    memcpy(payload, "exec ", sizeof("exec ") - 1);
    memcpy(payload + sizeof("exec ") - 1, profile, profile_len);

    static const char *const attr_paths[] = {
        "/proc/thread-self/attr/apparmor/exec",
        "/proc/self/attr/apparmor/exec",
        "/proc/thread-self/attr/exec",
        "/proc/self/attr/exec",
        NULL,
    };
    int r = write_process_attribute(attr_paths, payload, payload_len);
    free(payload);
    return r;
}

static int apply_exec_mac_contexts(const rustd_spawn_params *p) {
    int r = apply_selinux_exec_context(p->selinux_context);
    if (r < 0 && !p->selinux_context_ignore)
        return r;

    r = apply_apparmor_exec_profile(p->apparmor_profile);
    if (r < 0 && !p->apparmor_profile_ignore)
        return r;
    return 0;
}

static void close_fds_except(int fd_first, const int *keep, int keep_count) {
    for (int fd = fd_first; fd < MAX_FD_SCAN; fd++) {
        int skip = 0;
        for (int k = 0; k < keep_count; k++) {
            if (keep[k] == fd) {
                skip = 1;
                break;
            }
        }
        if (!skip)
            close(fd);
    }
}

static int attach_self_to_cgroup(const char *path) {
    if (!path || path[0] == '\0')
        return 0;

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    static const char self[] = "0\n";
    size_t offset = 0;
    while (offset < sizeof(self) - 1) {
        ssize_t written = write(fd, self + offset, sizeof(self) - 1 - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int error = errno;
            close(fd);
            return -error;
        }
        offset += (size_t)written;
    }

    if (close(fd) < 0)
        return -errno;
    return 0;
}

static rlim_t decode_rlimit(uint64_t value) {
    return value == UINT64_MAX ? RLIM_INFINITY : (rlim_t)value;
}

static int setrlimit_closest_local(int resource, const struct rlimit *requested) {
    if (setrlimit(resource, requested) == 0)
        return 0;
    if (errno != EPERM)
        return -errno;

    struct rlimit highest;
    if (getrlimit(resource, &highest) < 0)
        return -errno;
    if (highest.rlim_max == RLIM_INFINITY)
        return -EPERM;

    struct rlimit fixed = {
        .rlim_cur = requested->rlim_cur < highest.rlim_max ? requested->rlim_cur : highest.rlim_max,
        .rlim_max = requested->rlim_max < highest.rlim_max ? requested->rlim_max : highest.rlim_max,
    };
    if (fixed.rlim_cur == highest.rlim_cur && fixed.rlim_max == highest.rlim_max)
        return 0;
    if (setrlimit(resource, &fixed) < 0)
        return -errno;
    return 0;
}

static int apply_rlimits(const rustd_spawn_rlimit *limits, size_t n_limits) {
    if (!limits || n_limits == 0)
        return 0;
    for (size_t i = 0; i < n_limits; i++) {
        struct rlimit value = {
            .rlim_cur = decode_rlimit(limits[i].soft),
            .rlim_max = decode_rlimit(limits[i].hard),
        };
        if (value.rlim_cur > value.rlim_max)
            return -EINVAL;
        int r = setrlimit_closest_local(limits[i].resource, &value);
        if (r < 0)
            return r;
    }
    return 0;
}

static int apply_environment(const char * const *envp) {
    if (!envp)
        return 0;

    for (size_t i = 0; envp[i]; i++) {
        const char *separator = strchr(envp[i], '=');
        if (!separator || separator == envp[i])
            return -EINVAL;

        size_t key_length = (size_t)(separator - envp[i]);
        char *key = strndup(envp[i], key_length);
        if (!key)
            return -ENOMEM;
        int result = setenv(key, separator + 1, 1);
        free(key);
        if (result < 0)
            return -errno;
    }
    return 0;
}

static _Noreturn void child_fail(int error_fd, int error_number, int exit_status) {
    if (error_fd >= 0) {
        if (error_number <= 0)
  error_number = EIO;
        ssize_t written;
        do {
  written = write(error_fd, &error_number, sizeof(error_number));
        } while (written < 0 && errno == EINTR);
    }
    _exit(exit_status);
}

static pid_t wait_for_exec_result(pid_t pid, int error_fd) {
    int error_number = 0;
    ssize_t length;
    do {
        length = read(error_fd, &error_number, sizeof(error_number));
    } while (length < 0 && errno == EINTR);
    int read_error = length < 0 ? errno : 0;
    close(error_fd);

    if (length == 0)
        return pid;

    int status;
    if (length == (ssize_t)sizeof(error_number)) {
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
  ;
        return error_number > 0 ? -error_number : -EIO;
    }

    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    return read_error != 0 ? -read_error : -EIO;
}


static void wait_for_idle_gate(int fd) {
    if (fd < 0)
        return;

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLHUP | POLLERR };
        while (poll(&pfd, 1, 5000) < 0 && errno == EINTR)
            ;
        close(fd);
        return;
    }

    int remaining_ms = 5000;
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLHUP | POLLERR };
        int r = poll(&pfd, 1, remaining_ms);
        if (r >= 0 || errno != EINTR)
            break;

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
            break;
        long long elapsed_ms = (long long)(now.tv_sec - start.tv_sec) * 1000LL
                             + (long long)(now.tv_nsec - start.tv_nsec) / 1000000LL;
        if (elapsed_ms >= 5000)
            break;
        remaining_ms = 5000 - (int)elapsed_ms;
    }

    close(fd);
}

int rustd_spawn_sandbox_needs_mount_namespace(const rustd_spawn_sandbox *sandbox) {
    if (!sandbox)
        return 0;
    return sandbox->private_tmp
        || sandbox->private_devices
        || sandbox->private_mounts
        || sandbox->protect_system > 0
        || sandbox->protect_home > 0
        || sandbox->protect_kernel_tunables
        || sandbox->protect_kernel_modules
        || sandbox->protect_kernel_logs
        || sandbox->protect_clock
        || sandbox->protect_control_groups
        || sandbox->restrict_suid_sgid;
}

pid_t rustd_spawn(const rustd_spawn_params *p) {
    if (!p || !p->path || p->path[0] == '\0' || !p->argv || !p->argv[0])
        return -EINVAL;

    int n_listen = (p->listen_fds && p->n_listen_fds > 0) ? p->n_listen_fds : 0;
    int exec_pipe[2] = { -1, -1 };
    if (p->wait_for_exec) {
        if (pipe2(exec_pipe, O_CLOEXEC) < 0)
  return -errno;
        int minimum_error_fd = RUSTD_LISTEN_FDS_START + n_listen;
        int moved = fcntl(exec_pipe[1], F_DUPFD_CLOEXEC, minimum_error_fd);
        if (moved < 0) {
  int error = errno;
  close(exec_pipe[0]);
  close(exec_pipe[1]);
  return -error;
        }
        close(exec_pipe[1]);
        exec_pipe[1] = moved;
    }

    int idle_gate_fd = -1;
    if ((p->idle_read_fd >= 0) != (p->idle_write_fd >= 0)) {
        if (exec_pipe[0] >= 0)
  close(exec_pipe[0]);
        if (exec_pipe[1] >= 0)
  close(exec_pipe[1]);
        return -EINVAL;
    }
    if (p->idle_read_fd >= 0) {
        int minimum_idle_fd = RUSTD_LISTEN_FDS_START + n_listen + (p->wait_for_exec ? 1 : 0);
        idle_gate_fd = fcntl(p->idle_read_fd, F_DUPFD_CLOEXEC, minimum_idle_fd);
        if (idle_gate_fd < 0) {
  int error = errno;
  if (exec_pipe[0] >= 0)
      close(exec_pipe[0]);
  if (exec_pipe[1] >= 0)
      close(exec_pipe[1]);
  return -error;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        if (exec_pipe[0] >= 0)
  close(exec_pipe[0]);
        if (exec_pipe[1] >= 0)
  close(exec_pipe[1]);
        if (idle_gate_fd >= 0)
  close(idle_gate_fd);
        return -error;
    }

    if (pid > 0) {
        if (idle_gate_fd >= 0)
  close(idle_gate_fd);
        if (!p->wait_for_exec)
  return pid;
        close(exec_pipe[1]);
        return wait_for_exec_result(pid, exec_pipe[0]);
    }

    int error_fd = -1;
    if (p->wait_for_exec) {
        close(exec_pipe[0]);
        error_fd = exec_pipe[1];
    }

    if (idle_gate_fd >= 0) {
        close(p->idle_read_fd);
        close(p->idle_write_fd);
    }

    for (int sig = 1; sig < NSIG; sig++) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sigaction(sig, &sa, NULL);
    }

    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);

    {
        int r = attach_self_to_cgroup(p->cgroup_procs_path);
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    if (p->stdin_fd == -1) {
        int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_fd < 0)
  child_fail(error_fd, errno, 125);
        if (dup2(null_fd, STDIN_FILENO) < 0) {
  int error = errno;
  close(null_fd);
  child_fail(error_fd, error, 125);
        }
        close(null_fd);
    } else if (p->stdin_fd != STDIN_FILENO && dup2(p->stdin_fd, STDIN_FILENO) < 0) {
        child_fail(error_fd, errno, 125);
    }

    if (p->stdout_fd >= 0 && p->stdout_fd != STDOUT_FILENO
  && dup2(p->stdout_fd, STDOUT_FILENO) < 0)
        child_fail(error_fd, errno, 125);
    if (p->stderr_fd >= 0 && p->stderr_fd != STDERR_FILENO
  && dup2(p->stderr_fd, STDERR_FILENO) < 0)
        child_fail(error_fd, errno, 125);

    if (p->sandbox) {
        const rustd_spawn_sandbox *sb = p->sandbox;
        int needs_mount_namespace = rustd_spawn_sandbox_needs_mount_namespace(sb);
        if (needs_mount_namespace || sb->private_network) {
  int r = rustd_sandbox_mount_namespaces(
      sb->private_tmp, sb->private_devices, sb->private_network,
      sb->protect_system, sb->protect_home, needs_mount_namespace);
  if (r < 0)
      child_fail(error_fd, -r, 125);
        }
        if (sb->protect_kernel_tunables || sb->protect_kernel_modules
      || sb->protect_kernel_logs || sb->protect_clock
      || sb->protect_control_groups || sb->restrict_suid_sgid) {
  int r = rustd_sandbox_protect_paths(
      sb->protect_kernel_tunables, sb->protect_kernel_modules,
      sb->protect_kernel_logs, sb->protect_clock,
      sb->protect_control_groups, sb->restrict_suid_sgid);
  if (r < 0)
      child_fail(error_fd, -r, 125);
        }
    }

    {
        int r = apply_exec_mac_contexts(p);
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    int seccomp_forced_no_new_privs = 0;
    if (p->sandbox && p->sandbox->restrict_realtime) {
        int r = rustd_sandbox_restrict_realtime();
        if (r == -EACCES || r == -EPERM) {
  r = rustd_sandbox_no_new_privs();
  if (r < 0)
      child_fail(error_fd, -r, 125);
  seccomp_forced_no_new_privs = 1;
  r = rustd_sandbox_restrict_realtime();
        }
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (p->sandbox && p->sandbox->memory_deny_write_execute) {
        int r = rustd_seccomp_memory_deny_write_execute();
        if (r < 0)
  child_fail(error_fd, -r, 125);
        seccomp_forced_no_new_privs = 1;
    }

    if (p->sandbox && p->sandbox->restrict_namespaces) {
        int r = rustd_seccomp_restrict_namespaces(0);
        if (r < 0)
  child_fail(error_fd, -r, 125);
        seccomp_forced_no_new_privs = 1;
    }

    if (p->sandbox && p->sandbox->protect_kernel_logs) {
        int r = rustd_seccomp_protect_kernel_logs();
        if (r == -EACCES || r == -EPERM) {
            r = rustd_sandbox_no_new_privs();
            if (r < 0)
                child_fail(error_fd, -r, 125);
            seccomp_forced_no_new_privs = 1;
            r = rustd_seccomp_protect_kernel_logs();
        }
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    if (p->sandbox && p->sandbox->protect_clock) {
        int r = rustd_seccomp_protect_clock();
        if (r == -EACCES || r == -EPERM) {
            r = rustd_sandbox_no_new_privs();
            if (r < 0)
                child_fail(error_fd, -r, 125);
            seccomp_forced_no_new_privs = 1;
            r = rustd_seccomp_protect_clock();
        }
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    {
        int r = apply_rlimits(p->rlimits, p->n_rlimits);
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    if (p->cap_bounding_set != UINT64_MAX) {
        int r = rustd_capability_bounding_set_drop(p->cap_bounding_set);
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (p->ambient_caps != 0 && p->cap_bounding_set != UINT64_MAX
  && (p->ambient_caps & ~p->cap_bounding_set) != 0)
        child_fail(error_fd, EINVAL, 125);

    int keep_caps = 0;
    if (p->ambient_caps != 0 && (uid_t)p->uid != (uid_t)-1
  && p->uid != geteuid()) {
        if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) < 0)
  child_fail(error_fd, errno, 125);
        keep_caps = 1;
    }

    if ((gid_t)p->gid != (gid_t)-1) {
        if (setgroups(0, NULL) < 0)
  child_fail(error_fd, errno, 125);
        if (setresgid(p->gid, p->gid, p->gid) < 0)
  child_fail(error_fd, errno, 125);
    }

    if ((uid_t)p->uid != (uid_t)-1) {
        if (setresuid(p->uid, p->uid, p->uid) < 0)
  child_fail(error_fd, errno, 125);
    }

    if (p->ambient_caps != 0) {
        int r = rustd_capability_ambient_prepare(p->ambient_caps);
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (keep_caps && prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) < 0)
        child_fail(error_fd, errno, 125);

    {
        int r = rustd_capability_ambient_apply(p->ambient_caps);
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (p->sandbox && p->sandbox->no_new_privs && !seccomp_forced_no_new_privs) {
        int r = rustd_sandbox_no_new_privs();
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (p->cwd && p->cwd[0] != '\0' && chdir(p->cwd) < 0)
        child_fail(error_fd, errno, 126);

    {
        int r = apply_environment(p->envp);
        if (r < 0)
  child_fail(error_fd, -r, 125);
    }

    if (n_listen > 0) {
        for (int i = 0; i < n_listen; i++) {
  int src = p->listen_fds[i];
  int dst = RUSTD_LISTEN_FDS_START + i;
  if (src == dst) {
      int fl = fcntl(dst, F_GETFD);
      if (fl < 0 || fcntl(dst, F_SETFD, fl & ~FD_CLOEXEC) < 0)
          child_fail(error_fd, errno, 125);
  } else {
      if (dup2(src, dst) < 0)
          child_fail(error_fd, errno, 125);
      int fl = fcntl(dst, F_GETFD);
      if (fl < 0 || fcntl(dst, F_SETFD, fl & ~FD_CLOEXEC) < 0)
          child_fail(error_fd, errno, 125);
      if (src >= RUSTD_LISTEN_FDS_START)
          close(src);
  }
        }

        char buf[32];
        snprintf(buf, sizeof(buf), "%d", n_listen);
        if (setenv("LISTEN_FDS", buf, 1) < 0)
  child_fail(error_fd, errno, 125);
        snprintf(buf, sizeof(buf), "%d", (int)getpid());
        if (setenv("LISTEN_PID", buf, 1) < 0)
  child_fail(error_fd, errno, 125);
    }

    if (p->notify_fd >= 0) {
        const char *notify_socket = getenv("RUSTD_NOTIFY_SOCKET");
        if (!notify_socket || notify_socket[0] == '\0')
  notify_socket = "@rustd/notify";
        if (setenv("NOTIFY_SOCKET", notify_socket, 1) < 0)
  child_fail(error_fd, errno, 125);
    }

    if (p->watchdog_usec > 0) {
        char watchdog_value[32];
        snprintf(
  watchdog_value,
  sizeof(watchdog_value),
  "%llu",
  (unsigned long long)p->watchdog_usec);
        if (setenv("WATCHDOG_USEC", watchdog_value, 1) < 0)
  child_fail(error_fd, errno, 125);
        snprintf(watchdog_value, sizeof(watchdog_value), "%d", (int)getpid());
        if (setenv("WATCHDOG_PID", watchdog_value, 1) < 0)
  child_fail(error_fd, errno, 125);
    }

    int max_keep = 5 + n_listen;
    int *keep = malloc((size_t)max_keep * sizeof(int));
    if (!keep)
        child_fail(error_fd, ENOMEM, 125);
    int keep_count = 0;
    keep[keep_count++] = STDIN_FILENO;
    keep[keep_count++] = STDOUT_FILENO;
    keep[keep_count++] = STDERR_FILENO;
    for (int i = 0; i < n_listen; i++)
        keep[keep_count++] = RUSTD_LISTEN_FDS_START + i;
    if (error_fd >= RUSTD_LISTEN_FDS_START)
        keep[keep_count++] = error_fd;
    if (idle_gate_fd >= RUSTD_LISTEN_FDS_START)
        keep[keep_count++] = idle_gate_fd;

    close_fds_except(3, keep + 3, keep_count - 3);
    free(keep);

    wait_for_idle_gate(idle_gate_fd);

    if (p->sandbox && p->sandbox->restrict_native_syscalls) {
        int r = rustd_seccomp_restrict_native_architecture();
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    if (p->sandbox && p->sandbox->syscall_filter_enabled) {
        int r = rustd_seccomp_syscall_rules(
            p->sandbox->syscall_filter_rules,
            p->sandbox->n_syscall_filter_rules,
            p->sandbox->syscall_filter_default_action);
        if (r < 0)
            child_fail(error_fd, -r, 125);
    }

    if (strchr(p->path, '/'))
        execv(p->path, (char * const *)p->argv);
    else
        execvp(p->path, (char * const *)p->argv);
    child_fail(error_fd, errno, 127);
}
