/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * spawn_helper.c — child side of rustd_spawn().
 *
 * This code runs in a fresh image that posix_spawn() created for the manager,
 * so it is a brand new single-threaded process rather than a copy of PID 1.
 * The helper is the final service process and execs in place.
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

#include "capability.h"
#include "sandbox.h"
#include "seccomp.h"
#include "spawn.h"
#include "spawn_helper.h"
#include "spawn_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MAX_FD_SCAN 1024
#define RUSTD_SPAWN_IDLE_TIMEOUT_MS 5000

typedef struct {
    rustd_spawn_wire_header header;
    unsigned char *blob;
    const char *path;
    const char **argv;
    const char **envp;
    const char *cwd;
    const char *cgroup_procs_path;
    const char *selinux_context;
    const char *apparmor_profile;
    const char *notify_socket;
    const char **read_write_paths;
    rustd_spawn_rlimit *rlimits;
    rustd_seccomp_rule *seccomp_rules;
    rustd_spawn_sandbox sandbox;
} rustd_spawn_request;

static int error_descriptor = -1;

static void helper_log_kmsg(int error_number, const char *step, int step_line) {
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0)
        return;

    char line[256];
    int length = snprintf(
            line,
            sizeof(line),
            "<3>rustd-spawn-helper: %s+%d failed: %s\n",
            step,
            step_line,
            strerror(error_number));
    if (length > 0) {
        ssize_t written;
        do {
            written = write(fd, line, (size_t)length);
        } while (written < 0 && errno == EINTR);
    }
    close(fd);
}

#define helper_fail(error_number, exit_status) \
    helper_fail_at((error_number), (exit_status), __func__, __LINE__)

static _Noreturn void helper_fail_at(
        int error_number, int exit_status, const char *step, int step_line) {
    if (error_number <= 0)
        error_number = EIO;
    if (error_descriptor >= 0) {
        ssize_t written;
        do {
            written = send(
                    error_descriptor, &error_number, sizeof(error_number), MSG_NOSIGNAL);
        } while (written < 0 && errno == EINTR);
    }
    helper_log_kmsg(error_number, step, step_line);
    _exit(exit_status);
}

static int read_request_blob(int fd, unsigned char **ret_blob, size_t *ret_size) {
    struct stat status;
    if (fstat(fd, &status) < 0)
        return -errno;
    if (!S_ISREG(status.st_mode))
        return -EPROTO;
    if (status.st_size < (off_t)sizeof(rustd_spawn_wire_header))
        return -EPROTO;
    if ((size_t)status.st_size > RUSTD_SPAWN_MAX_REQUEST_BYTES)
        return -E2BIG;

    int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0)
        return -EPROTO;
    if ((seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK))
        != (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK))
        return -EPROTO;

    size_t size = (size_t)status.st_size;
    unsigned char *blob = malloc(size);
    if (!blob)
        return -ENOMEM;

    size_t offset = 0;
    while (offset < size) {
        ssize_t length = pread(fd, blob + offset, size - offset, (off_t)offset);
        if (length < 0) {
            if (errno == EINTR)
                continue;
            int error = errno;
            free(blob);
            return -error;
        }
        if (length == 0) {
            free(blob);
            return -EPROTO;
        }
        offset += (size_t)length;
    }

    *ret_blob = blob;
    *ret_size = size;
    return 0;
}

static int decode_header(const rustd_spawn_wire_header *header, size_t size) {
    if (header->magic != RUSTD_SPAWN_WIRE_MAGIC)
        return -EPROTO;
    if (header->version != RUSTD_SPAWN_WIRE_VERSION)
        return -EPROTO;
    if (header->header_bytes != sizeof(*header))
        return -EPROTO;
    if (header->total_bytes != size)
        return -EPROTO;
    if ((header->flags & ~RUSTD_SPAWN_FLAG_ALL) != 0)
        return -EPROTO;
    if (header->n_argv == 0 || header->n_argv > RUSTD_SPAWN_MAX_ARGV)
        return -EPROTO;
    if (header->n_env > RUSTD_SPAWN_MAX_ENV)
        return -EPROTO;
    if (header->n_rlimits > RUSTD_SPAWN_MAX_RLIMITS)
        return -EPROTO;
    if (header->n_listen_fds > (uint32_t)RUSTD_SPAWN_MAX_LISTEN_FDS)
        return -EPROTO;
    if (header->n_seccomp_rules > RUSTD_SPAWN_MAX_SECCOMP_RULES)
        return -EPROTO;
    if (header->n_read_write_paths > RUSTD_SPAWN_MAX_READ_WRITE_PATHS)
        return -EPROTO;
    if (header->n_env > 0 && !(header->flags & RUSTD_SPAWN_FLAG_HAS_ENVIRONMENT))
        return -EPROTO;
    if (header->n_read_write_paths > 0 && !(header->flags & RUSTD_SPAWN_FLAG_HAS_SANDBOX))
        return -EPROTO;
    return 0;
}

static int decode_vector(
        rustd_spawn_reader *reader,
        uint32_t count,
        const char ***ret_vector) {
    const char **vector = calloc((size_t)count + 1, sizeof(*vector));
    if (!vector)
        return -ENOMEM;
    for (uint32_t i = 0; i < count; i++) {
        int r = rustd_spawn_read_string(reader, &vector[i]);
        if (r < 0) {
            free(vector);
            return r;
        }
    }
    vector[count] = NULL;
    *ret_vector = vector;
    return 0;
}

static int valid_read_write_path(const char *value) {
    if (!value || value[0] == '\0')
        return 0;
    const char *path = value[0] == '-' ? value + 1 : value;
    return path[0] == '/';
}

static void request_release(rustd_spawn_request *request) {
    free(request->argv);
    free(request->envp);
    free(request->read_write_paths);
    free(request->rlimits);
    free(request->seccomp_rules);
    free(request->blob);
    memset(request, 0, sizeof(*request));
}

static int decode_request(int fd, rustd_spawn_request *request) {
    memset(request, 0, sizeof(*request));

    size_t size = 0;
    int r = read_request_blob(fd, &request->blob, &size);
    if (r < 0)
        return r;

    memcpy(&request->header, request->blob, sizeof(request->header));
    r = decode_header(&request->header, size);
    if (r < 0)
        goto fail;

    rustd_spawn_reader reader = {
        .data = request->blob,
        .size = size,
        .offset = sizeof(request->header),
    };

    r = rustd_spawn_read_string(&reader, &request->path);
    if (r < 0)
        goto fail;
    if (request->path[0] == '\0') {
        r = -EPROTO;
        goto fail;
    }

    r = decode_vector(&reader, request->header.n_argv, &request->argv);
    if (r < 0)
        goto fail;
    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_ENVIRONMENT) {
        r = decode_vector(&reader, request->header.n_env, &request->envp);
        if (r < 0)
            goto fail;
    }

    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_CWD) {
        r = rustd_spawn_read_string(&reader, &request->cwd);
        if (r < 0)
            goto fail;
    }
    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_CGROUP) {
        r = rustd_spawn_read_string(&reader, &request->cgroup_procs_path);
        if (r < 0)
            goto fail;
    }
    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_SELINUX) {
        r = rustd_spawn_read_string(&reader, &request->selinux_context);
        if (r < 0)
            goto fail;
    }
    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_APPARMOR) {
        r = rustd_spawn_read_string(&reader, &request->apparmor_profile);
        if (r < 0)
            goto fail;
    }
    if (request->header.flags & RUSTD_SPAWN_FLAG_HAS_NOTIFY_SOCKET) {
        r = rustd_spawn_read_string(&reader, &request->notify_socket);
        if (r < 0)
            goto fail;
    }

    if (request->header.n_read_write_paths > 0) {
        r = decode_vector(&reader, request->header.n_read_write_paths, &request->read_write_paths);
        if (r < 0)
            goto fail;
        for (uint32_t i = 0; i < request->header.n_read_write_paths; i++) {
            if (!valid_read_write_path(request->read_write_paths[i])) {
                r = -EPROTO;
                goto fail;
            }
        }
    }

    if (request->header.n_rlimits > 0) {
        request->rlimits = calloc(request->header.n_rlimits, sizeof(*request->rlimits));
        if (!request->rlimits) {
            r = -ENOMEM;
            goto fail;
        }
        for (uint32_t i = 0; i < request->header.n_rlimits; i++) {
            uint32_t resource;
            uint64_t soft;
            uint64_t hard;
            if (rustd_spawn_read_u32(&reader, &resource) < 0
                || rustd_spawn_read_u64(&reader, &soft) < 0
                || rustd_spawn_read_u64(&reader, &hard) < 0) {
                r = -EPROTO;
                goto fail;
            }
            request->rlimits[i].resource = (int)resource;
            request->rlimits[i].soft = soft;
            request->rlimits[i].hard = hard;
        }
    }

    if (request->header.n_seccomp_rules > 0) {
        request->seccomp_rules = calloc(request->header.n_seccomp_rules, sizeof(*request->seccomp_rules));
        if (!request->seccomp_rules) {
            r = -ENOMEM;
            goto fail;
        }
        for (uint32_t i = 0; i < request->header.n_seccomp_rules; i++) {
            uint32_t number;
            uint32_t action;
            if (rustd_spawn_read_u32(&reader, &number) < 0
                || rustd_spawn_read_u32(&reader, &action) < 0) {
                r = -EPROTO;
                goto fail;
            }
            request->seccomp_rules[i].nr = (int)number;
            request->seccomp_rules[i].action = action;
        }
    }

    if (reader.offset != size) {
        r = -EPROTO;
        goto fail;
    }

    const rustd_spawn_wire_header *header = &request->header;
    request->sandbox.no_new_privs = (int)header->no_new_privs;
    request->sandbox.private_tmp = (int)header->private_tmp;
    request->sandbox.private_devices = (int)header->private_devices;
    request->sandbox.private_network = (int)header->private_network;
    request->sandbox.private_mounts = (int)header->private_mounts;
    request->sandbox.protect_system = (int)header->protect_system;
    request->sandbox.protect_home = (int)header->protect_home;
    request->sandbox.protect_kernel_tunables = (int)header->protect_kernel_tunables;
    request->sandbox.protect_kernel_modules = (int)header->protect_kernel_modules;
    request->sandbox.protect_kernel_logs = (int)header->protect_kernel_logs;
    request->sandbox.protect_clock = (int)header->protect_clock;
    request->sandbox.protect_control_groups = (int)header->protect_control_groups;
    request->sandbox.restrict_suid_sgid = (int)header->restrict_suid_sgid;
    request->sandbox.restrict_realtime = (int)header->restrict_realtime;
    request->sandbox.restrict_namespaces = (int)header->restrict_namespaces;
    request->sandbox.memory_deny_write_execute = (int)header->memory_deny_write_execute;
    request->sandbox.syscall_filter_rules = request->seccomp_rules;
    request->sandbox.n_syscall_filter_rules = header->n_seccomp_rules;
    request->sandbox.syscall_filter_default_action = header->seccomp_default_action;
    request->sandbox.syscall_filter_enabled = (int)header->syscall_filter_enabled;
    request->sandbox.restrict_native_syscalls = (int)header->restrict_native_syscalls;
    request->sandbox.read_write_paths = request->read_write_paths;
    request->sandbox.n_read_write_paths = header->n_read_write_paths;
    return 0;

fail:
    request_release(request);
    return r;
}

static void close_descriptors_from(unsigned int first) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, (unsigned int)first, ~0U, 0U) == 0)
        return;
#endif
    long scan_limit = MAX_FD_SCAN;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY
        && (long)limit.rlim_cur > scan_limit)
        scan_limit = (long)limit.rlim_cur;
    if (scan_limit > 65536)
        scan_limit = 65536;
    for (long fd = (long)first; fd < scan_limit; fd++)
        close((int)fd);
}

static int lift_control_descriptor(int fd, int minimum, int *ret_fd) {
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, minimum);
    if (moved < 0)
        return -errno;
    close(fd);
    *ret_fd = moved;
    return 0;
}

static int publish_listen_descriptors(uint32_t n_listen) {
    for (uint32_t i = 0; i < n_listen; i++) {
        int source = RUSTD_SPAWN_LISTEN_FD_BASE + (int)i;
        int target = RUSTD_LISTEN_FDS_START + (int)i;
        if (dup2(source, target) < 0)
            return -errno;
    }
    for (int fd = RUSTD_LISTEN_FDS_START + (int)n_listen;
         fd < RUSTD_SPAWN_LISTEN_FD_BASE + (int)n_listen;
         fd++)
        close(fd);

    if (n_listen == 0)
        return 0;

    char value[32];
    snprintf(value, sizeof(value), "%u", n_listen);
    if (setenv("RUSTD_LISTEN_FDS", value, 1) < 0)
        return -errno;
    if (setenv("LISTEN_FDS", value, 1) < 0)
        return -errno;
    snprintf(value, sizeof(value), "%d", (int)getpid());
    if (setenv("RUSTD_LISTEN_PID", value, 1) < 0)
        return -errno;
    if (setenv("LISTEN_PID", value, 1) < 0)
        return -errno;
    return 0;
}

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
        "/sys/fs/selinux/enforce", "/sys/fs/selinux", NULL,
    };
    int enabled = security_module_present(enabled_paths);
    if (enabled <= 0)
        return enabled;

    static const char *const attr_paths[] = {
        "/proc/thread-self/attr/selinux/exec", "/proc/self/attr/selinux/exec",
        "/proc/thread-self/attr/exec", "/proc/self/attr/exec", NULL,
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
        "/proc/thread-self/attr/apparmor/exec", "/proc/self/attr/apparmor/exec",
        "/proc/thread-self/attr/exec", "/proc/self/attr/exec", NULL,
    };
    int r = write_process_attribute(attr_paths, payload, payload_len);
    free(payload);
    return r;
}

static int apply_exec_mac_contexts(const rustd_spawn_request *request) {
    int r = apply_selinux_exec_context(request->selinux_context);
    if (r < 0 && !(request->header.flags & RUSTD_SPAWN_FLAG_SELINUX_IGNORE))
        return r;

    r = apply_apparmor_exec_profile(request->apparmor_profile);
    if (r < 0 && !(request->header.flags & RUSTD_SPAWN_FLAG_APPARMOR_IGNORE))
        return r;
    return 0;
}

static int attach_self_to_cgroup(const char *path) {
    if (!path || path[0] == '\0')
        return 0;

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        int error = errno;
        int kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC | O_NOCTTY);
        if (kmsg >= 0) {
            char line[512];
            int length = snprintf(
                    line, sizeof(line),
                    "<3>rustd-spawn-helper: attach_self_to_cgroup open('%s') failed: %s\n",
                    path, strerror(error));
            if (length > 0) {
                ssize_t written;
                do {
                    written = write(kmsg, line, (size_t)length);
                } while (written < 0 && errno == EINTR);
            }
            close(kmsg);
        }
        return -error;
    }

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

static int apply_environment(const char *const *envp) {
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

static void wait_for_idle_gate(int fd) {
    if (fd < 0)
        return;

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLHUP | POLLERR };
        while (poll(&pfd, 1, RUSTD_SPAWN_IDLE_TIMEOUT_MS) < 0 && errno == EINTR)
            ;
        close(fd);
        return;
    }

    int remaining_ms = RUSTD_SPAWN_IDLE_TIMEOUT_MS;
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
        if (elapsed_ms >= RUSTD_SPAWN_IDLE_TIMEOUT_MS)
            break;
        remaining_ms = RUSTD_SPAWN_IDLE_TIMEOUT_MS - (int)elapsed_ms;
    }

    close(fd);
}

static void establish_controlling_tty(const rustd_spawn_request *request) {
    if (!isatty(STDIN_FILENO))
        return;

    if (setsid() < 0)
        helper_fail(errno, 125);
    int force = (request->header.flags & RUSTD_SPAWN_FLAG_TTY_FORCE) != 0;
    if (ioctl(STDIN_FILENO, TIOCSCTTY, force ? 1 : 0) < 0)
        helper_fail(errno, 125);
}

static void apply_sandbox_mounts(const rustd_spawn_request *request) {
    if (!(request->header.flags & RUSTD_SPAWN_FLAG_HAS_SANDBOX))
        return;

    const rustd_spawn_sandbox *sandbox = &request->sandbox;
    int needs_mount_namespace = rustd_spawn_sandbox_needs_mount_namespace(sandbox);
    if (needs_mount_namespace || sandbox->private_network) {
        int r = rustd_sandbox_mount_namespaces(
                sandbox->private_tmp, sandbox->private_devices, sandbox->private_network,
                sandbox->protect_system, sandbox->protect_home, needs_mount_namespace);
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (sandbox->n_read_write_paths > 0) {
        int r = rustd_sandbox_make_writable_paths(
                sandbox->read_write_paths, sandbox->n_read_write_paths);
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (sandbox->protect_kernel_tunables || sandbox->protect_kernel_modules
        || sandbox->protect_kernel_logs || sandbox->protect_clock
        || sandbox->protect_control_groups || sandbox->restrict_suid_sgid) {
        int r = rustd_sandbox_protect_paths(
                sandbox->protect_kernel_tunables, sandbox->protect_kernel_modules,
                sandbox->protect_kernel_logs, sandbox->protect_clock,
                sandbox->protect_control_groups, sandbox->restrict_suid_sgid);
        if (r < 0)
            helper_fail(-r, 125);
    }
}

static void apply_sandbox_filters(const rustd_spawn_request *request, int *forced_no_new_privs) {
    if (!(request->header.flags & RUSTD_SPAWN_FLAG_HAS_SANDBOX))
        return;

    const rustd_spawn_sandbox *sandbox = &request->sandbox;
    if (sandbox->restrict_realtime) {
        int r = rustd_sandbox_restrict_realtime();
        if (r == -EACCES || r == -EPERM) {
            r = rustd_sandbox_no_new_privs();
            if (r < 0)
                helper_fail(-r, 125);
            *forced_no_new_privs = 1;
            r = rustd_sandbox_restrict_realtime();
        }
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (sandbox->memory_deny_write_execute) {
        int r = rustd_seccomp_memory_deny_write_execute();
        if (r < 0)
            helper_fail(-r, 125);
        *forced_no_new_privs = 1;
    }

    if (sandbox->restrict_namespaces) {
        int r = rustd_seccomp_restrict_namespaces(0);
        if (r < 0)
            helper_fail(-r, 125);
        *forced_no_new_privs = 1;
    }

    if (sandbox->protect_kernel_logs) {
        int r = rustd_seccomp_protect_kernel_logs();
        if (r == -EACCES || r == -EPERM) {
            r = rustd_sandbox_no_new_privs();
            if (r < 0)
                helper_fail(-r, 125);
            *forced_no_new_privs = 1;
            r = rustd_seccomp_protect_kernel_logs();
        }
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (sandbox->protect_clock) {
        int r = rustd_seccomp_protect_clock();
        if (r == -EACCES || r == -EPERM) {
            r = rustd_sandbox_no_new_privs();
            if (r < 0)
                helper_fail(-r, 125);
            *forced_no_new_privs = 1;
            r = rustd_seccomp_protect_clock();
        }
        if (r < 0)
            helper_fail(-r, 125);
    }
}

static void apply_credentials(const rustd_spawn_request *request) {
    const rustd_spawn_wire_header *header = &request->header;

    if (header->cap_bounding_set != UINT64_MAX) {
        int r = rustd_capability_bounding_set_drop(header->cap_bounding_set);
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (header->ambient_caps != 0 && header->cap_bounding_set != UINT64_MAX
        && (header->ambient_caps & ~header->cap_bounding_set) != 0)
        helper_fail(EINVAL, 125);

    int keep_caps = 0;
    if (header->ambient_caps != 0 && (uid_t)header->uid != (uid_t)-1
        && (uid_t)header->uid != geteuid()) {
        if (prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) < 0)
            helper_fail(errno, 125);
        keep_caps = 1;
    }

    if ((gid_t)header->gid != (gid_t)-1) {
        if (setgroups(0, NULL) < 0)
            helper_fail(errno, 125);
        if (setresgid((gid_t)header->gid, (gid_t)header->gid, (gid_t)header->gid) < 0)
            helper_fail(errno, 125);
    }

    if ((uid_t)header->uid != (uid_t)-1) {
        if (setresuid((uid_t)header->uid, (uid_t)header->uid, (uid_t)header->uid) < 0)
            helper_fail(errno, 125);
    }

    if (header->ambient_caps != 0) {
        int r = rustd_capability_ambient_prepare(header->ambient_caps);
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (keep_caps && prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) < 0)
        helper_fail(errno, 125);

    {
        int r = rustd_capability_ambient_apply(header->ambient_caps);
        if (r < 0)
            helper_fail(-r, 125);
    }
}

static void apply_service_environment(const rustd_spawn_request *request) {
    const rustd_spawn_wire_header *header = &request->header;

    int r = apply_environment(request->envp);
    if (r < 0)
        helper_fail(-r, 125);

    r = publish_listen_descriptors(header->n_listen_fds);
    if (r < 0)
        helper_fail(-r, 125);

    if (request->notify_socket && setenv("RUSTD_NOTIFY_SOCKET", request->notify_socket, 1) < 0)
        helper_fail(errno, 125);
    if (request->notify_socket && setenv("NOTIFY_SOCKET", request->notify_socket, 1) < 0)
        helper_fail(errno, 125);

    if (header->watchdog_usec > 0) {
        char value[32];
        snprintf(value, sizeof(value), "%llu", (unsigned long long)header->watchdog_usec);
        if (setenv("RUSTD_WATCHDOG_USEC", value, 1) < 0)
            helper_fail(errno, 125);
        snprintf(value, sizeof(value), "%d", (int)getpid());
        if (setenv("RUSTD_WATCHDOG_PID", value, 1) < 0)
            helper_fail(errno, 125);
    }
}

_Noreturn void rustd_spawn_helper_main(void) {
    error_descriptor = RUSTD_SPAWN_ERROR_FD;

    rustd_spawn_request request;
    int r = decode_request(RUSTD_SPAWN_REQUEST_FD, &request);
    close(RUSTD_SPAWN_REQUEST_FD);
    if (r < 0)
        helper_fail(-r, 125);

    int n_listen = (int)request.header.n_listen_fds;
    int idle_fd = -1;
    if (!(request.header.flags & RUSTD_SPAWN_FLAG_HAS_IDLE_GATE))
        close(RUSTD_SPAWN_IDLE_FD);

    close_descriptors_from((unsigned int)(RUSTD_SPAWN_LISTEN_FD_BASE + n_listen));

    r = lift_control_descriptor(
            RUSTD_SPAWN_ERROR_FD,
            RUSTD_SPAWN_LISTEN_FD_BASE + n_listen,
            &error_descriptor);
    if (r < 0) {
        error_descriptor = RUSTD_SPAWN_ERROR_FD;
        helper_fail(-r, 125);
    }
    if (request.header.flags & RUSTD_SPAWN_FLAG_HAS_IDLE_GATE) {
        r = lift_control_descriptor(
                RUSTD_SPAWN_IDLE_FD,
                RUSTD_SPAWN_LISTEN_FD_BASE + n_listen,
                &idle_fd);
        if (r < 0)
            helper_fail(-r, 125);
    }

    r = attach_self_to_cgroup(request.cgroup_procs_path);
    if (r < 0)
        helper_fail(-r, 125);

    apply_sandbox_mounts(&request);

    r = apply_exec_mac_contexts(&request);
    if (r < 0)
        helper_fail(-r, 125);

    int forced_no_new_privs = 0;
    apply_sandbox_filters(&request, &forced_no_new_privs);

    r = apply_rlimits(request.rlimits, request.header.n_rlimits);
    if (r < 0)
        helper_fail(-r, 125);

    apply_credentials(&request);

    if ((request.header.flags & RUSTD_SPAWN_FLAG_HAS_SANDBOX)
        && request.sandbox.no_new_privs && !forced_no_new_privs) {
        r = rustd_sandbox_no_new_privs();
        if (r < 0)
            helper_fail(-r, 125);
    }

    if (request.cwd && chdir(request.cwd) < 0)
        helper_fail(errno, 126);

    apply_service_environment(&request);

    wait_for_idle_gate(idle_fd);
    establish_controlling_tty(&request);

    if (request.header.flags & RUSTD_SPAWN_FLAG_HAS_SANDBOX) {
        if (request.sandbox.restrict_native_syscalls) {
            r = rustd_seccomp_restrict_native_architecture();
            if (r < 0)
                helper_fail(-r, 125);
        }
        if (request.sandbox.syscall_filter_enabled) {
            r = rustd_seccomp_syscall_rules(
                    request.sandbox.syscall_filter_rules,
                    request.sandbox.n_syscall_filter_rules,
                    request.sandbox.syscall_filter_default_action);
            if (r < 0)
                helper_fail(-r, 125);
        }
    }

    if (strchr(request.path, '/'))
        execv(request.path, (char *const *)request.argv);
    else
        execvp(request.path, (char *const *)request.argv);
    helper_fail(errno, 127);
}
