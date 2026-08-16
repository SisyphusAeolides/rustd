/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * spawn.c — manager side of process spawning.
 *
 * PID 1 runs IPC and D-Bus threads, so it must never fork(): the child would
 * inherit locks held by threads that do not exist in it, and every allocation,
 * setenv(3) or NSS-adjacent call between fork and exec would be undefined.
 *
 * Instead the manager serialises the request into a sealed memfd and
 * posix_spawn()s a fresh RustD image in helper mode with an explicit
 * descriptor mapping.  posix_spawn() only runs async-signal-safe glibc code in
 * the new process, and the helper — a brand new single-threaded image — is the
 * process that applies cgroup, namespace, MAC, rlimit, credential, capability,
 * seccomp and environment setup before exec'ing the service.  The helper never
 * forks either, so the PID returned here is the final service PID and remains
 * a direct child of the manager.
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

#include "sandbox.h"
#include "seccomp.h"
#include "spawn.h"
#include "spawn_helper.h"
#include "spawn_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/*
 * Helper image used for every spawn.  It is installed by the production entry
 * point before the manager creates its first thread and is only read
 * afterwards, so no lock is needed on the spawn path.
 */
static char helper_executable[PATH_MAX];
static int helper_executable_ready;

int rustd_spawn_helper_configure(const char *executable_path) {
    if (!executable_path || executable_path[0] != '/')
        return -EINVAL;

    size_t length = strnlen(executable_path, sizeof(helper_executable));
    if (length >= sizeof(helper_executable))
        return -ENAMETOOLONG;
    if (access(executable_path, X_OK) < 0)
        return -errno;

    memcpy(helper_executable, executable_path, length + 1);
    helper_executable_ready = 1;
    return 0;
}

int rustd_spawn_helper_configured(void) {
    return helper_executable_ready;
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

static int bounded_length(const char *value, size_t *ret_length) {
    size_t length = strnlen(value, RUSTD_SPAWN_MAX_STRING_BYTES + 1);
    if (length > RUSTD_SPAWN_MAX_STRING_BYTES)
        return -E2BIG;
    *ret_length = length;
    return 0;
}

static int count_vector(const char *const *vector, size_t limit, size_t *ret_count) {
    size_t count = 0;
    while (vector[count]) {
        size_t ignored;
        int r = bounded_length(vector[count], &ignored);
        if (r < 0)
            return r;
        count++;
        if (count > limit)
            return -E2BIG;
    }
    *ret_count = count;
    return 0;
}

/*
 * Reject anything the helper would have to guess about.  Everything the child
 * used to discover after fork() is decided here, while errors can still be
 * reported to the caller directly.
 */
static int validate_params(const rustd_spawn_params *p, size_t *ret_argv, size_t *ret_env) {
    if (!p || !p->path || p->path[0] == '\0' || !p->argv || !p->argv[0])
        return -EINVAL;

    size_t ignored;
    int r = bounded_length(p->path, &ignored);
    if (r < 0)
        return r;
    r = count_vector(p->argv, RUSTD_SPAWN_MAX_ARGV, ret_argv);
    if (r < 0)
        return r;

    *ret_env = 0;
    if (p->envp) {
        r = count_vector(p->envp, RUSTD_SPAWN_MAX_ENV, ret_env);
        if (r < 0)
            return r;
        for (size_t i = 0; i < *ret_env; i++) {
            const char *separator = strchr(p->envp[i], '=');
            if (!separator || separator == p->envp[i])
                return -EINVAL;
        }
    }

    if (p->cwd) {
        r = bounded_length(p->cwd, &ignored);
        if (r < 0)
            return r;
    }
    if (p->cgroup_procs_path) {
        r = bounded_length(p->cgroup_procs_path, &ignored);
        if (r < 0)
            return r;
    }
    if (p->selinux_context) {
        r = bounded_length(p->selinux_context, &ignored);
        if (r < 0)
            return r;
    }
    if (p->apparmor_profile) {
        r = bounded_length(p->apparmor_profile, &ignored);
        if (r < 0)
            return r;
    }

    if (p->n_rlimits > RUSTD_SPAWN_MAX_RLIMITS)
        return -E2BIG;
    if (p->n_rlimits > 0 && !p->rlimits)
        return -EINVAL;

    if (p->n_listen_fds < 0)
        return -EINVAL;
    if (p->n_listen_fds > RUSTD_SPAWN_MAX_LISTEN_FDS)
        return -E2BIG;
    if (p->n_listen_fds > 0 && !p->listen_fds)
        return -EINVAL;
    if (p->n_listen_fds > 0) {
        for (int i = 0; i < p->n_listen_fds; i++) {
            if (p->listen_fds[i] < 0)
                return -EBADF;
        }
    }

    if (p->stdin_fd < -1 || p->stdout_fd < -1 || p->stderr_fd < -1 || p->notify_fd < -1)
        return -EBADF;

    if ((p->idle_read_fd >= 0) != (p->idle_write_fd >= 0))
        return -EINVAL;

    if (p->sandbox) {
        const rustd_spawn_sandbox *sandbox = p->sandbox;
        if (sandbox->n_syscall_filter_rules > RUSTD_SPAWN_MAX_SECCOMP_RULES)
            return -E2BIG;
        if (sandbox->n_syscall_filter_rules > 0 && !sandbox->syscall_filter_rules)
            return -EINVAL;
    }

    return 0;
}

static void write_string(rustd_spawn_writer *writer, const char *value) {
    rustd_spawn_write_string(writer, value, strlen(value));
}

/*
 * Serialise the request.  With writer->data == NULL this only measures, so the
 * buffer is sized by exactly the code that fills it.
 */
static void write_request(
        const rustd_spawn_params *p,
        const char *notify_socket,
        size_t n_argv,
        size_t n_env,
        size_t total_bytes,
        rustd_spawn_writer *writer) {
    const rustd_spawn_sandbox *sandbox = p->sandbox;
    int n_listen = (p->listen_fds && p->n_listen_fds > 0) ? p->n_listen_fds : 0;

    uint32_t flags = 0;
    if (p->wait_for_exec)
        flags |= RUSTD_SPAWN_FLAG_WAIT_FOR_EXEC;
    if (p->envp)
        flags |= RUSTD_SPAWN_FLAG_HAS_ENVIRONMENT;
    if (sandbox)
        flags |= RUSTD_SPAWN_FLAG_HAS_SANDBOX;
    if (p->idle_read_fd >= 0)
        flags |= RUSTD_SPAWN_FLAG_HAS_IDLE_GATE;
    if (p->cwd && p->cwd[0] != '\0')
        flags |= RUSTD_SPAWN_FLAG_HAS_CWD;
    if (p->cgroup_procs_path && p->cgroup_procs_path[0] != '\0')
        flags |= RUSTD_SPAWN_FLAG_HAS_CGROUP;
    if (p->selinux_context)
        flags |= RUSTD_SPAWN_FLAG_HAS_SELINUX;
    if (p->apparmor_profile)
        flags |= RUSTD_SPAWN_FLAG_HAS_APPARMOR;
    if (p->selinux_context_ignore)
        flags |= RUSTD_SPAWN_FLAG_SELINUX_IGNORE;
    if (p->apparmor_profile_ignore)
        flags |= RUSTD_SPAWN_FLAG_APPARMOR_IGNORE;
    if (notify_socket)
        flags |= RUSTD_SPAWN_FLAG_HAS_NOTIFY_SOCKET;

    rustd_spawn_wire_header header;
    memset(&header, 0, sizeof(header));
    header.magic = RUSTD_SPAWN_WIRE_MAGIC;
    header.version = RUSTD_SPAWN_WIRE_VERSION;
    header.header_bytes = (uint32_t)sizeof(header);
    header.total_bytes = (uint32_t)total_bytes;
    header.flags = flags;
    header.n_argv = (uint32_t)n_argv;
    header.n_env = (uint32_t)n_env;
    header.n_rlimits = (uint32_t)p->n_rlimits;
    header.n_listen_fds = (uint32_t)n_listen;
    header.uid = (uint32_t)p->uid;
    header.gid = (uint32_t)p->gid;
    header.cap_bounding_set = p->cap_bounding_set;
    header.ambient_caps = p->ambient_caps;
    header.watchdog_usec = p->watchdog_usec;

    if (sandbox) {
        header.n_seccomp_rules = (uint32_t)sandbox->n_syscall_filter_rules;
        header.seccomp_default_action = sandbox->syscall_filter_default_action;
        header.no_new_privs = (uint32_t)sandbox->no_new_privs;
        header.private_tmp = (uint32_t)sandbox->private_tmp;
        header.private_devices = (uint32_t)sandbox->private_devices;
        header.private_network = (uint32_t)sandbox->private_network;
        header.private_mounts = (uint32_t)sandbox->private_mounts;
        header.protect_system = (uint32_t)sandbox->protect_system;
        header.protect_home = (uint32_t)sandbox->protect_home;
        header.protect_kernel_tunables = (uint32_t)sandbox->protect_kernel_tunables;
        header.protect_kernel_modules = (uint32_t)sandbox->protect_kernel_modules;
        header.protect_kernel_logs = (uint32_t)sandbox->protect_kernel_logs;
        header.protect_clock = (uint32_t)sandbox->protect_clock;
        header.protect_control_groups = (uint32_t)sandbox->protect_control_groups;
        header.restrict_suid_sgid = (uint32_t)sandbox->restrict_suid_sgid;
        header.restrict_realtime = (uint32_t)sandbox->restrict_realtime;
        header.restrict_namespaces = (uint32_t)sandbox->restrict_namespaces;
        header.memory_deny_write_execute = (uint32_t)sandbox->memory_deny_write_execute;
        header.syscall_filter_enabled = (uint32_t)sandbox->syscall_filter_enabled;
        header.restrict_native_syscalls = (uint32_t)sandbox->restrict_native_syscalls;
    }

    rustd_spawn_write_bytes(writer, &header, sizeof(header));

    write_string(writer, p->path);
    for (uint32_t i = 0; i < header.n_argv; i++)
        write_string(writer, p->argv[i]);
    for (uint32_t i = 0; i < header.n_env; i++)
        write_string(writer, p->envp[i]);
    if (flags & RUSTD_SPAWN_FLAG_HAS_CWD)
        write_string(writer, p->cwd);
    if (flags & RUSTD_SPAWN_FLAG_HAS_CGROUP)
        write_string(writer, p->cgroup_procs_path);
    if (flags & RUSTD_SPAWN_FLAG_HAS_SELINUX)
        write_string(writer, p->selinux_context);
    if (flags & RUSTD_SPAWN_FLAG_HAS_APPARMOR)
        write_string(writer, p->apparmor_profile);
    if (flags & RUSTD_SPAWN_FLAG_HAS_NOTIFY_SOCKET)
        write_string(writer, notify_socket);

    for (uint32_t i = 0; i < header.n_rlimits; i++) {
        rustd_spawn_write_u32(writer, (uint32_t)p->rlimits[i].resource);
        rustd_spawn_write_u64(writer, p->rlimits[i].soft);
        rustd_spawn_write_u64(writer, p->rlimits[i].hard);
    }

    for (uint32_t i = 0; i < header.n_seccomp_rules; i++) {
        rustd_spawn_write_u32(writer, (uint32_t)sandbox->syscall_filter_rules[i].nr);
        rustd_spawn_write_u32(writer, sandbox->syscall_filter_rules[i].action);
    }
}

/* Publish the request through a sealed memfd so the helper cannot be fed a
 * growing or mutating buffer, and so nothing else can rewrite it in flight. */
static int create_request_memfd(const unsigned char *data, size_t length) {
    int fd = memfd_create("rustd-spawn-request", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0)
        return -errno;

    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int error = errno;
            close(fd);
            return -error;
        }
        if (written == 0) {
            close(fd);
            return -EIO;
        }
        offset += (size_t)written;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0) {
        int error = errno;
        close(fd);
        return -error;
    }
    return fd;
}

/*
 * Descriptors handed to posix_spawn() must not collide with the descriptor
 * numbers the child mapping writes to, otherwise a later dup2 action could
 * overwrite an earlier action's source.  Sources are therefore lifted above
 * the whole target range first, always with F_DUPFD_CLOEXEC so no window
 * exists where a concurrently spawning thread could leak them.
 */
typedef struct {
    int fds[RUSTD_SPAWN_MAX_LISTEN_FDS + 8];
    int count;
} rustd_spawn_fd_scratch;

static int scratch_lift(rustd_spawn_fd_scratch *scratch, int fd, int minimum, int *ret_fd) {
    if (fd >= minimum) {
        *ret_fd = fd;
        return 0;
    }
    if (scratch->count >= (int)(sizeof(scratch->fds) / sizeof(scratch->fds[0])))
        return -EMFILE;

    int moved = fcntl(fd, F_DUPFD_CLOEXEC, minimum);
    if (moved < 0)
        return -errno;
    scratch->fds[scratch->count++] = moved;
    *ret_fd = moved;
    return 0;
}

static void scratch_release(rustd_spawn_fd_scratch *scratch) {
    for (int i = 0; i < scratch->count; i++)
        close(scratch->fds[i]);
    scratch->count = 0;
}

static int add_mapping(
        posix_spawn_file_actions_t *actions,
        rustd_spawn_fd_scratch *scratch,
        int source,
        int target,
        int minimum) {
    int lifted = -1;
    int r = scratch_lift(scratch, source, minimum, &lifted);
    if (r < 0)
        return r;
    return -posix_spawn_file_actions_adddup2(actions, lifted, target);
}

static int spawn_helper_image(
        const rustd_spawn_params *p,
        int n_listen,
        int request_fd,
        int error_fd,
        pid_t *ret_pid) {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    rustd_spawn_fd_scratch scratch = { .count = 0 };
    int minimum = RUSTD_SPAWN_LISTEN_FD_BASE + n_listen;

    int r = posix_spawn_file_actions_init(&actions);
    if (r != 0)
        return -r;
    r = posix_spawnattr_init(&attributes);
    if (r != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return -r;
    }

    sigset_t all_signals;
    sigset_t no_signals;
    sigfillset(&all_signals);
    sigemptyset(&no_signals);
    r = -posix_spawnattr_setsigdefault(&attributes, &all_signals);
    if (r == 0)
        r = -posix_spawnattr_setsigmask(&attributes, &no_signals);
    if (r == 0)
        r = -posix_spawnattr_setflags(
                &attributes,
                POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);

    if (r == 0) {
        if (p->stdin_fd < 0)
            r = -posix_spawn_file_actions_addopen(
                    &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
        else
            r = add_mapping(&actions, &scratch, p->stdin_fd, STDIN_FILENO, minimum);
    }
    if (r == 0 && p->stdout_fd >= 0)
        r = add_mapping(&actions, &scratch, p->stdout_fd, STDOUT_FILENO, minimum);
    if (r == 0 && p->stderr_fd >= 0)
        r = add_mapping(&actions, &scratch, p->stderr_fd, STDERR_FILENO, minimum);
    if (r == 0)
        r = add_mapping(&actions, &scratch, request_fd, RUSTD_SPAWN_REQUEST_FD, minimum);
    if (r == 0)
        r = add_mapping(&actions, &scratch, error_fd, RUSTD_SPAWN_ERROR_FD, minimum);
    if (r == 0 && p->idle_read_fd >= 0)
        r = add_mapping(&actions, &scratch, p->idle_read_fd, RUSTD_SPAWN_IDLE_FD, minimum);
    for (int i = 0; r == 0 && i < n_listen; i++)
        r = add_mapping(
                &actions,
                &scratch,
                p->listen_fds[i],
                RUSTD_SPAWN_LISTEN_FD_BASE + i,
                minimum);

    if (r == 0) {
        char *const helper_argv[] = {
            helper_executable,
            (char *)RUSTD_SPAWN_HELPER_ARGUMENT,
            NULL,
        };
        pid_t pid = -1;
        int error = posix_spawn(
                &pid, helper_executable, &actions, &attributes, helper_argv, environ);
        if (error != 0)
            r = -error;
        else
            *ret_pid = pid;
    }

    scratch_release(&scratch);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    return r;
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

pid_t rustd_spawn(const rustd_spawn_params *p) {
    size_t n_argv = 0;
    size_t n_env = 0;
    int r = validate_params(p, &n_argv, &n_env);
    if (r < 0)
        return (pid_t)r;
    if (!helper_executable_ready)
        return -ENOSYS;

    /* Resolved here so the helper never has to read the manager environment. */
    const char *notify_socket = NULL;
    if (p->notify_fd >= 0) {
        notify_socket = getenv("RUSTD_NOTIFY_SOCKET");
        if (!notify_socket || notify_socket[0] == '\0')
            notify_socket = "@rustd/notify";
    }

    rustd_spawn_writer measure = { .data = NULL, .capacity = 0, .offset = 0, .failed = 0 };
    write_request(p, notify_socket, n_argv, n_env, 0, &measure);
    if (measure.failed)
        return -EINVAL;
    if (measure.offset > RUSTD_SPAWN_MAX_REQUEST_BYTES)
        return -E2BIG;

    size_t total_bytes = measure.offset;
    unsigned char *buffer = malloc(total_bytes);
    if (!buffer)
        return -ENOMEM;

    rustd_spawn_writer fill = {
        .data = buffer,
        .capacity = total_bytes,
        .offset = 0,
        .failed = 0,
    };
    write_request(p, notify_socket, n_argv, n_env, total_bytes, &fill);
    if (fill.failed || fill.offset != total_bytes) {
        free(buffer);
        return -EINVAL;
    }

    int request_fd = create_request_memfd(buffer, total_bytes);
    free(buffer);
    if (request_fd < 0)
        return (pid_t)request_fd;

    /*
     * A socket pair rather than a pipe: the helper reports setup failures with
     * MSG_NOSIGNAL, so a caller that did not ask for the exec handshake can
     * drop its end without ever signalling the child.
     */
    int error_socket[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, error_socket) < 0) {
        int error = errno;
        close(request_fd);
        return -error;
    }

    int n_listen = (p->listen_fds && p->n_listen_fds > 0) ? p->n_listen_fds : 0;
    pid_t pid = -1;
    r = spawn_helper_image(p, n_listen, request_fd, error_socket[1], &pid);

    close(request_fd);
    close(error_socket[1]);
    if (r < 0) {
        close(error_socket[0]);
        return (pid_t)r;
    }

    if (!p->wait_for_exec) {
        close(error_socket[0]);
        return pid;
    }
    return wait_for_exec_result(pid, error_socket[0]);
}

/*
 * Helper mode entry.  The manager execs this same image with a private
 * argument; running from an ELF constructor keeps the mode out of every
 * command-line surface and guarantees no manager state is touched before the
 * request is applied.  rustd_spawn_helper_main() never returns.
 *
 * argv is recovered from /proc/self/cmdline rather than from a
 * three-argument constructor so the entry stays portable under -Wpedantic.
 */
__attribute__((constructor)) static void rustd_spawn_helper_entry(void) {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;

    char buffer[PATH_MAX + sizeof(RUSTD_SPAWN_HELPER_ARGUMENT) + 8];
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0)
        return;
    buffer[length] = '\0';

    /* cmdline stores argv entries as consecutive NUL-terminated strings. */
    const char *argument = memchr(buffer, '\0', (size_t)length);
    if (!argument || argument + 1 >= buffer + length)
        return;
    argument++;
    if (strcmp(argument, RUSTD_SPAWN_HELPER_ARGUMENT) != 0)
        return;
    rustd_spawn_helper_main();
}
