/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* libsystemd.so.0 compatibility shim over librustd_{service,journal,device,login}.so.1 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>

#include <rustd/device.h>
#include <rustd/journal.h>
#include <rustd/login.h>
#include <rustd/service.h>

/* --- env aliasing: systemd names → RustD names when unset --- */

static void alias_notify_env(void) {
    const char *notify = getenv("NOTIFY_SOCKET");
    if (notify && *notify && !getenv("RUSTD_NOTIFY_SOCKET"))
        (void)setenv("RUSTD_NOTIFY_SOCKET", notify, 0);
}

static void alias_listen_env(void) {
    static const struct {
        const char *legacy;
        const char *native;
    } pairs[] = {
        {"LISTEN_PID", "RUSTD_LISTEN_PID"},
        {"LISTEN_PIDFDID", "RUSTD_LISTEN_PIDFDID"},
        {"LISTEN_FDS", "RUSTD_LISTEN_FDS"},
        {"LISTEN_FDNAMES", "RUSTD_LISTEN_FDNAMES"},
        {"WATCHDOG_USEC", "RUSTD_WATCHDOG_USEC"},
        {"WATCHDOG_PID", "RUSTD_WATCHDOG_PID"},
    };
    size_t i;
    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        const char *value = getenv(pairs[i].legacy);
        if (value && *value && !getenv(pairs[i].native))
            (void)setenv(pairs[i].native, value, 0);
    }
}

static void clear_legacy_notify(int unset_environment) {
    if (!unset_environment)
        return;
    (void)unsetenv("NOTIFY_SOCKET");
}

static void clear_legacy_listen(int unset_environment) {
    if (!unset_environment)
        return;
    (void)unsetenv("LISTEN_PID");
    (void)unsetenv("LISTEN_PIDFDID");
    (void)unsetenv("LISTEN_FDS");
    (void)unsetenv("LISTEN_FDNAMES");
}

/* --- boot / notify / listen --- */

int sd_booted(void) {
    struct stat st;
    if (stat("/run/rustd", &st) == 0 && S_ISDIR(st.st_mode))
        return 1;
    if (access("/run/rustd/.exclusive-replacement", F_OK) == 0)
        return 1;
    /* Also treat classic systemd runtime as booted for dual-stack hosts. */
    if (stat("/run/systemd/system", &st) == 0 && S_ISDIR(st.st_mode))
        return 1;
    return 0;
}

int sd_notify(int unset_environment, const char *state) {
    int result;
    alias_notify_env();
    result = rustd_notify_send(0, state, NULL, 0);
    clear_legacy_notify(unset_environment);
    if (unset_environment)
        (void)unsetenv("RUSTD_NOTIFY_SOCKET");
    return result;
}

int sd_pid_notify(pid_t pid, int unset_environment, const char *state) {
    int result;
    alias_notify_env();
    result = rustd_notify_send(pid, state, NULL, 0);
    clear_legacy_notify(unset_environment);
    if (unset_environment)
        (void)unsetenv("RUSTD_NOTIFY_SOCKET");
    return result;
}

int sd_listen_fds(int unset_environment) {
    int result;
    alias_listen_env();
    result = rustd_listen_fds(unset_environment);
    clear_legacy_listen(unset_environment);
    return result;
}

int sd_is_socket(int fd, int family, int type, int listening) {
    return rustd_is_socket(fd, family, type, listening);
}

/* --- journal --- */

int sd_journal_sendv(const struct iovec *iov, int n) {
    return rustd_journal_sendv(iov, n);
}

int sd_journal_send(const char *format, ...) {
    char buffer[2048];
    struct iovec iov;
    va_list ap;
    int n;

    if (!format)
        return -EINVAL;
    va_start(ap, format);
    n = vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= sizeof(buffer))
        return -ENOBUFS;
    iov.iov_base = buffer;
    iov.iov_len = (size_t)n;
    return rustd_journal_sendv(&iov, 1);
}

int sd_journal_send_with_location(
    const char *file, const char *line, const char *func, const char *format, ...) {
    char buffer[2048];
    struct iovec iov;
    va_list ap;
    int n;
    (void)file;
    (void)line;
    (void)func;

    if (!format)
        return -EINVAL;
    va_start(ap, format);
    n = vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= sizeof(buffer))
        return -ENOBUFS;
    iov.iov_base = buffer;
    iov.iov_len = (size_t)n;
    return rustd_journal_sendv(&iov, 1);
}

int sd_journal_print_with_location(
    int priority, const char *file, const char *line, const char *func, const char *format, ...) {
    char message[1600];
    va_list ap;
    int n;
    (void)file;
    (void)line;
    (void)func;

    if (!format)
        return -EINVAL;
    va_start(ap, format);
    n = vsnprintf(message, sizeof(message), format, ap);
    va_end(ap);
    if (n < 0)
        return -EINVAL;
    return rustd_journal_print(priority, "%s", message);
}

int sd_journal_open(rustd_journal **ret, int flags) {
    (void)flags;
    return rustd_journal_open(ret, NULL);
}

int sd_journal_open_directory(rustd_journal **ret, const char *path, int flags) {
    (void)flags;
    return rustd_journal_open(ret, path);
}

void sd_journal_close(rustd_journal *journal) {
    rustd_journal_unref(journal);
}

int sd_journal_seek_tail(rustd_journal *journal) {
    return rustd_journal_seek_tail(journal);
}

int sd_journal_next(rustd_journal *journal) {
    return rustd_journal_next(journal);
}

int sd_journal_previous(rustd_journal *journal) {
    (void)journal;
    return 0;
}

int sd_journal_previous_skip(rustd_journal *journal, uint64_t skip) {
    (void)journal;
    (void)skip;
    return 0;
}

int sd_journal_get_data(
    rustd_journal *journal, const char *field, const void **data, size_t *length) {
    return rustd_journal_get_data(journal, field, data, length);
}

int sd_journal_get_realtime_usec(rustd_journal *journal, uint64_t *usec) {
    return rustd_journal_get_realtime_usec(journal, usec);
}

int sd_journal_add_match(rustd_journal *journal, const void *data, size_t size) {
    (void)journal;
    (void)data;
    (void)size;
    return 0;
}

int sd_journal_add_disjunction(rustd_journal *journal) {
    (void)journal;
    return 0;
}

void sd_journal_flush_matches(rustd_journal *journal) {
    (void)journal;
}

static int write_full(int fd, const void *data, size_t size) {
    const uint8_t *cursor = data;

    while (size > 0U) {
        ssize_t written = write(fd, cursor, size);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (written == 0)
            return -EIO;
        cursor += (size_t)written;
        size -= (size_t)written;
    }
    return 0;
}

int sd_journal_stream_fd(const char *identifier, int priority, int level_prefix) {
    static const char path[] = "/run/rustd/journal/stdout";
    struct sockaddr_un address;
    char header_tail[12];
    int fd;
    int result;
    int send_buffer = 8 * 1024 * 1024;
    size_t identifier_length;

    if (priority < 0 || priority > 7)
        return -EINVAL;
    if (!identifier)
        identifier = "";

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (sizeof(path) > sizeof(address.sun_path))
        return -ENAMETOOLONG;
    memcpy(address.sun_path, path, sizeof(path));

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        result = -errno;
        close(fd);
        return result;
    }
    if (shutdown(fd, SHUT_RD) < 0) {
        result = -errno;
        close(fd);
        return result;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer));

    identifier_length = strlen(identifier);
    result = write_full(fd, identifier, identifier_length);
    if (result < 0) {
        close(fd);
        return result;
    }

    header_tail[0] = '\n';
    header_tail[1] = '\n';
    header_tail[2] = (char)('0' + priority);
    header_tail[3] = '\n';
    header_tail[4] = level_prefix ? '1' : '0';
    header_tail[5] = '\n';
    header_tail[6] = '0';
    header_tail[7] = '\n';
    header_tail[8] = '0';
    header_tail[9] = '\n';
    header_tail[10] = '0';
    header_tail[11] = '\n';
    result = write_full(fd, header_tail, sizeof(header_tail));
    if (result < 0) {
        close(fd);
        return result;
    }
    return fd;
}

/* --- login --- */

int sd_get_sessions(char ***sessions) {
    return rustd_get_sessions(sessions);
}

int sd_uid_get_sessions(uid_t uid, int require_active, char ***sessions) {
    return rustd_uid_get_sessions(uid, require_active, sessions);
}

int sd_uid_get_seats(uid_t uid, int require_active, char ***seats) {
    return rustd_uid_get_seats(uid, require_active, seats);
}

int sd_uid_get_state(uid_t uid, char **state) {
    return rustd_uid_get_state(uid, state);
}

int sd_uid_get_display(uid_t uid, char **display) {
    char **sessions = NULL;
    int n;
    int i;
    int result = -ENXIO;

    if (!display)
        return -EINVAL;
    *display = NULL;
    n = rustd_uid_get_sessions(uid, 1, &sessions);
    if (n < 0)
        return n;
    for (i = 0; i < n; i++) {
        char *disp = NULL;
        if (rustd_session_get_display(sessions[i], &disp) == 0 && disp && *disp) {
            *display = disp;
            result = 0;
            break;
        }
        free(disp);
    }
    for (i = 0; i < n; i++)
        free(sessions[i]);
    free(sessions);
    return result;
}

int sd_uid_get_login_time(uid_t uid, uint64_t *usec) {
    char **sessions = NULL;
    int n;
    int i;
    uint64_t best = 0;
    int found = 0;

    if (!usec)
        return -EINVAL;
    n = rustd_uid_get_sessions(uid, 0, &sessions);
    if (n < 0)
        return n;
    for (i = 0; i < n; i++) {
        uint64_t start = 0;
        if (rustd_session_get_start_time(sessions[i], &start) == 0) {
            if (!found || start < best)
                best = start;
            found = 1;
        }
    }
    for (i = 0; i < n; i++)
        free(sessions[i]);
    free(sessions);
    if (!found)
        return -ENXIO;
    *usec = best;
    return 0;
}

int sd_session_get_uid(const char *session, uid_t *uid) {
    return rustd_session_get_uid(session, uid);
}
int sd_session_get_seat(const char *session, char **seat) {
    return rustd_session_get_seat(session, seat);
}
int sd_session_get_state(const char *session, char **state) {
    return rustd_session_get_state(session, state);
}
int sd_session_get_type(const char *session, char **type) {
    return rustd_session_get_type(session, type);
}
int sd_session_get_class(const char *session, char **class) {
    return rustd_session_get_class(session, class);
}
int sd_session_get_display(const char *session, char **display) {
    return rustd_session_get_display(session, display);
}
int sd_session_get_tty(const char *session, char **tty) {
    return rustd_session_get_tty(session, tty);
}
int sd_session_get_username(const char *session, char **user) {
    return rustd_session_get_username(session, user);
}
int sd_session_get_leader(const char *session, pid_t *leader) {
    return rustd_session_get_leader(session, leader);
}
int sd_session_get_remote_host(const char *session, char **host) {
    return rustd_session_get_remote_host(session, host);
}
int sd_session_get_start_time(const char *session, uint64_t *usec) {
    return rustd_session_get_start_time(session, usec);
}

int sd_session_is_active(const char *session) {
    char *state = NULL;
    int result;

    result = rustd_session_get_state(session, &state);
    if (result < 0)
        return result;
    result = (state && strcmp(state, "active") == 0) ? 1 : 0;
    free(state);
    return result;
}

int sd_pid_get_session(pid_t pid, char **session) {
    return rustd_pid_get_session(pid, session);
}
int sd_pid_get_owner_uid(pid_t pid, uid_t *uid) {
    return rustd_pid_get_owner_uid(pid, uid);
}
int sd_pid_get_unit(pid_t pid, char **unit) {
    return rustd_pid_get_unit(pid, unit);
}
int sd_pid_get_user_unit(pid_t pid, char **unit) {
    return rustd_pid_get_user_unit(pid, unit);
}
int sd_pid_get_slice(pid_t pid, char **slice) {
    return rustd_pid_get_slice(pid, slice);
}
int sd_pid_get_machine_name(pid_t pid, char **machine) {
    return rustd_pid_get_machine_name(pid, machine);
}

static int pidfd_get_target_pid(int pidfd, pid_t *pid) {
    char path[64];
    char line[128];
    FILE *file;
    long value;

    if (pidfd < 0 || !pid)
        return -EBADF;
    if (fcntl(pidfd, F_GETFD) < 0)
        return -errno;
    if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd) >= (int)sizeof(path))
        return -EOVERFLOW;

    file = fopen(path, "re");
    if (!file)
        return -errno;
    while (fgets(line, sizeof(line), file)) {
        char *end = NULL;
        if (strncmp(line, "Pid:", 4) != 0)
            continue;
        errno = 0;
        value = strtol(line + 4, &end, 10);
        if (errno != 0 || end == line + 4) {
            fclose(file);
            return -EIO;
        }
        fclose(file);
        if (value <= 0 || value > INT32_MAX)
            return -ESRCH;
        *pid = (pid_t)value;
        return 0;
    }
    fclose(file);
    return -EBADF;
}

static int pidfd_verify_target_pid(int pidfd, pid_t pid) {
    pid_t current;
    int result = pidfd_get_target_pid(pidfd, &current);
    if (result < 0)
        return result;
    return current == pid ? 0 : -ESRCH;
}

int sd_pidfd_get_session(int pidfd, char **session) {
    char *resolved = NULL;
    pid_t pid;
    int result;

    if (pidfd < 0)
        return -EBADF;
    result = pidfd_get_target_pid(pidfd, &pid);
    if (result < 0)
        return result;
    result = rustd_pid_get_session(pid, &resolved);
    if (result < 0)
        return result;
    result = pidfd_verify_target_pid(pidfd, pid);
    if (result < 0) {
        free(resolved);
        return result;
    }
    if (session)
        *session = resolved;
    else
        free(resolved);
    return 0;
}

int sd_pidfd_get_owner_uid(int pidfd, uid_t *uid) {
    uid_t resolved;
    pid_t pid;
    int result;

    if (pidfd < 0)
        return -EBADF;
    result = pidfd_get_target_pid(pidfd, &pid);
    if (result < 0)
        return result;
    result = rustd_pid_get_owner_uid(pid, &resolved);
    if (result < 0)
        return result;
    result = pidfd_verify_target_pid(pidfd, pid);
    if (result < 0)
        return result;
    if (uid)
        *uid = resolved;
    return 0;
}

int sd_seat_can_multi_session(const char *seat) {
    (void)seat;
    return 1;
}

int sd_login_monitor_new(const char *category, rustd_login_monitor **ret) {
    if (!ret)
        return -EINVAL;
    *ret = rustd_login_monitor_new(category);
    return *ret ? 0 : -ENOMEM;
}
rustd_login_monitor *sd_login_monitor_unref(rustd_login_monitor *monitor) {
    return rustd_login_monitor_unref(monitor);
}
int sd_login_monitor_flush(rustd_login_monitor *monitor) {
    return rustd_login_monitor_flush(monitor);
}
int sd_login_monitor_get_fd(rustd_login_monitor *monitor) {
    return rustd_login_monitor_get_fd(monitor);
}
int sd_login_monitor_get_events(rustd_login_monitor *monitor) {
    return rustd_login_monitor_get_events(monitor);
}

/* --- sd_device (subset; map onto rustd_device where possible) --- */

struct sd_device {
    unsigned refs;
    rustd_device_ctx *ctx;
    rustd_device *dev;
};

struct sd_device_monitor {
    unsigned refs;
    rustd_device_ctx *ctx;
    rustd_device_monitor *monitor;
};

static int sd_device_alloc(struct sd_device **ret) {
    struct sd_device *device;
    if (!ret)
        return -EINVAL;
    device = calloc(1, sizeof(*device));
    if (!device)
        return -ENOMEM;
    device->ctx = rustd_device_ctx_new();
    if (!device->ctx) {
        free(device);
        return -ENOMEM;
    }
    device->refs = 1U;
    *ret = device;
    return 0;
}

struct sd_device *sd_device_ref(struct sd_device *device) {
    if (!device)
        return NULL;
    device->refs++;
    return device;
}

struct sd_device *sd_device_unref(struct sd_device *device) {
    if (!device)
        return NULL;
    if (--device->refs > 0U)
        return NULL;
    rustd_device_unref(device->dev);
    rustd_device_ctx_unref(device->ctx);
    free(device);
    return NULL;
}

int sd_device_new_from_devname(struct sd_device **ret, const char *devname) {
    struct sd_device *device;
    struct stat st;
    int r;

    if (!ret || !devname)
        return -EINVAL;
    r = sd_device_alloc(&device);
    if (r < 0)
        return r;
    if (stat(devname, &st) < 0) {
        r = -errno;
        sd_device_unref(device);
        return r;
    }
    if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode)) {
        sd_device_unref(device);
        return -ENODEV;
    }
    device->dev = rustd_device_new_from_devnum(
        device->ctx, S_ISBLK(st.st_mode) ? 'b' : 'c', st.st_rdev);
    if (!device->dev) {
        sd_device_unref(device);
        return -ENOENT;
    }
    *ret = device;
    return 0;
}

int sd_device_open(struct sd_device *device, int flags) {
    const char *devnode;
    int fd;

    if (!device || !device->dev)
        return -EINVAL;
    devnode = rustd_device_get_devnode(device->dev);
    if (!devnode)
        return -ENOENT;
    fd = open(devnode, flags | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

int sd_device_get_action(struct sd_device *device, int64_t *ret) {
    static const char *const actions[] = {
        "add", "remove", "change", "move", "online", "offline", "bind", "unbind",
    };
    const char *action;
    size_t i;

    if (!device || !device->dev || !ret)
        return -EINVAL;
    action = rustd_device_get_action(device->dev);
    if (!action)
        return -ENODATA;
    for (i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
        if (strcmp(action, actions[i]) == 0) {
            *ret = (int64_t)i;
            return 0;
        }
    }
    return -EINVAL;
}

int sd_device_get_devname(struct sd_device *device, const char **ret) {
    const char *devnode;
    if (!device || !device->dev || !ret)
        return -EINVAL;
    devnode = rustd_device_get_devnode(device->dev);
    if (!devnode)
        return -ENOENT;
    *ret = devnode;
    return 0;
}

int sd_device_get_is_initialized(struct sd_device *device) {
    return device && device->dev ? rustd_device_get_is_initialized(device->dev) : 0;
}

int sd_device_monitor_new(struct sd_device_monitor **ret) {
    struct sd_device_monitor *monitor;
    if (!ret)
        return -EINVAL;
    monitor = calloc(1, sizeof(*monitor));
    if (!monitor)
        return -ENOMEM;
    monitor->ctx = rustd_device_ctx_new();
    if (!monitor->ctx) {
        free(monitor);
        return -ENOMEM;
    }
    monitor->refs = 1U;
    monitor->monitor =
        rustd_device_monitor_new_from_netlink(monitor->ctx, "udev");
    if (!monitor->monitor) {
        rustd_device_ctx_unref(monitor->ctx);
        free(monitor);
        return -ENOMEM;
    }
    *ret = monitor;
    return 0;
}

struct sd_device_monitor *sd_device_monitor_unref(struct sd_device_monitor *monitor) {
    if (!monitor)
        return NULL;
    if (--monitor->refs > 0U)
        return NULL;
    rustd_device_monitor_unref(monitor->monitor);
    rustd_device_ctx_unref(monitor->ctx);
    free(monitor);
    return NULL;
}

int sd_device_monitor_filter_add_match_subsystem_devtype(
    struct sd_device_monitor *monitor, const char *subsystem, const char *devtype) {
    if (!monitor)
        return -EINVAL;
    return rustd_device_monitor_filter_add_match_subsystem_devtype(
        monitor->monitor, subsystem, devtype);
}

int sd_device_monitor_start(struct sd_device_monitor *monitor, void *callback, void *userdata) {
    (void)callback;
    (void)userdata;
    if (!monitor)
        return -EINVAL;
    return rustd_device_monitor_enable_receiving(monitor->monitor);
}

/* sd_event stubs used by a few desktop consumers; fail closed. */
struct sd_event;

struct sd_event *sd_device_monitor_get_event(struct sd_device_monitor *monitor) {
    (void)monitor;
    return NULL;
}

int sd_event_add_time_relative(
    struct sd_event *event, void **ret, int clock, uint64_t usec, uint64_t accuracy,
    void *callback, void *userdata) {
    (void)event;
    (void)ret;
    (void)clock;
    (void)usec;
    (void)accuracy;
    (void)callback;
    (void)userdata;
    return -ENOSYS;
}

int sd_event_exit(struct sd_event *event, int code) {
    (void)event;
    (void)code;
    return -ENOSYS;
}

int sd_event_loop(struct sd_event *event) {
    (void)event;
    return -ENOSYS;
}

int sd_notifyf(int unset_environment, const char *format, ...) {
    char buffer[2048];
    va_list ap;
    int n;

    if (!format)
        return -EINVAL;
    va_start(ap, format);
    n = vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);
    if (n < 0)
        return -EINVAL;
    if ((size_t)n >= sizeof(buffer))
        return -ENOBUFS;
    return sd_notify(unset_environment, buffer);
}

int sd_journal_printv_with_location(
    int priority, const char *file, const char *line, const char *func, const char *format,
    va_list ap) {
    char message[1600];
    int n;
    (void)file;
    (void)line;
    (void)func;
    if (!format)
        return -EINVAL;
    n = vsnprintf(message, sizeof(message), format, ap);
    if (n < 0)
        return -EINVAL;
    return rustd_journal_print(priority, "%s", message);
}

int sd_login_monitor_get_timeout(rustd_login_monitor *monitor, uint64_t *timeout_usec) {
    return rustd_login_monitor_get_timeout(monitor, timeout_usec);
}

int sd_session_is_remote(const char *session) {
    return rustd_session_is_remote(session);
}

int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
    return rustd_uid_is_on_seat(uid, require_active, seat);
}

int sd_pid_get_cgroup(pid_t pid, char **cgroup) {
    return rustd_pid_get_cgroup(pid, cgroup);
}

int sd_pid_get_user_slice(pid_t pid, char **slice) {
    return rustd_pid_get_user_slice(pid, slice);
}

int sd_device_new_from_syspath(struct sd_device **ret, const char *syspath) {
    struct sd_device *device;
    int r;

    if (!ret || !syspath)
        return -EINVAL;
    r = sd_device_alloc(&device);
    if (r < 0)
        return r;
    device->dev = rustd_device_new_from_syspath(device->ctx, syspath);
    if (!device->dev) {
        sd_device_unref(device);
        return -ENOENT;
    }
    *ret = device;
    return 0;
}

const char *sd_device_get_property_first(struct sd_device *device, const char **value) {
    rustd_device_list_entry *entry;
    if (!device || !device->dev)
        return NULL;
    entry = rustd_device_get_properties_list_entry(device->dev);
    if (!entry)
        return NULL;
    if (value)
        *value = rustd_device_list_entry_get_value(entry);
    return rustd_device_list_entry_get_name(entry);
}

const char *sd_device_get_property_next(struct sd_device *device, const char **value) {
    (void)device;
    (void)value;
    return NULL;
}

struct sd_device_enumerator {
    unsigned refs;
    rustd_device_ctx *ctx;
    rustd_device_enumerate *enumerate;
};

int sd_device_enumerator_new(struct sd_device_enumerator **ret) {
    struct sd_device_enumerator *enumerator;
    if (!ret)
        return -EINVAL;
    enumerator = calloc(1, sizeof(*enumerator));
    if (!enumerator)
        return -ENOMEM;
    enumerator->refs = 1U;
    enumerator->ctx = rustd_device_ctx_new();
    if (!enumerator->ctx) {
        free(enumerator);
        return -ENOMEM;
    }
    enumerator->enumerate = rustd_device_enumerate_new(enumerator->ctx);
    if (!enumerator->enumerate) {
        rustd_device_ctx_unref(enumerator->ctx);
        free(enumerator);
        return -ENOMEM;
    }
    *ret = enumerator;
    return 0;
}

struct sd_device_enumerator *sd_device_enumerator_unref(struct sd_device_enumerator *enumerator) {
    if (!enumerator)
        return NULL;
    if (--enumerator->refs > 0U)
        return NULL;
    rustd_device_enumerate_unref(enumerator->enumerate);
    rustd_device_ctx_unref(enumerator->ctx);
    free(enumerator);
    return NULL;
}

int sd_device_enumerator_add_match_property(
    struct sd_device_enumerator *enumerator, const char *property, const char *value) {
    if (!enumerator)
        return -EINVAL;
    return rustd_device_enumerate_add_match_property(enumerator->enumerate, property, value);
}

int sd_device_enumerator_allow_uninitialized(struct sd_device_enumerator *enumerator) {
    (void)enumerator;
    return 0;
}

struct sd_device *sd_device_enumerator_get_device_first(struct sd_device_enumerator *enumerator) {
    rustd_device_list_entry *entry;
    const char *syspath;
    struct sd_device *device = NULL;

    if (!enumerator)
        return NULL;
    if (rustd_device_enumerate_scan_devices(enumerator->enumerate) < 0)
        return NULL;
    entry = rustd_device_enumerate_get_list_entry(enumerator->enumerate);
    if (!entry)
        return NULL;
    syspath = rustd_device_list_entry_get_name(entry);
    if (!syspath || sd_device_new_from_syspath(&device, syspath) < 0)
        return NULL;
    return device;
}

struct sd_hwdb {
    rustd_device_hwdb *hwdb;
};

int sd_hwdb_new(struct sd_hwdb **ret) {
    struct sd_hwdb *hwdb;
    if (!ret)
        return -EINVAL;
    hwdb = calloc(1, sizeof(*hwdb));
    if (!hwdb)
        return -ENOMEM;
    hwdb->hwdb = rustd_device_hwdb_new();
    if (!hwdb->hwdb) {
        free(hwdb);
        return -ENOMEM;
    }
    *ret = hwdb;
    return 0;
}

struct sd_hwdb *sd_hwdb_unref(struct sd_hwdb *hwdb) {
    if (!hwdb)
        return NULL;
    rustd_device_hwdb_unref(hwdb->hwdb);
    free(hwdb);
    return NULL;
}

int sd_hwdb_get(struct sd_hwdb *hwdb, const char *modalias, const char *key, const char **value) {
    rustd_device_list_entry *entry;
    if (!hwdb || !modalias || !key || !value)
        return -EINVAL;
    entry = rustd_device_hwdb_get_properties_list_entry(hwdb->hwdb, modalias);
    while (entry) {
        const char *name = rustd_device_list_entry_get_name(entry);
        if (name && strcmp(name, key) == 0) {
            *value = rustd_device_list_entry_get_value(entry);
            return 0;
        }
        entry = rustd_device_list_entry_get_next(entry);
    }
    return -ENOENT;
}

typedef struct sd_id128 {
    uint8_t bytes[16];
} sd_id128_t;

int sd_id128_get_machine(sd_id128_t *ret) {
    FILE *fp;
    char text[64];
    unsigned values[16];
    size_t i;

    if (!ret)
        return -EINVAL;
    fp = fopen("/etc/machine-id", "r");
    if (!fp)
        return -errno;
    if (!fgets(text, sizeof(text), fp)) {
        int saved = -errno;
        fclose(fp);
        return saved ? saved : -EIO;
    }
    fclose(fp);
    if (sscanf(text,
               "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
               &values[0], &values[1], &values[2], &values[3], &values[4], &values[5],
               &values[6], &values[7], &values[8], &values[9], &values[10], &values[11],
               &values[12], &values[13], &values[14], &values[15]) != 16)
        return -EINVAL;
    for (i = 0; i < 16; i++)
        ret->bytes[i] = (uint8_t)values[i];
    return 0;
}

int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
    sd_id128_t machine;
    size_t i;
    int r = sd_id128_get_machine(&machine);
    if (r < 0)
        return r;
    if (!ret)
        return -EINVAL;
    for (i = 0; i < 16; i++)
        ret->bytes[i] = machine.bytes[i] ^ app_id.bytes[i];
    return 0;
}

char *sd_id128_to_string(sd_id128_t id, char s[33]) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (!s)
        return NULL;
    for (i = 0; i < 16; i++) {
        s[i * 2] = hex[(id.bytes[i] >> 4) & 0xf];
        s[i * 2 + 1] = hex[id.bytes[i] & 0xf];
    }
    s[32] = '\0';
    return s;
}

struct sd_event_source;

int sd_event_default(struct sd_event **ret) {
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_event_add_io(
    struct sd_event *event, struct sd_event_source **ret, int fd, uint32_t events, void *callback,
    void *userdata) {
    (void)event;
    (void)ret;
    (void)fd;
    (void)events;
    (void)callback;
    (void)userdata;
    return -ENOSYS;
}

int sd_event_add_signal(
    struct sd_event *event, struct sd_event_source **ret, int signal, void *callback,
    void *userdata) {
    (void)event;
    (void)ret;
    (void)signal;
    (void)callback;
    (void)userdata;
    return -ENOSYS;
}

int sd_event_add_child(
    struct sd_event *event, struct sd_event_source **ret, pid_t pid, int options, void *callback,
    void *userdata) {
    (void)event;
    (void)ret;
    (void)pid;
    (void)options;
    (void)callback;
    (void)userdata;
    return -ENOSYS;
}

int sd_event_add_inotify(
    struct sd_event *event, struct sd_event_source **ret, const char *path, uint32_t mask,
    void *callback, void *userdata) {
    (void)event;
    (void)ret;
    (void)path;
    (void)mask;
    (void)callback;
    (void)userdata;
    return -ENOSYS;
}

struct sd_event *sd_event_source_get_event(struct sd_event_source *source) {
    (void)source;
    return NULL;
}

int sd_event_source_set_priority(struct sd_event_source *source, int64_t priority) {
    (void)source;
    (void)priority;
    return -ENOSYS;
}

struct sd_event_source *sd_event_source_unref(struct sd_event_source *source) {
    (void)source;
    return NULL;
}

struct sd_event *sd_event_unref(struct sd_event *event) {
    (void)event;
    return NULL;
}
