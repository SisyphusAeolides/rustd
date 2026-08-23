/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* libsystemd.so.0 compatibility shim over librustd_{service,journal,device,login}.so.1 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <rustd/device.h>
#include <rustd/journal.h>
#include <rustd/login.h>
#include <rustd/service.h>

static void free_string_vector(char **values, int count);

typedef struct sd_id128 {
    uint8_t bytes[16];
} sd_id128_t;

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

int sd_pid_notify_with_fds(pid_t pid, int unset_environment, const char *state,
                           const int *fds, unsigned n_fds) {
    int result;
    if (n_fds > 0U && !fds)
        return -EINVAL;
    alias_notify_env();
    result = rustd_notify_send(pid, state, fds, n_fds);
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

int sd_listen_fds_with_names(int unset_environment, char ***names) {
    const char *raw;
    char *copy = NULL;
    char *cursor;
    char **result = NULL;
    int count;
    int index;
    if (!names)
        return -EINVAL;
    *names = NULL;
    alias_listen_env();
    raw = getenv("RUSTD_LISTEN_FDNAMES");
    if (raw && *raw) {
        copy = strdup(raw);
        if (!copy)
            return -ENOMEM;
    }
    count = rustd_listen_fds(0);
    if (count < 0) {
        free(copy);
        return count;
    }
    if (count > 0) {
        result = calloc((size_t)count + 1U, sizeof(*result));
        if (!result) {
            free(copy);
            return -ENOMEM;
        }
    }
    cursor = copy;
    for (index = 0; index < count; index++) {
        char *separator = cursor ? strchr(cursor, ':') : NULL;
        if (separator)
            *separator = '\0';
        result[index] = strdup(cursor && *cursor ? cursor : "unknown");
        if (!result[index]) {
            free_string_vector(result, index);
            free(copy);
            return -ENOMEM;
        }
        cursor = separator ? separator + 1 : NULL;
    }
    free(copy);
    if (unset_environment) {
        (void)rustd_listen_fds(1);
        clear_legacy_listen(1);
    }
    *names = result;
    return count;
}

int sd_is_socket(int fd, int family, int type, int listening) {
    return rustd_is_socket(fd, family, type, listening);
}

int sd_is_fifo(int fd, const char *path) {
    struct stat descriptor;
    struct stat expected;
    if (fd < 0)
        return -EBADF;
    if (fstat(fd, &descriptor) < 0)
        return -errno;
    if (!S_ISFIFO(descriptor.st_mode))
        return 0;
    if (!path)
        return 1;
    if (stat(path, &expected) < 0)
        return errno == ENOENT ? 0 : -errno;
    return descriptor.st_dev == expected.st_dev && descriptor.st_ino == expected.st_ino;
}

int sd_is_mq(int fd, const char *path) {
    struct statfs fs;
    char proc_path[64];
    char target[PATH_MAX];
    ssize_t length;
    if (fd < 0)
        return -EBADF;
    if (fstatfs(fd, &fs) < 0)
        return -errno;
    if ((unsigned long)fs.f_type != 0x19800202UL)
        return 0;
    if (!path)
        return 1;
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    length = readlink(proc_path, target, sizeof(target) - 1U);
    if (length < 0)
        return -errno;
    target[length] = '\0';
    return strcmp(target, path) == 0;
}

static int socket_type_and_listening(int fd, int type, int listening) {
    int value;
    socklen_t size = sizeof(value);
    if (fd < 0)
        return -EBADF;
    if (type > 0) {
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &size) < 0)
            return errno == ENOTSOCK ? 0 : -errno;
        if (value != type)
            return 0;
    }
    if (listening >= 0) {
        size = sizeof(value);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &value, &size) < 0)
            return errno == ENOTSOCK ? 0 : -errno;
        if (!!value != !!listening)
            return 0;
    }
    return 1;
}

int sd_is_socket_sockaddr(int fd, int type, const struct sockaddr *address,
                          size_t length, int listening) {
    struct sockaddr_storage actual;
    socklen_t actual_length = sizeof(actual);
    int result = socket_type_and_listening(fd, type, listening);
    if (result <= 0 || !address || length < sizeof(sa_family_t) ||
        length > sizeof(actual))
        return result <= 0 ? result : -EINVAL;
    if (getsockname(fd, (struct sockaddr *)&actual, &actual_length) < 0)
        return -errno;
    return actual_length == length && memcmp(&actual, address, length) == 0;
}

int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    int result = socket_type_and_listening(fd, type, listening);
    if (result <= 0)
        return result;
    if (getsockname(fd, (struct sockaddr *)&address, &length) < 0)
        return -errno;
    if (address.ss_family != AF_INET && address.ss_family != AF_INET6)
        return 0;
    if (family != 0 && address.ss_family != family)
        return 0;
    if (port != 0) {
        uint16_t actual = address.ss_family == AF_INET
            ? ((struct sockaddr_in *)&address)->sin_port
            : ((struct sockaddr_in6 *)&address)->sin6_port;
        if (actual != htons(port))
            return 0;
    }
    return 1;
}

int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
    struct sockaddr_un address;
    socklen_t address_length = sizeof(address);
    size_t actual_length;
    int result = socket_type_and_listening(fd, type, listening);
    if (result <= 0)
        return result;
    if (getsockname(fd, (struct sockaddr *)&address, &address_length) < 0)
        return -errno;
    if (address.sun_family != AF_UNIX)
        return 0;
    if (!path)
        return 1;
    if (length == 0U)
        length = strlen(path);
    actual_length = address_length > offsetof(struct sockaddr_un, sun_path)
        ? address_length - offsetof(struct sockaddr_un, sun_path) : 0U;
    if (path[0] != '\0' && actual_length > 0U && address.sun_path[actual_length - 1U] == '\0')
        actual_length--;
    return actual_length == length && memcmp(address.sun_path, path, length) == 0;
}

/* --- journal --- */

int sd_journal_sendv(const struct iovec *iov, int n) {
    return rustd_journal_sendv(iov, n);
}

int sd_journal_open(rustd_journal **ret, int flags) {
    (void)flags;
    return rustd_journal_open(ret, NULL);
}

int sd_journal_open_directory(rustd_journal **ret, const char *path, int flags) {
    (void)flags;
    return rustd_journal_open(ret, path);
}

static int fd_path(int fd, char **path) {
    char proc_path[64];
    char target[PATH_MAX];
    ssize_t length;
    if (fd < 0 || !path)
        return -EINVAL;
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    length = readlink(proc_path, target, sizeof(target) - 1U);
    if (length < 0)
        return -errno;
    target[length] = '\0';
    *path = strdup(target);
    return *path ? 0 : -ENOMEM;
}

int sd_journal_open_directory_fd(rustd_journal **ret, int fd, int flags) {
    char *path = NULL;
    struct stat st;
    int result;
    if (fstat(fd, &st) < 0)
        return -errno;
    if (!S_ISDIR(st.st_mode))
        return -ENOTDIR;
    result = fd_path(fd, &path);
    if (result < 0)
        return result;
    result = sd_journal_open_directory(ret, path, flags);
    free(path);
    return result;
}

static int open_entries_paths(rustd_journal **ret, const char **paths, unsigned count,
                              int flags) {
    char *directory = NULL;
    unsigned index;
    int result;
    if (!ret || !paths || count == 0U)
        return -EINVAL;
    for (index = 0U; index < count; index++) {
        char *copy;
        char *slash;
        if (!paths[index]) {
            free(directory);
            return -EINVAL;
        }
        copy = strdup(paths[index]);
        if (!copy) {
            free(directory);
            return -ENOMEM;
        }
        slash = strrchr(copy, '/');
        if (!slash || strcmp(slash + 1U, "entries.log") != 0) {
            free(copy);
            free(directory);
            return -EPROTONOSUPPORT;
        }
        *slash = '\0';
        if (directory && strcmp(directory, copy) != 0) {
            free(copy);
            free(directory);
            return -EXDEV;
        }
        if (!directory)
            directory = copy;
        else
            free(copy);
    }
    result = sd_journal_open_directory(ret, directory, flags);
    free(directory);
    return result;
}

int sd_journal_open_files(rustd_journal **ret, const char **paths, int flags) {
    unsigned count = 0U;
    if (!paths)
        return -EINVAL;
    while (paths[count])
        count++;
    return open_entries_paths(ret, paths, count, flags);
}

int sd_journal_open_files_fd(rustd_journal **ret, int fds[], unsigned n_fds,
                             int flags) {
    const char **paths;
    unsigned index;
    int result;
    if (!fds || n_fds == 0U)
        return -EINVAL;
    paths = calloc(n_fds, sizeof(*paths));
    if (!paths)
        return -ENOMEM;
    for (index = 0U; index < n_fds; index++) {
        char *path = NULL;
        result = fd_path(fds[index], &path);
        if (result < 0)
            goto finish;
        paths[index] = path;
    }
    result = open_entries_paths(ret, paths, n_fds, flags);
finish:
    for (index = 0U; index < n_fds; index++)
        free((void *)paths[index]);
    free(paths);
    return result;
}

int sd_journal_open_namespace(rustd_journal **ret, const char *namespace_name,
                              int flags) {
    char path[PATH_MAX];
    const char *cursor;
    if (!namespace_name || !*namespace_name)
        return sd_journal_open(ret, flags);
    for (cursor = namespace_name; *cursor; cursor++)
        if (!isalnum((unsigned char)*cursor) && *cursor != '_' && *cursor != '-')
            return -EINVAL;
    if (snprintf(path, sizeof(path), "/run/rustd/journal.%s", namespace_name) >=
        (int)sizeof(path))
        return -ENAMETOOLONG;
    return sd_journal_open_directory(ret, path, flags);
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
    return rustd_journal_previous(journal);
}

int sd_journal_previous_skip(rustd_journal *journal, uint64_t skip) {
    return rustd_journal_previous_skip(journal, skip);
}

int sd_journal_next_skip(rustd_journal *journal, uint64_t skip) {
    return rustd_journal_next_skip(journal, skip);
}

int sd_journal_seek_head(rustd_journal *journal) {
    return rustd_journal_seek_head(journal);
}

int sd_journal_seek_cursor(rustd_journal *journal, const char *cursor) {
    return rustd_journal_seek_cursor(journal, cursor);
}

int sd_journal_seek_realtime_usec(rustd_journal *journal, uint64_t usec) {
    return rustd_journal_seek_realtime_usec(journal, usec);
}

int sd_journal_seek_monotonic_usec(rustd_journal *journal, sd_id128_t boot_id,
                                    uint64_t usec) {
    (void)boot_id;
    return rustd_journal_seek_monotonic_usec(journal, usec);
}

int sd_journal_get_data(
    rustd_journal *journal, const char *field, const void **data, size_t *length) {
    return rustd_journal_get_data(journal, field, data, length);
}

int sd_journal_get_realtime_usec(rustd_journal *journal, uint64_t *usec) {
    return rustd_journal_get_realtime_usec(journal, usec);
}

int sd_journal_get_monotonic_usec(rustd_journal *journal, uint64_t *usec,
                                  sd_id128_t *boot_id) {
    return rustd_journal_get_monotonic_usec(
        journal, usec, boot_id ? boot_id->bytes : NULL);
}

int sd_journal_get_cursor(rustd_journal *journal, char **cursor) {
    return rustd_journal_get_cursor(journal, cursor);
}

int sd_journal_test_cursor(rustd_journal *journal, const char *cursor) {
    return rustd_journal_test_cursor(journal, cursor);
}

int sd_journal_get_cutoff_realtime_usec(rustd_journal *journal,
                                        uint64_t *from, uint64_t *to) {
    return rustd_journal_get_cutoff_realtime_usec(journal, from, to);
}

int sd_journal_get_usage(rustd_journal *journal, uint64_t *bytes) {
    return rustd_journal_get_usage(journal, bytes);
}

int sd_journal_add_match(rustd_journal *journal, const void *data, size_t size) {
    return rustd_journal_add_match(journal, data, size);
}

int sd_journal_add_disjunction(rustd_journal *journal) {
    return rustd_journal_add_disjunction(journal);
}

int sd_journal_add_conjunction(rustd_journal *journal) {
    return rustd_journal_add_conjunction(journal);
}

void sd_journal_flush_matches(rustd_journal *journal) {
    rustd_journal_flush_matches(journal);
}

int sd_journal_enumerate_data(rustd_journal *journal, const void **data, size_t *length) {
    return rustd_journal_enumerate_data(journal, data, length);
}

int sd_journal_enumerate_available_data(
    rustd_journal *journal, const void **data, size_t *length) {
    return rustd_journal_enumerate_data(journal, data, length);
}

void sd_journal_restart_data(rustd_journal *journal) {
    rustd_journal_restart_data(journal);
}

int sd_journal_enumerate_fields(rustd_journal *journal, const char **field) {
    return rustd_journal_enumerate_fields(journal, field);
}

void sd_journal_restart_fields(rustd_journal *journal) {
    rustd_journal_restart_fields(journal);
}

int sd_journal_query_unique(rustd_journal *journal, const char *field) {
    return rustd_journal_query_unique(journal, field);
}

int sd_journal_enumerate_unique(rustd_journal *journal,
                                const void **data, size_t *length) {
    return rustd_journal_enumerate_unique(journal, data, length);
}

int sd_journal_enumerate_available_unique(
    rustd_journal *journal, const void **data, size_t *length) {
    return rustd_journal_enumerate_unique(journal, data, length);
}

void sd_journal_restart_unique(rustd_journal *journal) {
    rustd_journal_restart_unique(journal);
}

size_t sd_journal_get_data_threshold(rustd_journal *journal) {
    return rustd_journal_get_data_threshold(journal);
}

int sd_journal_set_data_threshold(rustd_journal *journal, size_t threshold) {
    return rustd_journal_set_data_threshold(journal, threshold);
}

int sd_journal_has_runtime_files(rustd_journal *journal) {
    return rustd_journal_has_runtime_files(journal);
}

int sd_journal_has_persistent_files(rustd_journal *journal) {
    return rustd_journal_has_persistent_files(journal);
}

int sd_journal_get_fd(rustd_journal *journal) {
    return rustd_journal_get_fd(journal);
}

int sd_journal_get_events(rustd_journal *journal) {
    return rustd_journal_get_events(journal);
}

int sd_journal_get_timeout(rustd_journal *journal, uint64_t *timeout) {
    return rustd_journal_get_timeout(journal, timeout);
}

int sd_journal_process(rustd_journal *journal) {
    return rustd_journal_process(journal);
}

int sd_journal_wait(rustd_journal *journal, uint64_t timeout_usec) {
    return rustd_journal_wait(journal, timeout_usec);
}

int sd_journal_reliable_fd(rustd_journal *journal) {
    return rustd_journal_get_fd(journal) >= 0 ? 1 : 0;
}

int sd_journal_get_catalog(rustd_journal *journal, char **text) {
    (void)journal;
    if (!text)
        return -EINVAL;
    *text = NULL;
    return -ENOENT;
}

int sd_journal_get_catalog_for_message_id(sd_id128_t id, char **text) {
    (void)id;
    if (!text)
        return -EINVAL;
    *text = NULL;
    return -ENOENT;
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

static int journal_stream_fd_path(const char *path, const char *identifier,
                                  int priority, int level_prefix) {
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
    if (strlen(path) >= sizeof(address.sun_path))
        return -ENAMETOOLONG;
    strcpy(address.sun_path, path);

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

int sd_journal_stream_fd(const char *identifier, int priority, int level_prefix) {
    return journal_stream_fd_path(
        "/run/rustd/journal/stdout", identifier, priority, level_prefix);
}

int sd_journal_stream_fd_with_namespace(const char *namespace_name,
                                        const char *identifier,
                                        int priority, int level_prefix) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    const char *cursor;
    if (!namespace_name || !*namespace_name)
        return sd_journal_stream_fd(identifier, priority, level_prefix);
    for (cursor = namespace_name; *cursor; cursor++)
        if (!isalnum((unsigned char)*cursor) && *cursor != '_' && *cursor != '-')
            return -EINVAL;
    if (snprintf(path, sizeof(path), "/run/rustd/journal.%s/stdout", namespace_name) >=
        (int)sizeof(path))
        return -ENAMETOOLONG;
    return journal_stream_fd_path(path, identifier, priority, level_prefix);
}

/* --- login --- */

int sd_get_sessions(char ***sessions) {
    return rustd_get_sessions(sessions);
}

static void free_string_vector(char **values, int count) {
    int index;
    for (index = 0; index < count; index++)
        free(values[index]);
    free(values);
}

int sd_get_uids(uid_t **uids) {
    char **sessions = NULL;
    uid_t *result = NULL;
    size_t count = 0U;
    int total;
    int index;
    if (!uids)
        return -EINVAL;
    *uids = NULL;
    total = rustd_get_sessions(&sessions);
    if (total < 0)
        return total;
    for (index = 0; index < total; index++) {
        uid_t uid;
        size_t candidate;
        if (rustd_session_get_uid(sessions[index], &uid) < 0)
            continue;
        for (candidate = 0U; candidate < count && result[candidate] != uid; candidate++) {}
        if (candidate == count) {
            uid_t *resized = realloc(result, (count + 1U) * sizeof(*result));
            if (!resized) {
                free(result);
                free_string_vector(sessions, total);
                return -ENOMEM;
            }
            result = resized;
            result[count++] = uid;
        }
    }
    free_string_vector(sessions, total);
    *uids = result;
    return (int)count;
}

int sd_get_seats(char ***seats) {
    char **sessions = NULL;
    char **result = NULL;
    size_t count = 0U;
    int total;
    int index;
    if (!seats)
        return -EINVAL;
    *seats = NULL;
    total = rustd_get_sessions(&sessions);
    if (total < 0)
        return total;
    for (index = 0; index < total; index++) {
        char *seat = NULL;
        size_t candidate;
        char **resized;
        if (rustd_session_get_seat(sessions[index], &seat) < 0 || !seat)
            continue;
        for (candidate = 0U; candidate < count && strcmp(result[candidate], seat) != 0;
             candidate++) {}
        if (candidate < count) {
            free(seat);
            continue;
        }
        resized = realloc(result, (count + 2U) * sizeof(*result));
        if (!resized) {
            free(seat);
            free_string_vector(result, (int)count);
            free_string_vector(sessions, total);
            return -ENOMEM;
        }
        result = resized;
        result[count++] = seat;
        result[count] = NULL;
    }
    free_string_vector(sessions, total);
    *seats = result;
    return (int)count;
}

int sd_get_machine_names(char ***machines) {
    DIR *directory;
    struct dirent *entry;
    char **result = NULL;
    size_t count = 0U;
    if (!machines)
        return -EINVAL;
    *machines = NULL;
    directory = opendir("/run/rustd/machines");
    if (!directory)
        return errno == ENOENT ? 0 : -errno;
    while ((entry = readdir(directory)) != NULL) {
        char **resized;
        if (entry->d_name[0] == '.')
            continue;
        resized = realloc(result, (count + 2U) * sizeof(*result));
        if (!resized) {
            closedir(directory);
            free_string_vector(result, (int)count);
            return -ENOMEM;
        }
        result = resized;
        result[count] = strdup(entry->d_name);
        if (!result[count]) {
            closedir(directory);
            free_string_vector(result, (int)count);
            return -ENOMEM;
        }
        result[++count] = NULL;
    }
    closedir(directory);
    *machines = result;
    return (int)count;
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
int sd_session_get_service(const char *session, char **service) {
    return rustd_session_get_service(session, service);
}
int sd_session_get_vt(const char *session, unsigned *vtnr) {
    char *tty = NULL;
    char *end = NULL;
    unsigned long value;
    int result;
    if (!vtnr)
        return -EINVAL;
    result = rustd_session_get_tty(session, &tty);
    if (result < 0)
        return result;
    if (strncmp(tty, "tty", 3U) != 0 || !isdigit((unsigned char)tty[3])) {
        free(tty);
        return -ENXIO;
    }
    errno = 0;
    value = strtoul(tty + 3U, &end, 10);
    if (errno || !end || *end || value == 0U || value > UINT_MAX) {
        free(tty);
        return -ENXIO;
    }
    free(tty);
    *vtnr = (unsigned)value;
    return 0;
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

int sd_seat_get_sessions(const char *seat, char ***sessions, uid_t **uids,
                         unsigned *n_uids) {
    char **all = NULL;
    char **matched = NULL;
    uid_t *matched_uids = NULL;
    size_t count = 0U;
    int total;
    int index;
    if (!seat || (!sessions && !uids))
        return -EINVAL;
    if (sessions)
        *sessions = NULL;
    if (uids)
        *uids = NULL;
    if (n_uids)
        *n_uids = 0U;
    total = rustd_get_sessions(&all);
    if (total < 0)
        return total;
    for (index = 0; index < total; index++) {
        char *candidate = NULL;
        uid_t uid;
        char **new_sessions;
        uid_t *new_uids;
        if (rustd_session_get_seat(all[index], &candidate) < 0 ||
            !candidate || strcmp(candidate, seat) != 0) {
            free(candidate);
            continue;
        }
        free(candidate);
        if (rustd_session_get_uid(all[index], &uid) < 0)
            continue;
        new_sessions = realloc(matched, (count + 2U) * sizeof(*matched));
        if (!new_sessions) {
            free_string_vector(matched, (int)count);
            free(matched_uids);
            free_string_vector(all, total);
            return -ENOMEM;
        }
        matched = new_sessions;
        new_uids = realloc(matched_uids, (count + 1U) * sizeof(*matched_uids));
        if (!new_uids) {
            free_string_vector(matched, (int)count);
            free(matched_uids);
            free_string_vector(all, total);
            return -ENOMEM;
        }
        matched_uids = new_uids;
        matched[count] = strdup(all[index]);
        if (!matched[count]) {
            free_string_vector(matched, (int)count);
            free(matched_uids);
            free_string_vector(all, total);
            return -ENOMEM;
        }
        matched[++count] = NULL;
        matched_uids[count - 1U] = uid;
    }
    free_string_vector(all, total);
    if (sessions)
        *sessions = matched;
    else
        free_string_vector(matched, (int)count);
    if (uids)
        *uids = matched_uids;
    else
        free(matched_uids);
    if (n_uids)
        *n_uids = (unsigned)count;
    return (int)count;
}

int sd_seat_get_active(const char *seat, char **session, uid_t *uid) {
    char **sessions = NULL;
    uid_t *uids = NULL;
    unsigned count = 0U;
    unsigned index;
    int result = sd_seat_get_sessions(seat, &sessions, &uids, &count);
    if (result < 0)
        return result;
    for (index = 0U; index < count; index++) {
        if (sd_session_is_active(sessions[index]) > 0) {
            if (session) {
                *session = strdup(sessions[index]);
                if (!*session) {
                    free_string_vector(sessions, (int)count);
                    free(uids);
                    return -ENOMEM;
                }
            }
            if (uid)
                *uid = uids[index];
            free_string_vector(sessions, (int)count);
            free(uids);
            return 0;
        }
    }
    free_string_vector(sessions, (int)count);
    free(uids);
    return -ENXIO;
}

static int seat_has_session_capability(const char *seat, int graphical) {
    char **sessions = NULL;
    unsigned count = 0U;
    unsigned index;
    int result = sd_seat_get_sessions(seat, &sessions, NULL, &count);
    if (result < 0)
        return result;
    result = 0;
    for (index = 0U; index < count; index++) {
        char *value = NULL;
        int got = graphical ? rustd_session_get_type(sessions[index], &value)
                            : rustd_session_get_tty(sessions[index], &value);
        if (got == 0 && value && *value &&
            (!graphical || strcmp(value, "x11") == 0 || strcmp(value, "wayland") == 0))
            result = 1;
        free(value);
        if (result)
            break;
    }
    free_string_vector(sessions, (int)count);
    return result;
}

int sd_seat_can_graphical(const char *seat) {
    return seat_has_session_capability(seat, 1);
}

int sd_seat_can_tty(const char *seat) {
    return seat_has_session_capability(seat, 0);
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
    rustd_device_list_entry *property_cursor;
};

struct sd_event;
static void rustd_event_free(struct sd_event *event);

struct sd_device_monitor {
    unsigned refs;
    rustd_device_ctx *ctx;
    rustd_device_monitor *monitor;
    struct sd_event *event;
    int (*callback)(struct sd_device_monitor *, struct sd_device *, void *);
    void *callback_userdata;
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
    rustd_event_free(monitor->event);
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

struct sd_event_source {
    unsigned refs;
    struct sd_event *event;
    enum { RUSTD_EVENT_TIME, RUSTD_EVENT_IO, RUSTD_EVENT_SIGNAL,
           RUSTD_EVENT_CHILD, RUSTD_EVENT_INOTIFY } kind;
    uint64_t deadline_usec;
    int fd;
    uint32_t events;
    int owns_fd;
    int signal_number;
    pid_t pid;
    int options;
    void *callback;
    void *userdata;
    int enabled;
    int64_t priority;
    struct sd_event_source *next;
};

struct sd_event {
    unsigned refs;
    struct sd_device_monitor *monitor;
    struct sd_event_source *sources;
    int exit_requested;
    int exit_code;
    int is_default;
};

static _Thread_local struct sd_event *rustd_default_event;

static void rustd_event_free(struct sd_event *event) {
    struct sd_event_source *source;
    if (!event) return;
    source = event->sources;
    while (source) {
        struct sd_event_source *next = source->next;
        if (source->owns_fd && source->fd >= 0)
            close(source->fd);
        free(source);
        source = next;
    }
    free(event);
}

static uint64_t rustd_event_monotonic_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000) + (uint64_t)ts.tv_nsec / UINT64_C(1000);
}

int sd_device_monitor_start(struct sd_device_monitor *monitor, void *callback, void *userdata) {
    if (!monitor || !callback) return -EINVAL;
    monitor->callback = (int (*)(struct sd_device_monitor *, struct sd_device *, void *))callback;
    monitor->callback_userdata = userdata;
    return rustd_device_monitor_enable_receiving(monitor->monitor);
}

struct sd_event *sd_device_monitor_get_event(struct sd_device_monitor *monitor) {
    if (!monitor) return NULL;
    if (!monitor->event) {
        monitor->event = calloc(1, sizeof(*monitor->event));
        if (!monitor->event) return NULL;
        monitor->event->refs = 1U;
        monitor->event->monitor = monitor;
    }
    return monitor->event;
}

int sd_event_add_time_relative(struct sd_event *event, void **ret, int clock, uint64_t usec, uint64_t accuracy, void *callback, void *userdata) {
    struct sd_event_source *source; uint64_t now; (void)accuracy;
    if (!event || !callback) return -EINVAL;
    if (clock != CLOCK_MONOTONIC && clock != CLOCK_BOOTTIME) return -EOPNOTSUPP;
    now = rustd_event_monotonic_usec();
    if (UINT64_MAX - now < usec) return -ERANGE;
    source = calloc(1, sizeof(*source)); if (!source) return -ENOMEM;
    source->refs = 1U; source->event = event; source->kind = RUSTD_EVENT_TIME;
    source->fd = -1; source->enabled = 1;
    source->deadline_usec = now + usec;
    source->callback = callback;
    source->userdata = userdata; source->next = event->sources; event->sources = source;
    if (ret)
        *ret = source;
    return 0;
}

int sd_event_exit(struct sd_event *event, int code) { if (!event) return -EINVAL; event->exit_requested = 1; event->exit_code = code; return 0; }

static int rustd_event_dispatch_timers(struct sd_event *event, uint64_t now) {
    struct sd_event_source *source;
    for (source = event->sources; source; source = source->next) {
        int result;
        if (!source->enabled || source->kind != RUSTD_EVENT_TIME ||
            source->deadline_usec > now)
            continue;
        source->enabled = 0;
        result = ((int (*)(struct sd_event_source *, uint64_t, void *))source->callback)(
            source, now, source->userdata);
        if (result < 0)
            return result;
    }
    return 0;
}

int sd_event_loop(struct sd_event *event) {
    if (!event) return -EINVAL;
    while (!event->exit_requested) {
        struct pollfd *pollfds = NULL;
        struct sd_event_source **owners = NULL;
        size_t count = 0U;
        size_t index = 0U;
        uint64_t now = rustd_event_monotonic_usec(); uint64_t nearest = UINT64_MAX;
        struct sd_event_source *source; int timeout = -1; int r;
        for (source = event->sources; source; source = source->next) {
            if (source->enabled && source->kind == RUSTD_EVENT_TIME &&
                source->deadline_usec < nearest)
                nearest = source->deadline_usec;
            if (source->enabled && source->fd >= 0)
                count++;
        }
        if (event->monitor && event->monitor->monitor &&
            rustd_device_monitor_get_fd(event->monitor->monitor) >= 0)
            count++;
        if (nearest != UINT64_MAX) { uint64_t delta = nearest > now ? nearest - now : 0; timeout = delta / 1000U > (uint64_t)INT_MAX ? INT_MAX : (int)((delta + 999U) / 1000U); }
        if (count > 0U) {
            pollfds = calloc(count, sizeof(*pollfds));
            owners = calloc(count, sizeof(*owners));
            if (!pollfds || !owners) { free(pollfds); free(owners); return -ENOMEM; }
        }
        for (source = event->sources; source; source = source->next) {
            if (!source->enabled || source->fd < 0)
                continue;
            pollfds[index].fd = source->fd;
            pollfds[index].events = source->kind == RUSTD_EVENT_IO
                ? (short)source->events : POLLIN;
            owners[index++] = source;
        }
        if (event->monitor && event->monitor->monitor && index < count) {
            pollfds[index].fd = rustd_device_monitor_get_fd(event->monitor->monitor);
            pollfds[index].events = POLLIN;
            owners[index] = NULL;
            index++;
        }
        if (count == 0U && timeout < 0) { free(pollfds); free(owners); return event->exit_code; }
        r = poll(pollfds, count, timeout);
        if (r < 0) { free(pollfds); free(owners); if (errno == EINTR) continue; return -errno; }
        now = rustd_event_monotonic_usec();
        r = rustd_event_dispatch_timers(event, now);
        if (r < 0) { free(pollfds); free(owners); return r; }
        for (index = 0U; index < count; index++) {
            struct sd_event_source *ready = owners[index];
            if (!pollfds[index].revents)
                continue;
            if (!ready) {
                if (event->monitor && event->monitor->callback) {
                    rustd_device *native = rustd_device_monitor_receive_device(event->monitor->monitor);
                    if (native) { struct sd_device *device = calloc(1, sizeof(*device)); if (!device) { rustd_device_unref(native); free(pollfds); free(owners); return -ENOMEM; }
                        device->refs = 1U; device->ctx = rustd_device_ctx_ref(event->monitor->ctx); device->dev = native;
                        r = event->monitor->callback(event->monitor, device, event->monitor->callback_userdata); sd_device_unref(device); if (r < 0) { free(pollfds); free(owners); return r; } }
                }
                continue;
            }
            if (ready->kind == RUSTD_EVENT_IO) {
                r = ((int (*)(struct sd_event_source *, int, uint32_t, void *))ready->callback)(
                    ready, ready->fd, (uint32_t)pollfds[index].revents, ready->userdata);
            } else if (ready->kind == RUSTD_EVENT_SIGNAL) {
                struct signalfd_siginfo info;
                ssize_t got = read(ready->fd, &info, sizeof(info));
                r = got == (ssize_t)sizeof(info)
                    ? ((int (*)(struct sd_event_source *, const struct signalfd_siginfo *, void *))ready->callback)(ready, &info, ready->userdata)
                    : got < 0 ? -errno : -EIO;
            } else if (ready->kind == RUSTD_EVENT_CHILD) {
                siginfo_t info;
                memset(&info, 0, sizeof(info));
                r = waitid(P_PID, (id_t)ready->pid, &info,
                           (ready->options ? ready->options : WEXITED) | WNOHANG | WNOWAIT);
                if (r < 0)
                    r = -errno;
                else if (info.si_pid != 0)
                    r = ((int (*)(struct sd_event_source *, const siginfo_t *, void *))ready->callback)(ready, &info, ready->userdata);
            } else {
                char buffer[4096];
                ssize_t got = read(ready->fd, buffer, sizeof(buffer));
                r = 0;
                if (got < 0)
                    r = -errno;
                else {
                    size_t offset = 0U;
                    while (offset + sizeof(struct inotify_event) <= (size_t)got) {
                        const struct inotify_event *info = (const struct inotify_event *)(buffer + offset);
                        r = ((int (*)(struct sd_event_source *, const struct inotify_event *, void *))ready->callback)(ready, info, ready->userdata);
                        if (r < 0) break;
                        offset += sizeof(*info) + info->len;
                    }
                }
            }
            if (r < 0) { free(pollfds); free(owners); return r; }
        }
        free(pollfds);
        free(owners);
    }
    return event->exit_code;
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
    device->property_cursor = entry;
    if (!entry)
        return NULL;
    if (value)
        *value = rustd_device_list_entry_get_value(entry);
    return rustd_device_list_entry_get_name(entry);
}

const char *sd_device_get_property_next(struct sd_device *device, const char **value) {
    rustd_device_list_entry *entry;

    if (!device || !device->dev || !device->property_cursor)
        return NULL;
    entry = rustd_device_list_entry_get_next(device->property_cursor);
    device->property_cursor = entry;
    if (!entry)
        return NULL;
    if (value)
        *value = rustd_device_list_entry_get_value(entry);
    return rustd_device_list_entry_get_name(entry);
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

int sd_id128_from_string(const char *text, sd_id128_t *ret) {
    char compact[33];
    size_t input_length;
    size_t input = 0U;
    size_t output = 0U;
    size_t index;
    sd_id128_t parsed = {{0}};
    if (!text || !ret)
        return -EINVAL;
    input_length = strlen(text);
    if (input_length != 32U && input_length != 36U)
        return -EINVAL;
    while (input < input_length) {
        if (input_length == 36U &&
            (input == 8U || input == 13U || input == 18U || input == 23U)) {
            if (text[input++] != '-')
                return -EINVAL;
            continue;
        }
        if (!isxdigit((unsigned char)text[input]) || output >= 32U)
            return -EINVAL;
        compact[output++] = text[input++];
    }
    if (output != 32U)
        return -EINVAL;
    compact[32] = '\0';
    for (index = 0U; index < 16U; index++) {
        unsigned high = (unsigned)(isdigit((unsigned char)compact[index * 2U])
            ? compact[index * 2U] - '0'
            : tolower((unsigned char)compact[index * 2U]) - 'a' + 10);
        unsigned low = (unsigned)(isdigit((unsigned char)compact[index * 2U + 1U])
            ? compact[index * 2U + 1U] - '0'
            : tolower((unsigned char)compact[index * 2U + 1U]) - 'a' + 10);
        parsed.bytes[index] = (uint8_t)((high << 4) | low);
    }
    *ret = parsed;
    return 0;
}

int sd_id128_get_boot(sd_id128_t *ret) {
    char text[64];
    FILE *stream;
    int result;
    if (!ret)
        return -EINVAL;
    stream = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!stream)
        return -errno;
    if (!fgets(text, sizeof(text), stream)) {
        result = ferror(stream) ? -EIO : -ENODATA;
        fclose(stream);
        return result;
    }
    fclose(stream);
    text[strcspn(text, "\r\n")] = '\0';
    return sd_id128_from_string(text, ret);
}

int sd_id128_randomize(sd_id128_t *ret) {
    size_t used = 0U;
    if (!ret)
        return -EINVAL;
    while (used < sizeof(ret->bytes)) {
        ssize_t got = getrandom(ret->bytes + used, sizeof(ret->bytes) - used, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        used += (size_t)got;
    }
    return 0;
}

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

int sd_event_default(struct sd_event **ret) {
    if (!ret)
        return -EINVAL;
    if (!rustd_default_event) {
        rustd_default_event = calloc(1, sizeof(*rustd_default_event));
        if (!rustd_default_event)
            return -ENOMEM;
        rustd_default_event->refs = 1U;
        rustd_default_event->is_default = 1;
    } else
        rustd_default_event->refs++;
    *ret = rustd_default_event;
    return 0;
}

static struct sd_event_source *event_source_new(struct sd_event *event, int kind,
                                                 void *callback, void *userdata) {
    struct sd_event_source *source;
    if (!event || !callback)
        return NULL;
    source = calloc(1, sizeof(*source));
    if (!source)
        return NULL;
    source->refs = 1U;
    source->event = event;
    source->kind = kind;
    source->fd = -1;
    source->callback = callback;
    source->userdata = userdata;
    source->enabled = 1;
    source->next = event->sources;
    event->sources = source;
    return source;
}

int sd_event_add_io(
    struct sd_event *event, struct sd_event_source **ret, int fd, uint32_t events, void *callback,
    void *userdata) {
    struct sd_event_source *source;
    if (!event || fd < 0 || events == 0U || !callback)
        return -EINVAL;
    if (fcntl(fd, F_GETFD) < 0)
        return -errno;
    source = event_source_new(event, RUSTD_EVENT_IO, callback, userdata);
    if (!source)
        return -ENOMEM;
    source->fd = fd;
    source->events = events;
    if (ret)
        *ret = source;
    return 0;
}

static int event_signal_exit(
    struct sd_event_source *source,
    const struct signalfd_siginfo *info,
    void *userdata) {
    (void)info;
    return sd_event_exit(source->event, (int)(intptr_t)userdata);
}

int sd_event_add_signal(
    struct sd_event *event, struct sd_event_source **ret, int signal, void *callback,
    void *userdata) {
    struct sd_event_source *source;
    sigset_t mask;
    int fd;
    int result;
    int number = signal & ~(1U << 30);
    if (!event || number <= 0 || number >= NSIG)
        return -EINVAL;
    if (!callback)
        callback = (void *)event_signal_exit;
    sigemptyset(&mask);
    sigaddset(&mask, number);
    result = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (result != 0)
        return -result;
    fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (fd < 0)
        return -errno;
    source = event_source_new(event, RUSTD_EVENT_SIGNAL, callback, userdata);
    if (!source) {
        close(fd);
        return -ENOMEM;
    }
    source->fd = fd;
    source->owns_fd = 1;
    source->signal_number = number;
    if (ret)
        *ret = source;
    return 0;
}

int sd_event_add_child(
    struct sd_event *event, struct sd_event_source **ret, pid_t pid, int options, void *callback,
    void *userdata) {
    struct sd_event_source *source;
    int fd;
    if (!event || !callback || pid <= 0)
        return -EINVAL;
#ifdef SYS_pidfd_open
    fd = (int)syscall(SYS_pidfd_open, pid, 0U);
#else
    errno = EOPNOTSUPP;
    fd = -1;
#endif
    if (fd < 0)
        return -errno;
    source = event_source_new(event, RUSTD_EVENT_CHILD, callback, userdata);
    if (!source) {
        close(fd);
        return -ENOMEM;
    }
    source->fd = fd;
    source->owns_fd = 1;
    source->pid = pid;
    source->options = options;
    if (ret)
        *ret = source;
    return 0;
}

int sd_event_add_inotify(
    struct sd_event *event, struct sd_event_source **ret, const char *path, uint32_t mask,
    void *callback, void *userdata) {
    struct sd_event_source *source;
    int fd;
    if (!event || !path || !callback || mask == 0U)
        return -EINVAL;
    fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (fd < 0)
        return -errno;
    if (inotify_add_watch(fd, path, mask) < 0) {
        int result = -errno;
        close(fd);
        return result;
    }
    source = event_source_new(event, RUSTD_EVENT_INOTIFY, callback, userdata);
    if (!source) {
        close(fd);
        return -ENOMEM;
    }
    source->fd = fd;
    source->owns_fd = 1;
    source->events = mask;
    if (ret)
        *ret = source;
    return 0;
}

struct sd_event *sd_event_source_get_event(struct sd_event_source *source) {
    return source ? source->event : NULL;
}

int sd_event_source_set_priority(struct sd_event_source *source, int64_t priority) {
    if (!source)
        return -EINVAL;
    source->priority = priority;
    return 0;
}

struct sd_event_source *sd_event_source_unref(struct sd_event_source *source) {
    struct sd_event_source **cursor;
    if (!source)
        return NULL;
    if (--source->refs > 0U)
        return NULL;
    if (source->event) {
        cursor = &source->event->sources;
        while (*cursor && *cursor != source)
            cursor = &(*cursor)->next;
        if (*cursor == source)
            *cursor = source->next;
    }
    if (source->owns_fd && source->fd >= 0)
        close(source->fd);
    free(source);
    return NULL;
}

struct sd_event *sd_event_unref(struct sd_event *event) {
    if (!event)
        return NULL;
    if (--event->refs > 0U)
        return NULL;
    if (event->is_default && rustd_default_event == event)
        rustd_default_event = NULL;
    rustd_event_free(event);
    return NULL;
}
