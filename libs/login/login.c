/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rustd/login.h>

#define SESSION_DIR "/run/rustd/sessions"
#define USER_DIR "/run/rustd/users"
#define SEAT_DIR "/run/rustd/seats"

unsigned rustd_login_abi_version(void) {
    return 1U;
}

struct rustd_login_monitor {
    int fd;
    int wd;
};

static char *session_path(const char *session) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", SESSION_DIR, session);
    return strdup(path);
}

static int read_key(const char *path, const char *key, char **out) {
    FILE *stream;
    char line[1024];
    size_t key_len;

    if (!path || !key || !out)
        return -EINVAL;
    *out = NULL;
    stream = fopen(path, "r");
    if (!stream)
        return -errno;
    key_len = strlen(key);
    while (fgets(line, sizeof(line), stream)) {
        size_t length = strlen(line);
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            *out = strdup(line + key_len + 1);
            fclose(stream);
            return *out ? 0 : -ENOMEM;
        }
    }
    fclose(stream);
    return -ENOENT;
}

static int collect_dir_names(const char *directory, char ***names) {
    DIR *dir;
    struct dirent *entry;
    char **result = NULL;
    size_t count = 0;

    if (!names)
        return -EINVAL;
    *names = NULL;
    dir = opendir(directory);
    if (!dir)
        return -errno;
    while ((entry = readdir(dir)) != NULL) {
        char **resized;
        if (entry->d_name[0] == '.')
            continue;
        resized = realloc(result, (count + 2U) * sizeof(char *));
        if (!resized) {
            closedir(dir);
            for (size_t i = 0; i < count; i++)
                free(result[i]);
            free(result);
            return -ENOMEM;
        }
        result = resized;
        result[count] = strdup(entry->d_name);
        if (!result[count]) {
            closedir(dir);
            for (size_t i = 0; i < count; i++)
                free(result[i]);
            free(result);
            return -ENOMEM;
        }
        count++;
        result[count] = NULL;
    }
    closedir(dir);
    *names = result;
    return (int)count;
}

int rustd_get_sessions(char ***sessions) {
    return collect_dir_names(SESSION_DIR, sessions);
}

int rustd_uid_get_sessions(uid_t uid, int require_active, char ***sessions) {
    char **all = NULL;
    char **matched = NULL;
    size_t count = 0;
    int total;
    int index;

    (void)require_active;
    total = rustd_get_sessions(&all);
    if (total < 0)
        return total;
    for (index = 0; index < total; index++) {
        uid_t session_uid = 0;
        if (rustd_session_get_uid(all[index], &session_uid) == 0 && session_uid == uid) {
            char **resized = realloc(matched, (count + 2U) * sizeof(char *));
            if (!resized) {
                for (int i = 0; i < total; i++)
                    free(all[i]);
                free(all);
                for (size_t i = 0; i < count; i++)
                    free(matched[i]);
                free(matched);
                return -ENOMEM;
            }
            matched = resized;
            matched[count++] = strdup(all[index]);
            matched[count] = NULL;
        }
        free(all[index]);
    }
    free(all);
    *sessions = matched;
    return (int)count;
}

int rustd_uid_get_seats(uid_t uid, int require_active, char ***seats) {
    char path[PATH_MAX];
    (void)require_active;
    snprintf(path, sizeof(path), "%s/%u", USER_DIR, uid);
    {
        char *seat = NULL;
        int result = read_key(path, "SEAT", &seat);
        if (result < 0)
            return collect_dir_names(SEAT_DIR, seats) >= 0 ? 0 : result;
        *seats = calloc(2, sizeof(char *));
        if (!*seats) {
            free(seat);
            return -ENOMEM;
        }
        (*seats)[0] = seat;
        return 1;
    }
}

int rustd_uid_get_state(uid_t uid, char **state) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%u", USER_DIR, uid);
    return read_key(path, "STATE", state);
}

int rustd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
    char **seats = NULL;
    int count = rustd_uid_get_seats(uid, require_active, &seats);
    int index;
    int matched = 0;
    if (count < 0)
        return count;
    for (index = 0; index < count; index++) {
        if (seat && seats[index] && strcmp(seats[index], seat) == 0)
            matched = 1;
        free(seats[index]);
    }
    free(seats);
    return matched;
}

int rustd_session_get_uid(const char *session, uid_t *uid) {
    char *path = session_path(session);
    char *value = NULL;
    int result;
    if (!path)
        return -ENOMEM;
    result = read_key(path, "UID", &value);
    free(path);
    if (result < 0)
        return result;
    *uid = (uid_t)strtoul(value, NULL, 10);
    free(value);
    return 0;
}

#define SESSION_STRING_GETTER(name, key) \
int rustd_session_get_##name(const char *session, char **out) { \
    char *path = session_path(session); \
    int result; \
    if (!path) return -ENOMEM; \
    result = read_key(path, key, out); \
    free(path); \
    return result; \
}

SESSION_STRING_GETTER(seat, "SEAT")
SESSION_STRING_GETTER(state, "STATE")
SESSION_STRING_GETTER(type, "TYPE")
SESSION_STRING_GETTER(class, "CLASS")
SESSION_STRING_GETTER(display, "DISPLAY")
SESSION_STRING_GETTER(tty, "TTY")
SESSION_STRING_GETTER(service, "SERVICE")
SESSION_STRING_GETTER(username, "USER")
SESSION_STRING_GETTER(remote_host, "REMOTE_HOST")
SESSION_STRING_GETTER(remote_user, "REMOTE_USER")

int rustd_session_get_leader(const char *session, pid_t *leader) {
    char *path = session_path(session);
    char *value = NULL;
    int result;
    if (!path)
        return -ENOMEM;
    result = read_key(path, "LEADER", &value);
    free(path);
    if (result < 0)
        return result;
    *leader = (pid_t)strtol(value, NULL, 10);
    free(value);
    return 0;
}

int rustd_session_get_start_time(const char *session, uint64_t *usec) {
    char *path = session_path(session);
    char *value = NULL;
    int result;
    if (!path)
        return -ENOMEM;
    result = read_key(path, "REALTIME_USEC", &value);
    free(path);
    if (result < 0)
        return result;
    *usec = strtoull(value, NULL, 10);
    free(value);
    return 0;
}

int rustd_session_is_remote(const char *session) {
    char *value = NULL;
    int result = rustd_session_get_remote_host(session, &value);
    if (result < 0)
        return 0;
    result = value && value[0] ? 1 : 0;
    free(value);
    return result;
}

static int read_cgroup_field(pid_t pid, const char *prefix, char **out) {
    char path[64];
    FILE *stream;
    char line[1024];

    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    stream = fopen(path, "r");
    if (!stream)
        return -errno;
    while (fgets(line, sizeof(line), stream)) {
        char *cursor = strchr(line, ':');
        if (!cursor)
            continue;
        cursor = strchr(cursor + 1, ':');
        if (!cursor)
            continue;
        cursor++;
        {
            size_t length = strlen(cursor);
            while (length > 0 && (cursor[length - 1] == '\n' || cursor[length - 1] == '\r'))
                cursor[--length] = '\0';
        }
        if (prefix) {
            const char *found = strstr(cursor, prefix);
            if (!found)
                continue;
            *out = strdup(found);
        } else {
            *out = strdup(cursor);
        }
        fclose(stream);
        return *out ? 0 : -ENOMEM;
    }
    fclose(stream);
    return -ENOENT;
}

int rustd_pid_get_session(pid_t pid, char **session) {
    char *cgroup = NULL;
    int result = read_cgroup_field(pid, "session-", &cgroup);
    char *end;
    if (result < 0)
        return result;
    end = strchr(cgroup, '.');
    if (end)
        *end = '\0';
    if (strncmp(cgroup, "session-", 8) == 0)
        *session = strdup(cgroup + 8);
    else
        *session = strdup(cgroup);
    free(cgroup);
    return *session ? 0 : -ENOMEM;
}

int rustd_pid_get_owner_uid(pid_t pid, uid_t *uid) {
    char path[64];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (fstatat(AT_FDCWD, path, &st, 0) < 0)
        return -errno;
    *uid = st.st_uid;
    return 0;
}

int rustd_pid_get_unit(pid_t pid, char **unit) {
    return read_cgroup_field(pid, ".service", unit);
}

int rustd_pid_get_user_unit(pid_t pid, char **unit) {
    return rustd_pid_get_unit(pid, unit);
}

int rustd_pid_get_slice(pid_t pid, char **slice) {
    return read_cgroup_field(pid, ".slice", slice);
}

int rustd_pid_get_user_slice(pid_t pid, char **slice) {
    return rustd_pid_get_slice(pid, slice);
}

int rustd_pid_get_cgroup(pid_t pid, char **cgroup) {
    return read_cgroup_field(pid, NULL, cgroup);
}

int rustd_pid_get_machine_name(pid_t pid, char **machine) {
    (void)pid;
    if (machine)
        *machine = NULL;
    return -ENOENT;
}

rustd_login_monitor *rustd_login_monitor_new(const char *category) {
    rustd_login_monitor *monitor;
    const char *path = SESSION_DIR;
    (void)category;
    monitor = calloc(1, sizeof(*monitor));
    if (!monitor)
        return NULL;
    monitor->fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (monitor->fd < 0) {
        free(monitor);
        return NULL;
    }
    if (strcmp(category ? category : "session", "uid") == 0)
        path = USER_DIR;
    else if (strcmp(category ? category : "session", "seat") == 0)
        path = SEAT_DIR;
    monitor->wd = inotify_add_watch(monitor->fd, path, IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_TO);
    if (monitor->wd < 0) {
        close(monitor->fd);
        free(monitor);
        return NULL;
    }
    return monitor;
}

rustd_login_monitor *rustd_login_monitor_unref(rustd_login_monitor *monitor) {
    if (!monitor)
        return NULL;
    if (monitor->fd >= 0)
        close(monitor->fd);
    free(monitor);
    return NULL;
}

int rustd_login_monitor_flush(rustd_login_monitor *monitor) {
    char buffer[4096];
    if (!monitor || monitor->fd < 0)
        return -EINVAL;
    while (read(monitor->fd, buffer, sizeof(buffer)) > 0) {
    }
    return 0;
}

int rustd_login_monitor_get_fd(rustd_login_monitor *monitor) {
    return monitor ? monitor->fd : -EINVAL;
}

int rustd_login_monitor_get_events(rustd_login_monitor *monitor) {
    (void)monitor;
    return POLLIN;
}

int rustd_login_monitor_get_timeout(rustd_login_monitor *monitor, uint64_t *timeout_usec) {
    (void)monitor;
    if (timeout_usec)
        *timeout_usec = (uint64_t)-1;
    return 0;
}
