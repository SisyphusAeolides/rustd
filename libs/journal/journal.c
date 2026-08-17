/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <rustd/journal.h>

#define JOURNAL_SOCKET_PATH "/run/rustd/journal/socket"
#define JOURNAL_RUNTIME_DIR "/run/rustd/journal"

unsigned rustd_journal_abi_version(void) {
    return 1U;
}

static int journal_connect(void) {
    struct sockaddr_un address;
    const char *path = getenv("RUSTD_JOURNAL_SOCKET");
    size_t length;
    int fd;

    if (!path || !*path)
        path = JOURNAL_SOCKET_PATH;
    length = strlen(path);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (path[0] == '@') {
        if (length > sizeof(address.sun_path))
            return -ENAMETOOLONG;
        memcpy(address.sun_path + 1, path + 1, length - 1U);
        length = offsetof(struct sockaddr_un, sun_path) + length;
    } else {
        if (length >= sizeof(address.sun_path))
            return -ENAMETOOLONG;
        memcpy(address.sun_path, path, length + 1U);
        length = offsetof(struct sockaddr_un, sun_path) + length + 1U;
    }

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    if (connect(fd, (struct sockaddr *)&address, (socklen_t)length) < 0) {
        int saved = -errno;
        close(fd);
        return saved;
    }
    return fd;
}

int rustd_journal_sendv(const struct iovec *iov, int n) {
    char *payload = NULL;
    size_t capacity = 0;
    size_t used = 0;
    int index;
    int fd;
    ssize_t sent;

    if (!iov || n <= 0)
        return -EINVAL;

    for (index = 0; index < n; index++) {
        const char *field = iov[index].iov_base;
        size_t field_len = iov[index].iov_len;
        size_t key_len = 0;

        if (!field || field_len == 0)
            return -EINVAL;
        while (key_len < field_len && field[key_len] != '=')
            key_len++;
        if (key_len == 0 || key_len >= field_len)
            return -EINVAL;
        if (field[0] == '_')
            return -EPERM;

        if (used + field_len + 1 > capacity) {
            size_t next = capacity ? capacity * 2U : 512U;
            char *resized;
            while (next < used + field_len + 1)
                next *= 2U;
            resized = realloc(payload, next);
            if (!resized) {
                free(payload);
                return -ENOMEM;
            }
            payload = resized;
            capacity = next;
        }
        memcpy(payload + used, field, field_len);
        used += field_len;
        payload[used++] = '\n';
    }

    fd = journal_connect();
    if (fd < 0) {
        free(payload);
        return fd;
    }
    sent = send(fd, payload, used, MSG_NOSIGNAL);
    free(payload);
    close(fd);
    if (sent < 0)
        return -errno;
    return 0;
}

int rustd_journal_print(int priority, const char *format, ...) {
    char message[2048];
    char priority_field[32];
    struct iovec fields[2];
    va_list args;
    int length;

    if (!format)
        return -EINVAL;
    va_start(args, format);
    length = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (length < 0)
        return -EINVAL;
    if ((size_t)length >= sizeof(message))
        length = (int)sizeof(message) - 1;

    {
        char *message_field = NULL;
        size_t message_size = (size_t)length + sizeof("MESSAGE=");
        int result;

        message_field = malloc(message_size);
        if (!message_field)
            return -ENOMEM;
        memcpy(message_field, "MESSAGE=", 8);
        memcpy(message_field + 8, message, (size_t)length);
        snprintf(priority_field, sizeof(priority_field), "PRIORITY=%d", priority);
        fields[0].iov_base = priority_field;
        fields[0].iov_len = strlen(priority_field);
        fields[1].iov_base = message_field;
        fields[1].iov_len = 8U + (size_t)length;
        result = rustd_journal_sendv(fields, 2);
        free(message_field);
        return result;
    }
}

struct rustd_journal {
    char *directory;
    char **paths;
    size_t path_count;
    /* Current entry index. SIZE_MAX is before the first entry and
     * path_count is after the last entry. */
    size_t path_index;
    char *entry;
    size_t entry_length;
};

static int collect_journal_files(rustd_journal *journal) {
    /* Minimal reader: load newline-framed text dumps under the runtime dir.
     * Binary journal file parsing remains daemon-private for now. */
    char path[512];
    FILE *stream;
    char line[4096];
    char **paths = NULL;
    size_t count = 0;

    snprintf(path, sizeof(path), "%s/entries.log",
             journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR);
    stream = fopen(path, "r");
    if (!stream)
        return -errno;

    while (fgets(line, sizeof(line), stream)) {
        size_t length = strlen(line);
        char *copy;
        char **resized;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (length == 0)
            continue;
        copy = strdup(line);
        if (!copy) {
            fclose(stream);
            for (size_t i = 0; i < count; i++)
                free(paths[i]);
            free(paths);
            return -ENOMEM;
        }
        resized = realloc(paths, (count + 1U) * sizeof(char *));
        if (!resized) {
            free(copy);
            fclose(stream);
            for (size_t i = 0; i < count; i++)
                free(paths[i]);
            free(paths);
            return -ENOMEM;
        }
        paths = resized;
        paths[count++] = copy;
    }
    fclose(stream);
    journal->paths = paths;
    journal->path_count = count;
    journal->path_index = count;
    return 0;
}

int rustd_journal_open(rustd_journal **ret, const char *directory) {
    rustd_journal *journal;
    int result;

    if (!ret)
        return -EINVAL;
    journal = calloc(1, sizeof(*journal));
    if (!journal)
        return -ENOMEM;
    if (directory) {
        journal->directory = strdup(directory);
        if (!journal->directory) {
            free(journal);
            return -ENOMEM;
        }
    }
    result = collect_journal_files(journal);
    if (result < 0 && result != -ENOENT) {
        rustd_journal_unref(journal);
        return result;
    }
    if (result == -ENOENT)
        journal->path_index = 0;
    *ret = journal;
    return 0;
}

void rustd_journal_unref(rustd_journal *journal) {
    if (!journal)
        return;
    free(journal->directory);
    for (size_t i = 0; i < journal->path_count; i++)
        free(journal->paths[i]);
    free(journal->paths);
    free(journal->entry);
    free(journal);
}

static void clear_current_entry(rustd_journal *journal) {
    free(journal->entry);
    journal->entry = NULL;
    journal->entry_length = 0;
}

static int load_entry(rustd_journal *journal, size_t index) {
    char *entry;

    if (index >= journal->path_count)
        return -ERANGE;
    entry = strdup(journal->paths[index]);
    if (!entry)
        return -ENOMEM;
    clear_current_entry(journal);
    journal->entry = entry;
    journal->entry_length = strlen(entry);
    journal->path_index = index;
    return 1;
}

int rustd_journal_seek_tail(rustd_journal *journal) {
    if (!journal)
        return -EINVAL;
    journal->path_index = journal->path_count;
    clear_current_entry(journal);
    return 0;
}

int rustd_journal_next(rustd_journal *journal) {
    size_t next_index;

    if (!journal)
        return -EINVAL;
    if (journal->path_count == 0)
        return 0;

    if (journal->path_index == SIZE_MAX)
        next_index = 0;
    else if (journal->path_index >= journal->path_count) {
        clear_current_entry(journal);
        return 0;
    } else {
        next_index = journal->path_index + 1U;
        if (next_index >= journal->path_count) {
            journal->path_index = journal->path_count;
            clear_current_entry(journal);
            return 0;
        }
    }
    return load_entry(journal, next_index);
}

int rustd_journal_previous(rustd_journal *journal) {
    size_t previous_index;

    if (!journal)
        return -EINVAL;
    if (journal->path_count == 0)
        return 0;

    if (journal->path_index == SIZE_MAX) {
        clear_current_entry(journal);
        return 0;
    }
    if (journal->path_index >= journal->path_count)
        previous_index = journal->path_count - 1U;
    else if (journal->path_index == 0) {
        journal->path_index = SIZE_MAX;
        clear_current_entry(journal);
        return 0;
    } else
        previous_index = journal->path_index - 1U;

    return load_entry(journal, previous_index);
}

int rustd_journal_previous_skip(rustd_journal *journal, uint64_t skip) {
    int moved = 0;

    if (!journal)
        return -EINVAL;
    while (skip > 0 && moved < INT_MAX) {
        int result = rustd_journal_previous(journal);
        if (result < 0)
            return result;
        if (result == 0)
            break;
        moved++;
        skip--;
    }
    return moved;
}

int rustd_journal_get_data(rustd_journal *journal, const char *field,
                           const void **data, size_t *length) {
    size_t field_len;
    const char *cursor;

    if (!journal || !field || !data || !length || !journal->entry)
        return -EINVAL;
    field_len = strlen(field);
    cursor = journal->entry;
    while (*cursor) {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len > field_len + 1 &&
            strncmp(cursor, field, field_len) == 0 &&
            cursor[field_len] == '=') {
            *data = cursor + field_len + 1;
            *length = line_len - field_len - 1;
            return 0;
        }
        if (!line_end)
            break;
        cursor = line_end + 1;
    }
    return -ENOENT;
}

int rustd_journal_get_realtime_usec(rustd_journal *journal, uint64_t *usec) {
    const void *data = NULL;
    size_t length = 0;
    int result;

    if (!usec)
        return -EINVAL;
    result = rustd_journal_get_data(journal, "REALTIME_USEC", &data, &length);
    if (result < 0)
        return result;
    {
        char buffer[64];
        char *end = NULL;
        unsigned long long value;
        if (length >= sizeof(buffer))
            return -EINVAL;
        memcpy(buffer, data, length);
        buffer[length] = '\0';
        value = strtoull(buffer, &end, 10);
        if (!end || *end)
            return -EINVAL;
        *usec = (uint64_t)value;
        return 0;
    }
}
