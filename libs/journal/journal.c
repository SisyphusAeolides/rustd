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

struct rustd_journal_match {
    char *data;
    size_t length;
    size_t field_length;
    unsigned term;
    struct rustd_journal_match *next;
};

struct rustd_journal {
    char *directory;
    char **paths;
    size_t path_count;
    /* Current entry index. SIZE_MAX is before the first entry and
     * path_count is after the last entry. */
    size_t path_index;
    char *entry;
    size_t entry_length;
    struct rustd_journal_match *matches;
    unsigned match_term;
};

static int append_journal_entry(char ***entries, size_t *count, const char *data, size_t length) {
    char **resized;
    char *copy;
    while (length > 0U && data[0] == '\n') {
        data++;
        length--;
    }
    while (length > 0U && data[length - 1U] == '\n')
        length--;
    if (length == 0U)
        return 0;
    copy = malloc(length + 1U);
    if (!copy)
        return -ENOMEM;
    memcpy(copy, data, length);
    copy[length] = '\0';
    resized = realloc(*entries, (*count + 1U) * sizeof(char *));
    if (!resized) {
        free(copy);
        return -ENOMEM;
    }
    *entries = resized;
    (*entries)[(*count)++] = copy;
    return 0;
}

static int collect_journal_files(rustd_journal *journal) {
    char path[512];
    FILE *stream;
    char *raw = NULL;
    char *data = NULL;
    char **entries = NULL;
    size_t count = 0U;
    long file_size;
    size_t raw_size;
    size_t normalized = 0U;
    size_t cursor = 0U;
    int framed;
    int result = 0;

    snprintf(path, sizeof(path), "%s/entries.log",
   journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR);
    stream = fopen(path, "rb");
    if (!stream)
        return -errno;
    if (fseek(stream, 0L, SEEK_END) < 0) {
        result = -errno;
        goto finish;
    }
    file_size = ftell(stream);
    if (file_size < 0) {
        result = -errno;
        goto finish;
    }
    if (fseek(stream, 0L, SEEK_SET) < 0) {
        result = -errno;
        goto finish;
    }
    raw_size = (size_t)file_size;
    raw = malloc(raw_size + 1U);
    data = malloc(raw_size + 1U);
    if (!raw || !data) {
        result = -ENOMEM;
        goto finish;
    }
    if (raw_size > 0U && fread(raw, 1U, raw_size, stream) != raw_size) {
        result = ferror(stream) ? -EIO : -EINVAL;
        goto finish;
    }
    raw[raw_size] = '\0';
    for (size_t i = 0U; i < raw_size; ++i)
        if (raw[i] != '\r')
  data[normalized++] = raw[i];
    data[normalized] = '\0';
    framed = strstr(data, "\n\n") != NULL;

    while (cursor < normalized) {
        size_t next = cursor;
        if (framed) {
  while (next + 1U < normalized && !(data[next] == '\n' && data[next + 1U] == '\n'))
      next++;
  if (next + 1U >= normalized)
      next = normalized;
        } else {
  while (next < normalized && data[next] != '\n')
      next++;
        }
        result = append_journal_entry(&entries, &count, data + cursor, next - cursor);
        if (result < 0)
  goto finish;
        if (framed) {
  cursor = next < normalized ? next + 2U : normalized;
  while (cursor < normalized && data[cursor] == '\n')
      cursor++;
        } else
  cursor = next < normalized ? next + 1U : normalized;
    }

finish:
    fclose(stream);
    free(raw);
    free(data);
    if (result < 0) {
        for (size_t i = 0U; i < count; ++i)
  free(entries[i]);
        free(entries);
        return result;
    }
    journal->paths = entries;
    journal->path_count = count;
    journal->path_index = SIZE_MAX;
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
        journal->path_index = SIZE_MAX;
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
    while (journal->matches) {
        struct rustd_journal_match *next = journal->matches->next;
        free(journal->matches->data);
        free(journal->matches);
        journal->matches = next;
    }
    free(journal);
}

static void clear_current_entry(rustd_journal *journal) {
    free(journal->entry);
    journal->entry = NULL;
    journal->entry_length = 0;
}


static void reset_journal_position(rustd_journal *journal) {
    journal->path_index = SIZE_MAX;
    clear_current_entry(journal);
}

int rustd_journal_add_match(rustd_journal *journal, const void *data, size_t size) {
    const char *bytes = data;
    const char *equals;
    struct rustd_journal_match *match;
    struct rustd_journal_match **tail;
    if (!journal || !data)
        return -EINVAL;
    if (size == 0U)
        size = strlen(bytes);
    if (size < 3U)
        return -EINVAL;
    equals = memchr(bytes, '=', size);
    if (!equals || equals == bytes || equals == bytes + size - 1U)
        return -EINVAL;
    match = calloc(1, sizeof(*match));
    if (!match)
        return -ENOMEM;
    match->data = malloc(size);
    if (!match->data) {
        free(match);
        return -ENOMEM;
    }
    memcpy(match->data, bytes, size);
    match->length = size;
    match->field_length = (size_t)(equals - bytes);
    match->term = journal->match_term;
    tail = &journal->matches;
    while (*tail)
        tail = &(*tail)->next;
    *tail = match;
    reset_journal_position(journal);
    return 0;
}

int rustd_journal_add_disjunction(rustd_journal *journal) {
    struct rustd_journal_match *match;
    int has_current = 0;
    if (!journal)
        return -EINVAL;
    for (match = journal->matches; match; match = match->next)
        if (match->term == journal->match_term) {
  has_current = 1;
  break;
        }
    if (!has_current)
        return -EINVAL;
    if (journal->match_term == UINT_MAX)
        return -ERANGE;
    journal->match_term++;
    reset_journal_position(journal);
    return 0;
}

void rustd_journal_flush_matches(rustd_journal *journal) {
    if (!journal)
        return;
    while (journal->matches) {
        struct rustd_journal_match *next = journal->matches->next;
        free(journal->matches->data);
        free(journal->matches);
        journal->matches = next;
    }
    journal->match_term = 0U;
    reset_journal_position(journal);
}

static int entry_has_exact_match(const char *entry, const struct rustd_journal_match *match) {
    const char *cursor = entry;
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length == match->length && memcmp(cursor, match->data, length) == 0)
  return 1;
        if (!end)
  break;
        cursor = end + 1;
    }
    return 0;
}

static int same_match_field(const struct rustd_journal_match *a,
                  const struct rustd_journal_match *b) {
    return a->field_length == b->field_length &&
 memcmp(a->data, b->data, a->field_length) == 0;
}

static int journal_entry_matches(const rustd_journal *journal, const char *entry) {
    const struct rustd_journal_match *term_match;
    unsigned term;
    if (!journal->matches)
        return 1;
    for (term = 0U; term <= journal->match_term; ++term) {
        int has_term = 0;
        int term_ok = 1;
        for (term_match = journal->matches; term_match; term_match = term_match->next) {
  const struct rustd_journal_match *previous;
  const struct rustd_journal_match *candidate;
  int field_seen = 0;
  int field_ok = 0;
  if (term_match->term != term)
      continue;
  has_term = 1;
  for (previous = journal->matches; previous != term_match; previous = previous->next)
      if (previous->term == term && same_match_field(previous, term_match)) {
          field_seen = 1;
          break;
      }
  if (field_seen)
      continue;
  for (candidate = term_match; candidate; candidate = candidate->next)
      if (candidate->term == term && same_match_field(candidate, term_match) &&
          entry_has_exact_match(entry, candidate)) {
          field_ok = 1;
          break;
      }
  if (!field_ok) {
      term_ok = 0;
      break;
  }
        }
        if (has_term && term_ok)
  return 1;
    }
    return 0;
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
    int result;
    if (!journal)
        return -EINVAL;
    if (journal->path_count == 0U)
        return 0;
    for (;;) {
        if (journal->path_index == SIZE_MAX)
  next_index = 0U;
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
        result = load_entry(journal, next_index);
        if (result < 0)
  return result;
        if (journal_entry_matches(journal, journal->entry))
  return 1;
    }
}

int rustd_journal_previous(rustd_journal *journal) {
    size_t previous_index;
    int result;
    if (!journal)
        return -EINVAL;
    if (journal->path_count == 0U)
        return 0;
    for (;;) {
        if (journal->path_index == SIZE_MAX) {
  clear_current_entry(journal);
  return 0;
        }
        if (journal->path_index >= journal->path_count)
  previous_index = journal->path_count - 1U;
        else if (journal->path_index == 0U) {
  journal->path_index = SIZE_MAX;
  clear_current_entry(journal);
  return 0;
        } else
  previous_index = journal->path_index - 1U;
        result = load_entry(journal, previous_index);
        if (result < 0)
  return result;
        if (journal_entry_matches(journal, journal->entry))
  return 1;
    }
}

int rustd_journal_previous_skip(rustd_journal *journal, uint64_t skip) {
    int moved = 0;

    if (!journal)
        return -EINVAL;
    if (skip > (uint64_t)INT_MAX)
        return -EINVAL;
    while (skip > 0) {
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
