/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <poll.h>
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
    int conjunction_all_terms;
    size_t data_threshold;
    size_t data_offset;
    char **field_names;
    size_t field_count;
    size_t field_index;
    char *unique_field;
    char **unique_values;
    size_t unique_count;
    size_t unique_index;
    int notify_fd;
    int notify_watch;
};

static void free_string_array(char **values, size_t count) {
    size_t index;
    for (index = 0U; index < count; index++)
        free(values[index]);
    free(values);
}

static void clear_enumerators(rustd_journal *journal) {
    journal->data_offset = 0U;
    free_string_array(journal->field_names, journal->field_count);
    journal->field_names = NULL;
    journal->field_count = 0U;
    journal->field_index = 0U;
    free(journal->unique_field);
    journal->unique_field = NULL;
    free_string_array(journal->unique_values, journal->unique_count);
    journal->unique_values = NULL;
    journal->unique_count = 0U;
    journal->unique_index = 0U;
}

static void clear_entries(rustd_journal *journal) {
    free_string_array(journal->paths, journal->path_count);
    journal->paths = NULL;
    journal->path_count = 0U;
}

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
    journal->data_threshold = 64U * 1024U;
    journal->notify_fd = -1;
    journal->notify_watch = -1;
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
    journal->notify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (journal->notify_fd >= 0) {
        journal->notify_watch = inotify_add_watch(
            journal->notify_fd,
            journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR,
            IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
        if (journal->notify_watch < 0) {
            close(journal->notify_fd);
            journal->notify_fd = -1;
        }
    }
    *ret = journal;
    return 0;
}

void rustd_journal_unref(rustd_journal *journal) {
    if (!journal)
        return;
    free(journal->directory);
    clear_entries(journal);
    free(journal->entry);
    clear_enumerators(journal);
    if (journal->notify_fd >= 0)
        close(journal->notify_fd);
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
    journal->data_offset = 0U;
}


static void reset_journal_position(rustd_journal *journal) {
    journal->path_index = SIZE_MAX;
    clear_current_entry(journal);
}

static int append_match(rustd_journal *journal, const void *data, size_t size,
                        unsigned term) {
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
    match->term = term;
    tail = &journal->matches;
    while (*tail)
        tail = &(*tail)->next;
    *tail = match;
    return 0;
}

int rustd_journal_add_match(rustd_journal *journal, const void *data, size_t size) {
    unsigned term;
    int result;
    if (!journal)
        return -EINVAL;
    if (size == 0U && data)
        size = strlen(data);
    if (journal->conjunction_all_terms) {
        for (term = 0U; term <= journal->match_term; term++) {
            result = append_match(journal, data, size, term);
            if (result < 0)
                return result;
        }
    } else {
        result = append_match(journal, data, size, journal->match_term);
        if (result < 0)
            return result;
    }
    reset_journal_position(journal);
    return 0;
}

int rustd_journal_add_conjunction(rustd_journal *journal) {
    if (!journal || !journal->matches)
        return -EINVAL;
    journal->conjunction_all_terms = 1;
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
    journal->conjunction_all_terms = 0;
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
    journal->conjunction_all_terms = 0;
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
            *data = cursor;
            *length = line_len > journal->data_threshold
                ? journal->data_threshold : line_len;
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
    {
        size_t threshold;
        if (!journal)
            return -EINVAL;
        threshold = journal->data_threshold;
        journal->data_threshold = SIZE_MAX;
        result = rustd_journal_get_data(journal, "REALTIME_USEC", &data, &length);
        journal->data_threshold = threshold;
    }
    if (result < 0)
        return result;
    {
        char buffer[64];
        char *end = NULL;
        unsigned long long value;
        const char *equals = memchr(data, '=', length);
        if (!equals)
            return -EINVAL;
        length -= (size_t)(equals + 1 - (const char *)data);
        data = equals + 1;
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

int rustd_journal_seek_head(rustd_journal *journal) {
    if (!journal)
        return -EINVAL;
    reset_journal_position(journal);
    return 0;
}

int rustd_journal_next_skip(rustd_journal *journal, uint64_t skip) {
    int moved = 0;
    if (!journal || skip > (uint64_t)INT_MAX)
        return -EINVAL;
    while (skip-- > 0U) {
        int result = rustd_journal_next(journal);
        if (result <= 0)
            return result < 0 ? result : moved;
        moved++;
    }
    return moved;
}

int rustd_journal_get_cursor(rustd_journal *journal, char **cursor) {
    uint64_t realtime = 0U;
    if (!journal || !cursor || !journal->entry || journal->path_index >= journal->path_count)
        return -EINVAL;
    if (rustd_journal_get_realtime_usec(journal, &realtime) < 0)
        realtime = 0U;
    if (asprintf(cursor, "rustd:%zu:%llu", journal->path_index,
                 (unsigned long long)realtime) < 0)
        return -ENOMEM;
    return 0;
}

int rustd_journal_seek_cursor(rustd_journal *journal, const char *cursor) {
    unsigned long long index;
    unsigned long long realtime;
    char extra;
    if (!journal || !cursor)
        return -EINVAL;
    if (sscanf(cursor, "rustd:%llu:%llu%c", &index, &realtime, &extra) != 2 ||
        index >= journal->path_count)
        return -EINVAL;
    (void)realtime;
    journal->path_index = index == 0U ? SIZE_MAX : (size_t)index - 1U;
    clear_current_entry(journal);
    return 0;
}

int rustd_journal_test_cursor(rustd_journal *journal, const char *cursor) {
    char *current = NULL;
    int result = rustd_journal_get_cursor(journal, &current);
    if (result < 0)
        return result;
    result = strcmp(current, cursor) == 0;
    free(current);
    return result;
}

static int seek_realtime(rustd_journal *journal, uint64_t usec) {
    size_t index;
    if (!journal)
        return -EINVAL;
    for (index = 0U; index < journal->path_count; index++) {
        uint64_t candidate;
        int result = load_entry(journal, index);
        if (result < 0)
            return result;
        if (rustd_journal_get_realtime_usec(journal, &candidate) == 0 && candidate >= usec) {
            journal->path_index = index == 0U ? SIZE_MAX : index - 1U;
            clear_current_entry(journal);
            return 0;
        }
    }
    return rustd_journal_seek_tail(journal);
}

int rustd_journal_seek_realtime_usec(rustd_journal *journal, uint64_t usec) {
    return seek_realtime(journal, usec);
}

int rustd_journal_seek_monotonic_usec(rustd_journal *journal, uint64_t usec) {
    size_t index;
    if (!journal)
        return -EINVAL;
    for (index = 0U; index < journal->path_count; index++) {
        uint64_t candidate;
        char *saved_entry = journal->entry;
        size_t saved_length = journal->entry_length;
        journal->entry = strdup(journal->paths[index]);
        if (!journal->entry) {
            journal->entry = saved_entry;
            return -ENOMEM;
        }
        journal->entry_length = strlen(journal->entry);
        if (rustd_journal_get_monotonic_usec(journal, &candidate, NULL) == 0 &&
            candidate >= usec) {
            free(journal->entry);
            journal->entry = saved_entry;
            journal->entry_length = saved_length;
            journal->path_index = index == 0U ? SIZE_MAX : index - 1U;
            clear_current_entry(journal);
            return 0;
        }
        free(journal->entry);
        journal->entry = saved_entry;
        journal->entry_length = saved_length;
    }
    return rustd_journal_seek_tail(journal);
}

int rustd_journal_get_cutoff_realtime_usec(rustd_journal *journal,
                                            uint64_t *from, uint64_t *to) {
    uint64_t minimum = UINT64_MAX;
    uint64_t maximum = 0U;
    size_t index;
    int found = 0;
    if (!journal || (!from && !to))
        return -EINVAL;
    for (index = 0U; index < journal->path_count; index++) {
        uint64_t value;
        char *entry = journal->entry;
        size_t entry_length = journal->entry_length;
        size_t path_index = journal->path_index;
        journal->entry = strdup(journal->paths[index]);
        if (!journal->entry) {
            journal->entry = entry;
            return -ENOMEM;
        }
        journal->entry_length = strlen(journal->entry);
        if (rustd_journal_get_realtime_usec(journal, &value) == 0) {
            if (value < minimum) minimum = value;
            if (value > maximum) maximum = value;
            found = 1;
        }
        free(journal->entry);
        journal->entry = entry;
        journal->entry_length = entry_length;
        journal->path_index = path_index;
    }
    if (!found)
        return 0;
    if (from) *from = minimum;
    if (to) *to = maximum;
    return 1;
}

int rustd_journal_get_monotonic_usec(rustd_journal *journal, uint64_t *usec,
                                     uint8_t boot_id[16]) {
    const void *data;
    size_t length;
    char buffer[64];
    char *end;
    unsigned long long value;
    int result;
    if (!journal || !usec)
        return -EINVAL;
    {
        size_t threshold;
        if (!journal)
            return -EINVAL;
        threshold = journal->data_threshold;
        journal->data_threshold = SIZE_MAX;
        result = rustd_journal_get_data(journal, "MONOTONIC_USEC", &data, &length);
        journal->data_threshold = threshold;
    }
    if (result < 0)
        return result;
    {
        const char *equals = memchr(data, '=', length);
        if (!equals)
            return -EINVAL;
        length -= (size_t)(equals + 1 - (const char *)data);
        data = equals + 1;
    }
    if (length >= sizeof(buffer))
        return -EINVAL;
    memcpy(buffer, data, length);
    buffer[length] = '\0';
    errno = 0;
    value = strtoull(buffer, &end, 10);
    if (errno || !end || *end)
        return -EINVAL;
    *usec = value;
    if (boot_id) {
        const void *boot_data;
        size_t boot_length;
        size_t threshold = journal->data_threshold;
        int boot_result;
        journal->data_threshold = SIZE_MAX;
        boot_result = rustd_journal_get_data(journal, "_BOOT_ID", &boot_data, &boot_length);
        journal->data_threshold = threshold;
        memset(boot_id, 0, 16U);
        if (boot_result == 0) {
            const char *equals = memchr(boot_data, '=', boot_length);
            const char *text = equals ? equals + 1 : NULL;
            size_t text_length = equals
                ? boot_length - (size_t)(text - (const char *)boot_data) : 0U;
            size_t digit = 0U;
            size_t byte = 0U;
            if (text_length != 32U)
                return -EINVAL;
            while (digit < text_length) {
                int high = isdigit((unsigned char)text[digit]) ? text[digit] - '0'
                    : isxdigit((unsigned char)text[digit])
                        ? tolower((unsigned char)text[digit]) - 'a' + 10 : -1;
                int low = isdigit((unsigned char)text[digit + 1U]) ? text[digit + 1U] - '0'
                    : isxdigit((unsigned char)text[digit + 1U])
                        ? tolower((unsigned char)text[digit + 1U]) - 'a' + 10 : -1;
                if (high < 0 || low < 0)
                    return -EINVAL;
                boot_id[byte++] = (uint8_t)((high << 4) | low);
                digit += 2U;
            }
        }
    }
    return 0;
}

int rustd_journal_enumerate_data(rustd_journal *journal, const void **data, size_t *length) {
    size_t start;
    size_t end;
    if (!journal || !data || !length || !journal->entry)
        return -EINVAL;
    if (journal->data_offset >= journal->entry_length)
        return 0;
    start = journal->data_offset;
    end = start;
    while (end < journal->entry_length && journal->entry[end] != '\n')
        end++;
    journal->data_offset = end < journal->entry_length ? end + 1U : end;
    *data = journal->entry + start;
    *length = end - start;
    if (*length > journal->data_threshold)
        *length = journal->data_threshold;
    return 1;
}

void rustd_journal_restart_data(rustd_journal *journal) {
    if (journal)
        journal->data_offset = 0U;
}

static int append_unique_string(char ***values, size_t *count,
                                const char *data, size_t length) {
    char **resized;
    size_t index;
    for (index = 0U; index < *count; index++)
        if (strlen((*values)[index]) == length &&
            memcmp((*values)[index], data, length) == 0)
            return 0;
    resized = realloc(*values, (*count + 1U) * sizeof(**values));
    if (!resized)
        return -ENOMEM;
    *values = resized;
    (*values)[*count] = strndup(data, length);
    if (!(*values)[*count])
        return -ENOMEM;
    (*count)++;
    return 0;
}

static int build_field_names(rustd_journal *journal) {
    size_t entry_index;
    if (journal->field_names)
        return 0;
    for (entry_index = 0U; entry_index < journal->path_count; entry_index++) {
        const char *cursor = journal->paths[entry_index];
        while (*cursor) {
            const char *end = strchr(cursor, '\n');
            const char *equals;
            size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
            equals = memchr(cursor, '=', length);
            if (equals) {
                int result = append_unique_string(&journal->field_names,
                    &journal->field_count, cursor, (size_t)(equals - cursor));
                if (result < 0)
                    return result;
            }
            if (!end)
                break;
            cursor = end + 1;
        }
    }
    return 0;
}

int rustd_journal_enumerate_fields(rustd_journal *journal, const char **field) {
    int result;
    if (!journal || !field)
        return -EINVAL;
    result = build_field_names(journal);
    if (result < 0)
        return result;
    if (journal->field_index >= journal->field_count)
        return 0;
    *field = journal->field_names[journal->field_index++];
    return 1;
}

void rustd_journal_restart_fields(rustd_journal *journal) {
    if (journal)
        journal->field_index = 0U;
}

int rustd_journal_query_unique(rustd_journal *journal, const char *field) {
    size_t entry_index;
    size_t field_length;
    if (!journal || !field || !*field || strchr(field, '='))
        return -EINVAL;
    free(journal->unique_field);
    journal->unique_field = strdup(field);
    free_string_array(journal->unique_values, journal->unique_count);
    journal->unique_values = NULL;
    journal->unique_count = 0U;
    journal->unique_index = 0U;
    if (!journal->unique_field)
        return -ENOMEM;
    field_length = strlen(field);
    for (entry_index = 0U; entry_index < journal->path_count; entry_index++) {
        const char *cursor = journal->paths[entry_index];
        while (*cursor) {
            const char *end = strchr(cursor, '\n');
            size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
            if (length > field_length && cursor[field_length] == '=' &&
                memcmp(cursor, field, field_length) == 0) {
                int result = append_unique_string(&journal->unique_values,
                    &journal->unique_count, cursor, length);
                if (result < 0)
                    return result;
            }
            if (!end)
                break;
            cursor = end + 1;
        }
    }
    return 0;
}

int rustd_journal_enumerate_unique(rustd_journal *journal,
                                   const void **data, size_t *length) {
    const char *value;
    if (!journal || !data || !length || !journal->unique_field)
        return -EINVAL;
    if (journal->unique_index >= journal->unique_count)
        return 0;
    value = journal->unique_values[journal->unique_index++];
    *data = value;
    *length = strlen(value);
    return 1;
}

void rustd_journal_restart_unique(rustd_journal *journal) {
    if (journal)
        journal->unique_index = 0U;
}

size_t rustd_journal_get_data_threshold(rustd_journal *journal) {
    return journal ? journal->data_threshold : 0U;
}

int rustd_journal_set_data_threshold(rustd_journal *journal, size_t threshold) {
    if (!journal)
        return -EINVAL;
    journal->data_threshold = threshold == 0U ? SIZE_MAX : threshold;
    return 0;
}

int rustd_journal_get_usage(rustd_journal *journal, uint64_t *bytes) {
    char path[PATH_MAX];
    struct stat st;
    if (!journal || !bytes)
        return -EINVAL;
    snprintf(path, sizeof(path), "%s/entries.log",
             journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR);
    if (stat(path, &st) < 0)
        return -errno;
    *bytes = (uint64_t)st.st_size;
    return 0;
}

int rustd_journal_has_runtime_files(rustd_journal *journal) {
    const char *directory;
    if (!journal)
        return -EINVAL;
    directory = journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR;
    return journal->path_count > 0U && strncmp(directory, "/run/", 5U) == 0;
}

int rustd_journal_has_persistent_files(rustd_journal *journal) {
    const char *directory;
    if (!journal)
        return -EINVAL;
    directory = journal->directory ? journal->directory : JOURNAL_RUNTIME_DIR;
    return journal->path_count > 0U && strncmp(directory, "/run/", 5U) != 0;
}

int rustd_journal_get_fd(rustd_journal *journal) {
    return journal ? (journal->notify_fd >= 0 ? journal->notify_fd : -ENOTSUP) : -EINVAL;
}

int rustd_journal_get_events(rustd_journal *journal) {
    return rustd_journal_get_fd(journal) < 0 ? -ENOTSUP : POLLIN;
}

int rustd_journal_get_timeout(rustd_journal *journal, uint64_t *timeout) {
    if (!journal || !timeout)
        return -EINVAL;
    *timeout = UINT64_MAX;
    return 0;
}

int rustd_journal_process(rustd_journal *journal) {
    char events[4096];
    ssize_t got;
    size_t old_count;
    size_t old_index;
    if (!journal)
        return -EINVAL;
    if (journal->notify_fd < 0)
        return 0;
    got = read(journal->notify_fd, events, sizeof(events));
    if (got < 0)
        return errno == EAGAIN ? 0 : -errno;
    old_count = journal->path_count;
    old_index = journal->path_index;
    clear_entries(journal);
    if (collect_journal_files(journal) < 0)
        journal->path_index = SIZE_MAX;
    else if (old_index != SIZE_MAX)
        journal->path_index = old_index < journal->path_count ? old_index : journal->path_count;
    return journal->path_count > old_count ? 1 : 2;
}

int rustd_journal_wait(rustd_journal *journal, uint64_t timeout_usec) {
    struct pollfd descriptor;
    int timeout_ms;
    int result;
    if (!journal || journal->notify_fd < 0)
        return -ENOTSUP;
    descriptor.fd = journal->notify_fd;
    descriptor.events = POLLIN;
    descriptor.revents = 0;
    timeout_ms = timeout_usec == UINT64_MAX ? -1 :
        timeout_usec / 1000U > (uint64_t)INT_MAX ? INT_MAX :
        (int)((timeout_usec + 999U) / 1000U);
    do result = poll(&descriptor, 1, timeout_ms); while (result < 0 && errno == EINTR);
    if (result <= 0)
        return result < 0 ? -errno : 0;
    return rustd_journal_process(journal);
}
