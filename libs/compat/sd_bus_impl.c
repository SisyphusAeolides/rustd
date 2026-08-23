/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <dbus/dbus.h>
#include "sd_bus_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct sd_event_source sd_event_source;
extern int sd_event_add_io(sd_event *event, sd_event_source **ret, int fd,
                           uint32_t events, void *callback, void *userdata)
    __attribute__((weak));
extern int sd_event_source_set_priority(sd_event_source *source, int64_t priority)
    __attribute__((weak));
extern int sd_event_add_time(sd_event *event, sd_event_source **ret, int clock,
                             uint64_t usec, uint64_t accuracy, void *callback,
                             void *userdata) __attribute__((weak));
extern int sd_event_source_set_enabled(sd_event_source *source, int mode)
    __attribute__((weak));
extern int sd_event_source_set_io_events(sd_event_source *source, uint32_t events)
    __attribute__((weak));
extern int sd_event_source_set_prepare(sd_event_source *source, void *callback)
    __attribute__((weak));
extern int sd_event_source_set_time(sd_event_source *source, uint64_t usec)
    __attribute__((weak));
extern sd_event_source *sd_event_source_unref(sd_event_source *source)
    __attribute__((weak));

/*
 * RustD libsystemd compatibility transport.
 *
 * This file intentionally uses libdbus-1 only as a D-Bus wire/transport
 * implementation. It neither links to nor calls libsystemd. The public
 * sd-bus declarations come from the development header while this engine is
 * being certified; RustD vendors the small public ABI declarations before
 * systemd build dependencies are removed from the release image.
 */

const unsigned sd_bus_object_vtable_format = 1U;

enum rustd_slot_kind {
    RUSTD_SLOT_FILTER,
    RUSTD_SLOT_MATCH,
    RUSTD_SLOT_OBJECT,
    RUSTD_SLOT_ASYNC,
    RUSTD_SLOT_MANAGER,
};

struct sd_bus_message {
    unsigned refs;
    sd_bus *bus;
    DBusMessage *message;
    DBusMessageIter append_stack[32];
    unsigned append_depth;
    bool append_initialized;
    bool sealed;
    DBusMessageIter read_stack[32];
    unsigned read_depth;
    bool read_initialized;
    sd_bus_error cached_error;
    int unix_fds[64];
    unsigned n_unix_fds;
    char *string_space;
    char *peek_contents;
};

struct sd_bus_slot {
    unsigned refs;
    enum rustd_slot_kind kind;
    sd_bus *bus;
    sd_bus_message_handler_t callback;
    sd_bus_message_handler_t install_callback;
    void *userdata;
    char *sender;
    char *path;
    char *interface;
    char *member;
    char *match;
    const sd_bus_vtable *vtable;
    DBusPendingCall *pending;
    uint64_t deadline_usec;
    struct sd_bus_slot *next;
};

struct sd_bus_creds {
    unsigned refs;
    uint64_t mask;
    pid_t pid;
    uid_t uid;
    uid_t euid;
    gid_t gid;
    gid_t egid;
    gid_t *supplementary_gids;
    int n_supplementary_gids;
    char *selinux_context;
};

struct sd_bus {
    unsigned refs;
    DBusConnection *connection;
    int input_fd;
    int output_fd;
    bool owns_input_fd;
    bool owns_output_fd;
    bool started;
    bool bus_client;
    bool server;
    bool trusted;
    sd_id128_t server_id;
    uint32_t next_serial;
    uint64_t method_call_timeout;
    char *address;
    sd_event *event;
    sd_event_source *event_source;
    sd_event_source *event_timer_source;
    sd_bus_message *current_message;
    struct sd_bus_slot *slots;
};

static DBusHandlerResult rustd_dbus_filter(DBusConnection *connection,
                                            DBusMessage *raw, void *userdata);
int sd_bus_message_new_signal(sd_bus *bus, sd_bus_message **ret, const char *path,
                              const char *interface, const char *member);
static bool rustd_object_path_below(const char *manager, const char *path);

struct rustd_bus_error_map {
    const char *name;
    int error;
};

static const struct rustd_bus_error_map rustd_bus_error_map[] = {
    {DBUS_ERROR_FAILED, EACCES},
    {DBUS_ERROR_NO_MEMORY, ENOMEM},
    {DBUS_ERROR_SERVICE_UNKNOWN, EHOSTUNREACH},
    {DBUS_ERROR_NAME_HAS_NO_OWNER, ENXIO},
    {DBUS_ERROR_NO_REPLY, ETIMEDOUT},
    {DBUS_ERROR_IO_ERROR, EIO},
    {DBUS_ERROR_BAD_ADDRESS, EADDRNOTAVAIL},
    {DBUS_ERROR_NOT_SUPPORTED, EOPNOTSUPP},
    {DBUS_ERROR_LIMITS_EXCEEDED, ENOBUFS},
    {DBUS_ERROR_ACCESS_DENIED, EACCES},
    {DBUS_ERROR_AUTH_FAILED, EACCES},
    {DBUS_ERROR_NO_SERVER, EHOSTDOWN},
    {DBUS_ERROR_TIMEOUT, ETIMEDOUT},
    {DBUS_ERROR_NO_NETWORK, ENONET},
    {DBUS_ERROR_ADDRESS_IN_USE, EADDRINUSE},
    {DBUS_ERROR_DISCONNECTED, ECONNRESET},
    {DBUS_ERROR_INVALID_ARGS, EINVAL},
    {DBUS_ERROR_FILE_NOT_FOUND, ENOENT},
    {DBUS_ERROR_FILE_EXISTS, EEXIST},
    {DBUS_ERROR_UNKNOWN_METHOD, EBADR},
    {DBUS_ERROR_UNKNOWN_OBJECT, EBADR},
    {DBUS_ERROR_UNKNOWN_INTERFACE, EBADR},
    {DBUS_ERROR_UNKNOWN_PROPERTY, EBADR},
    {DBUS_ERROR_PROPERTY_READ_ONLY, EROFS},
    {DBUS_ERROR_UNIX_PROCESS_ID_UNKNOWN, ESRCH},
    {DBUS_ERROR_INVALID_SIGNATURE, EINVAL},
    {DBUS_ERROR_INCONSISTENT_MESSAGE, EBADMSG},
    {DBUS_ERROR_TIMED_OUT, ETIMEDOUT},
    {DBUS_ERROR_MATCH_RULE_NOT_FOUND, ENOENT},
    {DBUS_ERROR_MATCH_RULE_INVALID, EINVAL},
    {DBUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED, EACCES},
    {DBUS_ERROR_INVALID_FILE_CONTENT, EINVAL},
    {DBUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN, ESRCH},
    {DBUS_ERROR_OBJECT_PATH_IN_USE, EBUSY},
};

int sd_bus_service_name_is_valid(const char *name) {
    return name && dbus_validate_bus_name(name, NULL);
}

int sd_bus_interface_name_is_valid(const char *name) {
    return name && dbus_validate_interface(name, NULL);
}

int sd_bus_member_name_is_valid(const char *name) {
    return name && dbus_validate_member(name, NULL);
}

int sd_bus_object_path_is_valid(const char *path) {
    return path && dbus_validate_path(path, NULL);
}

static int rustd_error_name_to_errno(const char *name) {
    size_t i;
    if (!name)
        return 0;
    if (strncmp(name, "System.Error.", 13U) == 0) {
        const char *wanted = name + 13U;
        int e;
        for (e = 1; e < 4096; ++e) {
            const char *candidate = strerrorname_np(e);
            if (candidate && strcmp(candidate, wanted) == 0)
                return e;
        }
        return EIO;
    }
    for (i = 0; i < sizeof(rustd_bus_error_map) / sizeof(rustd_bus_error_map[0]); ++i)
        if (strcmp(name, rustd_bus_error_map[i].name) == 0)
            return rustd_bus_error_map[i].error;
    return EIO;
}

static const char *rustd_errno_to_error_name(int error) {
    size_t i;
    for (i = 0; i < sizeof(rustd_bus_error_map) / sizeof(rustd_bus_error_map[0]); ++i)
        if (rustd_bus_error_map[i].error == error)
            return rustd_bus_error_map[i].name;
    return DBUS_ERROR_FAILED;
}

static bool rustd_bus_error_dirty(const sd_bus_error *e) {
    return e && (e->name || e->message || e->_need_free != 0);
}

static uint64_t rustd_bus_monotonic_usec(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return 0U;
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
           (uint64_t)now.tv_nsec / UINT64_C(1000);
}

int sd_bus_error_is_set(const sd_bus_error *e) {
    return e && e->name;
}

int sd_bus_error_set(sd_bus_error *e, const char *name, const char *message) {
    char *name_copy;
    char *message_copy;
    if (!e || !name || !message || rustd_bus_error_dirty(e))
        return -EINVAL;
    name_copy = strdup(name);
    message_copy = strdup(message);
    if (!name_copy || !message_copy) {
        free(name_copy);
        free(message_copy);
        return -ENOMEM;
    }
    e->name = name_copy;
    e->message = message_copy;
    e->_need_free = 1;
    return -rustd_error_name_to_errno(name);
}

int sd_bus_error_set_errno(sd_bus_error *e, int error) {
    char *name;
    char *message;
    const char *mapped;
    const char *errno_name;
    size_t length;
    if (error < 0)
        error = -error;
    if (!e)
        return -error;
    if (error == 0)
        return 0;
    if (rustd_bus_error_dirty(e))
        return -EINVAL;
    mapped = rustd_errno_to_error_name(error);
    if (strcmp(mapped, DBUS_ERROR_FAILED) != 0 || error == EACCES) {
        e->name = mapped;
        e->message = strerror(error);
        e->_need_free = 0;
        return -error;
    }
    errno_name = strerrorname_np(error);
    if (!errno_name) {
        e->name = DBUS_ERROR_FAILED;
        e->message = strerror(error);
        e->_need_free = 0;
        return -error;
    }
    length = strlen("System.Error.") + strlen(errno_name) + 1U;
    name = malloc(length);
    message = strdup(strerror(error));
    if (!name || !message) {
        free(name);
        free(message);
        e->name = DBUS_ERROR_NO_MEMORY;
        e->message = "Out of memory";
        e->_need_free = 0;
        return -error;
    }
    snprintf(name, length, "System.Error.%s", errno_name);
    e->name = name;
    e->message = message;
    e->_need_free = 1;
    return -error;
}

void sd_bus_error_free(sd_bus_error *e) {
    if (!e)
        return;
    if (e->_need_free > 0) {
        free((void *)e->name);
        free((void *)e->message);
    }
    *e = SD_BUS_ERROR_NULL;
}

int sd_bus_error_get_errno(const sd_bus_error *e) {
    return e && e->name ? rustd_error_name_to_errno(e->name) : 0;
}

int sd_bus_error_has_name(const sd_bus_error *e, const char *name) {
    if (!e)
        return 0;
    if (!e->name || !name)
        return e->name == name;
    return strcmp(e->name, name) == 0;
}

static void rustd_set_dbus_error(sd_bus_error *ret, const DBusError *error) {
    if (!ret || !error || !dbus_error_is_set(error) || rustd_bus_error_dirty(ret))
        return;
    ret->name = strdup(error->name ? error->name : DBUS_ERROR_FAILED);
    ret->message = strdup(error->message ? error->message : "D-Bus operation failed");
    if (ret->name && ret->message)
        ret->_need_free = 1;
    else {
        free((void *)ret->name);
        free((void *)ret->message);
        ret->name = DBUS_ERROR_NO_MEMORY;
        ret->message = "Out of memory";
        ret->_need_free = 0;
    }
}

static int rustd_dbus_error_result(const DBusError *error) {
    if (!error || !dbus_error_is_set(error))
        return -EIO;
    return -rustd_error_name_to_errno(error->name);
}

static int rustd_dispatch_message(sd_bus *bus, sd_bus_message *m);
static int rustd_raw_authenticate(sd_bus *bus);
static int rustd_raw_authenticate_server(sd_bus *bus);
static int rustd_raw_receive_message(int fd, int timeout, DBusMessage **ret);
static int rustd_raw_send_message(int fd, const void *data, size_t length,
                                  const int *fds, unsigned n_fds, int timeout);

static sd_bus_message *rustd_message_wrap(sd_bus *bus, DBusMessage *message, bool take_ref) {
    sd_bus_message *wrapped;
    if (!message)
        return NULL;
    wrapped = calloc(1, sizeof(*wrapped));
    if (!wrapped)
        return NULL;
    wrapped->refs = 1U;
    wrapped->bus = bus ? sd_bus_ref(bus) : NULL;
    wrapped->message = take_ref ? dbus_message_ref(message) : message;
    wrapped->cached_error = SD_BUS_ERROR_NULL;
    return wrapped;
}

static DBusMessageIter *rustd_append_iter(sd_bus_message *m) {
    if (!m->append_initialized) {
        dbus_message_iter_init_append(m->message, &m->append_stack[0]);
        m->append_initialized = true;
        m->append_depth = 0U;
    }
    return &m->append_stack[m->append_depth];
}

static int rustd_commit_string_space(sd_bus_message *m) {
    const char *value;
    DBusMessageIter *iter;
    if (!m || !m->string_space)
        return 0;
    value = m->string_space;
    iter = rustd_append_iter(m);
    if (!dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &value))
        return -ENOMEM;
    free(m->string_space);
    m->string_space = NULL;
    return 0;
}

static DBusMessageIter *rustd_read_iter(sd_bus_message *m) {
    (void)rustd_commit_string_space(m);
    if (!m->read_initialized) {
        if (!dbus_message_iter_init(m->message, &m->read_stack[0]))
            memset(&m->read_stack[0], 0, sizeof(m->read_stack[0]));
        m->read_initialized = true;
        m->read_depth = 0U;
    }
    return &m->read_stack[m->read_depth];
}

static const char *rustd_signature_end(const char *signature) {
    const char *cursor;
    if (!signature || !*signature)
        return signature;
    switch (*signature) {
    case 'a':
        return rustd_signature_end(signature + 1);
    case '(':
        cursor = signature + 1;
        while (*cursor && *cursor != ')')
            cursor = rustd_signature_end(cursor);
        return *cursor == ')' ? cursor + 1 : NULL;
    case '{':
        cursor = rustd_signature_end(signature + 1);
        if (!cursor)
            return NULL;
        cursor = rustd_signature_end(cursor);
        return cursor && *cursor == '}' ? cursor + 1 : NULL;
    default:
        return signature + 1;
    }
}

static char *rustd_signature_copy(const char *begin, const char *end) {
    size_t length;
    char *copy;
    if (!begin || !end || end < begin)
        return NULL;
    length = (size_t)(end - begin);
    copy = malloc(length + 1U);
    if (!copy)
        return NULL;
    memcpy(copy, begin, length);
    copy[length] = '\0';
    return copy;
}

static int rustd_append_basic_ap(sd_bus_message *m, DBusMessageIter *iter, char type, va_list *ap) {
    dbus_bool_t ok;
    switch (type) {
    case SD_BUS_TYPE_BYTE: {
        unsigned char value = (unsigned char)va_arg(*ap, int);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &value);
        break;
    }
    case SD_BUS_TYPE_BOOLEAN: {
        dbus_bool_t value = va_arg(*ap, int) ? TRUE : FALSE;
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);
        break;
    }
    case SD_BUS_TYPE_INT16: {
        dbus_int16_t value = (dbus_int16_t)va_arg(*ap, int);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_INT16, &value);
        break;
    }
    case SD_BUS_TYPE_UINT16: {
        dbus_uint16_t value = (dbus_uint16_t)va_arg(*ap, int);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &value);
        break;
    }
    case SD_BUS_TYPE_INT32: {
        dbus_int32_t value = va_arg(*ap, int32_t);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &value);
        break;
    }
    case SD_BUS_TYPE_UINT32: {
        dbus_uint32_t value = va_arg(*ap, uint32_t);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &value);
        break;
    }
    case SD_BUS_TYPE_INT64: {
        dbus_int64_t value = va_arg(*ap, int64_t);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_INT64, &value);
        break;
    }
    case SD_BUS_TYPE_UINT64: {
        dbus_uint64_t value = va_arg(*ap, uint64_t);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT64, &value);
        break;
    }
    case SD_BUS_TYPE_DOUBLE: {
        double value = va_arg(*ap, double);
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_DOUBLE, &value);
        break;
    }
    case SD_BUS_TYPE_UNIX_FD: {
        int value = va_arg(*ap, int);
        int copy;
        if (value < 0 || m->n_unix_fds >= sizeof(m->unix_fds) / sizeof(m->unix_fds[0]))
            return value < 0 ? -EBADF : -EMFILE;
        copy = fcntl(value, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
            return -errno;
        ok = dbus_message_iter_append_basic(iter, DBUS_TYPE_UNIX_FD, &value);
        if (!ok) {
            close(copy);
            return -ENOMEM;
        }
        m->unix_fds[m->n_unix_fds++] = copy;
        break;
    }
    case SD_BUS_TYPE_STRING:
    case SD_BUS_TYPE_OBJECT_PATH:
    case SD_BUS_TYPE_SIGNATURE: {
        const char *value = va_arg(*ap, const char *);
        int dbus_type = type == SD_BUS_TYPE_STRING ? DBUS_TYPE_STRING :
                        type == SD_BUS_TYPE_OBJECT_PATH ? DBUS_TYPE_OBJECT_PATH : DBUS_TYPE_SIGNATURE;
        if (!value && type != SD_BUS_TYPE_OBJECT_PATH)
            value = "";
        if (!value)
            return -EINVAL;
        ok = dbus_message_iter_append_basic(iter, dbus_type, &value);
        break;
    }
    default:
        return -EINVAL;
    }
    return ok ? 0 : -ENOMEM;
}

static int rustd_append_one(sd_bus_message *m, DBusMessageIter *iter,
                            const char **signature, va_list *ap) {
    const char *s = *signature;
    const char *end;
    DBusMessageIter child;
    int r;
    if (!s || !*s)
        return -EINVAL;
    if (strchr("ybnqiuxtdhsog", *s)) {
        r = rustd_append_basic_ap(m, iter, *s, ap);
        if (r >= 0)
            *signature = s + 1;
        return r;
    }
    if (*s == SD_BUS_TYPE_VARIANT) {
        const char *contents = va_arg(*ap, const char *);
        const char *nested;
        if (!contents || !dbus_signature_validate_single(contents, NULL))
            return -EINVAL;
        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, contents, &child))
            return -ENOMEM;
        nested = contents;
        r = rustd_append_one(m, &child, &nested, ap);
        if (r < 0)
            return r;
        if (!dbus_message_iter_close_container(iter, &child))
            return -ENOMEM;
        *signature = s + 1;
        return 0;
    }
    if (*s == SD_BUS_TYPE_ARRAY) {
        int count = va_arg(*ap, int);
        const char *element = s + 1;
        end = rustd_signature_end(element);
        char *contents;
        int index;
        if (count < 0 || !end)
            return -EINVAL;
        contents = rustd_signature_copy(element, end);
        if (!contents)
            return -ENOMEM;
        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, contents, &child)) {
            free(contents);
            return -ENOMEM;
        }
        for (index = 0; index < count; ++index) {
            const char *nested = element;
            r = rustd_append_one(m, &child, &nested, ap);
            if (r < 0) {
                free(contents);
                return r;
            }
        }
        free(contents);
        if (!dbus_message_iter_close_container(iter, &child))
            return -ENOMEM;
        *signature = end;
        return 0;
    }
    if (*s == '(' || *s == '{') {
        char close = *s == '(' ? ')' : '}';
        int dbus_type = *s == '(' ? DBUS_TYPE_STRUCT : DBUS_TYPE_DICT_ENTRY;
        const char *nested = s + 1;
        if (!dbus_message_iter_open_container(iter, dbus_type, NULL, &child))
            return -ENOMEM;
        while (*nested && *nested != close) {
            r = rustd_append_one(m, &child, &nested, ap);
            if (r < 0)
                return r;
        }
        if (*nested != close)
            return -EINVAL;
        if (!dbus_message_iter_close_container(iter, &child))
            return -ENOMEM;
        *signature = nested + 1;
        return 0;
    }
    return -EINVAL;
}

static int rustd_message_appendv(sd_bus_message *m, const char *types, va_list ap) {
    DBusMessageIter *iter;
    const char *cursor;
    va_list copy;
    int r;
    if (!m || !types || !dbus_signature_validate(types, NULL))
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    r = rustd_commit_string_space(m);
    if (r < 0)
        return r;
    iter = rustd_append_iter(m);
    cursor = types;
    va_copy(copy, ap);
    while (*cursor) {
        r = rustd_append_one(m, iter, &cursor, &copy);
        if (r < 0) {
            va_end(copy);
            return r;
        }
    }
    va_end(copy);
    return 0;
}

int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
    va_list ap;
    int r;
    va_start(ap, types);
    r = rustd_message_appendv(m, types, ap);
    va_end(ap);
    return r;
}

int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *value) {
    DBusMessageIter *iter;
    int dbus_type = type;
    if (!m || !value || !strchr("ybnqiuxtdhsog", type))
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    if (type == SD_BUS_TYPE_STRING)
        dbus_type = DBUS_TYPE_STRING;
    else if (type == SD_BUS_TYPE_OBJECT_PATH)
        dbus_type = DBUS_TYPE_OBJECT_PATH;
    else if (type == SD_BUS_TYPE_SIGNATURE)
        dbus_type = DBUS_TYPE_SIGNATURE;
    if (rustd_commit_string_space(m) < 0)
        return -ENOMEM;
    iter = rustd_append_iter(m);
    return dbus_message_iter_append_basic(iter, dbus_type, value) ? 0 : -ENOMEM;
}

int sd_bus_message_append_string_space(sd_bus_message *m, size_t size, char **ret) {
    char *space;
    int r;
    if (!m || !ret || size == SIZE_MAX)
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    r = rustd_commit_string_space(m);
    if (r < 0)
        return r;
    space = calloc(size + 1U, 1U);
    if (!space)
        return -ENOMEM;
    m->string_space = space;
    *ret = space;
    return 0;
}

int sd_bus_message_append_strv(sd_bus_message *m, char **values) {
    DBusMessageIter *iter;
    DBusMessageIter array;
    size_t index;
    int r;
    if (!m)
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    r = rustd_commit_string_space(m);
    if (r < 0)
        return r;
    iter = rustd_append_iter(m);
    if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                          &array))
        return -ENOMEM;
    for (index = 0; values && values[index]; index++) {
        const char *value = values[index];
        if (!dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &value))
            return -ENOMEM;
    }
    return dbus_message_iter_close_container(iter, &array) ? 0 : -ENOMEM;
}

static int rustd_dbus_fixed_size(char type) {
    switch (type) {
    case DBUS_TYPE_BYTE: return 1;
    case DBUS_TYPE_INT16:
    case DBUS_TYPE_UINT16: return 2;
    case DBUS_TYPE_BOOLEAN:
    case DBUS_TYPE_INT32:
    case DBUS_TYPE_UINT32:
    case DBUS_TYPE_UNIX_FD: return 4;
    case DBUS_TYPE_INT64:
    case DBUS_TYPE_UINT64:
    case DBUS_TYPE_DOUBLE: return 8;
    default: return 0;
    }
}

int sd_bus_message_append_array(sd_bus_message *m, char type, const void *ptr, size_t size) {
    DBusMessageIter *iter;
    DBusMessageIter array;
    const void *data = ptr;
    int element_size;
    int count;
    char signature[2] = {type, '\0'};
    if (!m || (!ptr && size != 0U) || !dbus_type_is_fixed(type))
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    element_size = rustd_dbus_fixed_size(type);
    if (element_size <= 0 || size % (size_t)element_size != 0U ||
        size / (size_t)element_size > (size_t)INT_MAX)
        return -EINVAL;
    count = (int)(size / (size_t)element_size);
    if (rustd_commit_string_space(m) < 0)
        return -ENOMEM;
    iter = rustd_append_iter(m);
    if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, signature, &array))
        return -ENOMEM;
    if (count > 0 && !dbus_message_iter_append_fixed_array(&array, type, &data, count))
        return -ENOMEM;
    return dbus_message_iter_close_container(iter, &array) ? 0 : -ENOMEM;
}

static int rustd_read_basic_iter(DBusMessageIter *iter, char type, void *ret) {
    int actual = dbus_message_iter_get_arg_type(iter);
    int wanted;
    if (type == SD_BUS_TYPE_STRING)
        wanted = DBUS_TYPE_STRING;
    else if (type == SD_BUS_TYPE_OBJECT_PATH)
        wanted = DBUS_TYPE_OBJECT_PATH;
    else if (type == SD_BUS_TYPE_SIGNATURE)
        wanted = DBUS_TYPE_SIGNATURE;
    else
        wanted = type;
    if (actual != wanted)
        return -ENXIO;
    if (ret)
        dbus_message_iter_get_basic(iter, ret);
    dbus_message_iter_next(iter);
    return 1;
}

static int rustd_read_one(DBusMessageIter *iter, const char **signature, va_list *ap) {
    const char *s = *signature;
    const char *end;
    int r;
    if (!s || !*s)
        return -EINVAL;
    if (strchr("ybnqiuxtdhsog", *s)) {
        void *ret = va_arg(*ap, void *);
        r = rustd_read_basic_iter(iter, *s, ret);
        if (r >= 0)
            *signature = s + 1;
        return r;
    }
    if (*s == SD_BUS_TYPE_VARIANT) {
        const char *expected = va_arg(*ap, const char *);
        DBusMessageIter child;
        char *actual;
        const char *nested;
        if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
            return -ENXIO;
        dbus_message_iter_recurse(iter, &child);
        actual = dbus_message_iter_get_signature(&child);
        if (!actual)
            return -ENOMEM;
        if (expected && strcmp(expected, actual) != 0) {
            dbus_free(actual);
            return -ENXIO;
        }
        nested = expected ? expected : actual;
        while (*nested) {
            r = rustd_read_one(&child, &nested, ap);
            if (r < 0) {
                dbus_free(actual);
                return r;
            }
        }
        dbus_free(actual);
        dbus_message_iter_next(iter);
        *signature = s + 1;
        return 1;
    }
    if (*s == SD_BUS_TYPE_ARRAY) {
        int expected_count = va_arg(*ap, int);
        const char *element = s + 1;
        DBusMessageIter child;
        int count = 0;
        if (expected_count < 0 || dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
            return -ENXIO;
        end = rustd_signature_end(element);
        if (!end)
            return -EINVAL;
        dbus_message_iter_recurse(iter, &child);
        while (dbus_message_iter_get_arg_type(&child) != DBUS_TYPE_INVALID) {
            const char *nested = element;
            if (count >= expected_count)
                return -EMSGSIZE;
            r = rustd_read_one(&child, &nested, ap);
            if (r < 0)
                return r;
            ++count;
        }
        if (count != expected_count)
            return -EMSGSIZE;
        dbus_message_iter_next(iter);
        *signature = end;
        return 1;
    }
    if (*s == '(' || *s == '{') {
        int wanted = *s == '(' ? DBUS_TYPE_STRUCT : DBUS_TYPE_DICT_ENTRY;
        char close = *s == '(' ? ')' : '}';
        DBusMessageIter child;
        const char *nested = s + 1;
        if (dbus_message_iter_get_arg_type(iter) != wanted)
            return -ENXIO;
        dbus_message_iter_recurse(iter, &child);
        while (*nested && *nested != close) {
            r = rustd_read_one(&child, &nested, ap);
            if (r < 0)
                return r;
        }
        if (*nested != close || dbus_message_iter_get_arg_type(&child) != DBUS_TYPE_INVALID)
            return -ENXIO;
        dbus_message_iter_next(iter);
        *signature = nested + 1;
        return 1;
    }
    return -EINVAL;
}

static int rustd_message_readv(sd_bus_message *m, const char *types, va_list ap) {
    DBusMessageIter *iter;
    const char *cursor;
    va_list copy;
    int total = 0;
    int r;
    if (!m || !types || !dbus_signature_validate(types, NULL))
        return -EINVAL;
    iter = rustd_read_iter(m);
    cursor = types;
    va_copy(copy, ap);
    while (*cursor) {
        r = rustd_read_one(iter, &cursor, &copy);
        if (r < 0) {
            va_end(copy);
            return r;
        }
        total += r > 0;
    }
    va_end(copy);
    return total;
}

int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
    va_list ap;
    int r;
    va_start(ap, types);
    r = rustd_message_readv(m, types, ap);
    va_end(ap);
    return r;
}

int sd_bus_message_read_basic(sd_bus_message *m, char type, void *ret) {
    if (!m)
        return -EINVAL;
    return rustd_read_basic_iter(rustd_read_iter(m), type, ret);
}

int sd_bus_message_read_array(sd_bus_message *m, char type, const void **ptr, size_t *size) {
    DBusMessageIter *iter;
    DBusMessageIter array;
    int count;
    int element_size;
    if (!m || !ptr || !size || !dbus_type_is_fixed(type))
        return -EINVAL;
    iter = rustd_read_iter(m);
    if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
        dbus_message_iter_get_element_type(iter) != type)
        return -ENXIO;
    dbus_message_iter_recurse(iter, &array);
    dbus_message_iter_get_fixed_array(&array, (void *)ptr, &count);
    element_size = rustd_dbus_fixed_size(type);
    *size = (size_t)count * (size_t)element_size;
    dbus_message_iter_next(iter);
    return 1;
}

int sd_bus_message_peek_type(sd_bus_message *m, char *type, const char **contents) {
    DBusMessageIter *iter;
    int actual;
    if (!m)
        return -EINVAL;
    iter = rustd_read_iter(m);
    actual = dbus_message_iter_get_arg_type(iter);
    if (actual == DBUS_TYPE_INVALID)
        return 0;
    if (type)
        *type = actual == DBUS_TYPE_STRUCT ? SD_BUS_TYPE_STRUCT :
                actual == DBUS_TYPE_DICT_ENTRY ? SD_BUS_TYPE_DICT_ENTRY : (char)actual;
    if (contents) {
        char *signature = NULL;
        const char *inner = NULL;
        size_t length = 0U;
        free(m->peek_contents);
        m->peek_contents = NULL;
        if (actual == DBUS_TYPE_VARIANT) {
            DBusMessageIter child;
            dbus_message_iter_recurse(iter, &child);
            signature = dbus_message_iter_get_signature(&child);
            inner = signature;
            length = signature ? strlen(signature) : 0U;
        } else if (actual == DBUS_TYPE_ARRAY || actual == DBUS_TYPE_STRUCT ||
                   actual == DBUS_TYPE_DICT_ENTRY) {
            signature = dbus_message_iter_get_signature(iter);
            if (signature) {
                inner = signature + 1U;
                length = strlen(signature) -
                         (actual == DBUS_TYPE_ARRAY ? 1U : 2U);
            }
        }
        if (inner) {
            m->peek_contents = strndup(inner, length);
            if (!m->peek_contents) {
                dbus_free(signature);
                return -ENOMEM;
            }
        }
        dbus_free(signature);
        *contents = m->peek_contents;
    }
    return 1;
}

static int rustd_copy_iter_value(DBusMessageIter *destination, DBusMessageIter *source) {
    int type = dbus_message_iter_get_arg_type(source);
    if (type == DBUS_TYPE_INVALID)
        return 0;
    if (dbus_type_is_basic(type)) {
        union {
            dbus_uint64_t u64;
            double d;
            const char *string;
        } value = {0};
        dbus_message_iter_get_basic(source, &value);
        if (!dbus_message_iter_append_basic(destination, type, &value))
            return -ENOMEM;
    } else if (type == DBUS_TYPE_ARRAY &&
               dbus_type_is_fixed(dbus_message_iter_get_element_type(source))) {
        DBusMessageIter child;
        DBusMessageIter output;
        void *data = NULL;
        int count = 0;
        int element = dbus_message_iter_get_element_type(source);
        char signature[2] = {(char)element, '\0'};
        dbus_message_iter_recurse(source, &child);
        dbus_message_iter_get_fixed_array(&child, &data, &count);
        if (!dbus_message_iter_open_container(destination, type, signature, &output) ||
            (count > 0 && !dbus_message_iter_append_fixed_array(&output, element, &data, count)) ||
            !dbus_message_iter_close_container(destination, &output))
            return -ENOMEM;
    } else if (type == DBUS_TYPE_ARRAY || type == DBUS_TYPE_VARIANT ||
               type == DBUS_TYPE_STRUCT || type == DBUS_TYPE_DICT_ENTRY) {
        DBusMessageIter child;
        DBusMessageIter output;
        char *signature = NULL;
        const char *contents = NULL;
        int r;
        dbus_message_iter_recurse(source, &child);
        if (type == DBUS_TYPE_ARRAY || type == DBUS_TYPE_VARIANT) {
            signature = dbus_message_iter_get_signature(&child);
            if (!signature)
                return -ENOMEM;
            contents = signature;
        }
        if (!dbus_message_iter_open_container(destination, type, contents, &output)) {
            dbus_free(signature);
            return -ENOMEM;
        }
        while (dbus_message_iter_get_arg_type(&child) != DBUS_TYPE_INVALID) {
            r = rustd_copy_iter_value(&output, &child);
            if (r < 0) {
                dbus_free(signature);
                return r;
            }
        }
        dbus_free(signature);
        if (!dbus_message_iter_close_container(destination, &output))
            return -ENOMEM;
    } else
        return -EOPNOTSUPP;
    dbus_message_iter_next(source);
    return 1;
}

int sd_bus_message_copy(sd_bus_message *destination, sd_bus_message *source, int all) {
    DBusMessageIter *from;
    DBusMessageIter *to;
    int copied = 0;
    int r;
    if (!destination || !source || (all != 0 && all != 1))
        return -EINVAL;
    if (destination->sealed)
        return -EPERM;
    r = rustd_commit_string_space(destination);
    if (r < 0)
        return r;
    from = rustd_read_iter(source);
    to = rustd_append_iter(destination);
    do {
        r = rustd_copy_iter_value(to, from);
        if (r <= 0)
            return r < 0 ? r : copied;
        copied += r;
    } while (all);
    return copied;
}

int sd_bus_message_open_container(sd_bus_message *m, char type, const char *contents) {
    DBusMessageIter child;
    DBusMessageIter *parent;
    int dbus_type = type;
    if (!m || m->append_depth + 1U >= 32U)
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    if (type == SD_BUS_TYPE_STRUCT)
        dbus_type = DBUS_TYPE_STRUCT;
    else if (type == SD_BUS_TYPE_DICT_ENTRY)
        dbus_type = DBUS_TYPE_DICT_ENTRY;
    if (dbus_type != DBUS_TYPE_ARRAY && dbus_type != DBUS_TYPE_VARIANT &&
        dbus_type != DBUS_TYPE_STRUCT && dbus_type != DBUS_TYPE_DICT_ENTRY)
        return -EINVAL;
    if (dbus_type == DBUS_TYPE_STRUCT || dbus_type == DBUS_TYPE_DICT_ENTRY)
        contents = NULL;
    parent = rustd_append_iter(m);
    if (!dbus_message_iter_open_container(parent, dbus_type, contents, &child))
        return -ENOMEM;
    ++m->append_depth;
    m->append_stack[m->append_depth] = child;
    return 0;
}

int sd_bus_message_close_container(sd_bus_message *m) {
    DBusMessageIter child;
    DBusMessageIter *parent;
    if (!m || !m->append_initialized || m->append_depth == 0U)
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    child = m->append_stack[m->append_depth];
    parent = &m->append_stack[m->append_depth - 1U];
    if (!dbus_message_iter_close_container(parent, &child))
        return -ENOMEM;
    --m->append_depth;
    return 0;
}

int sd_bus_message_enter_container(sd_bus_message *m, char type, const char *contents) {
    DBusMessageIter *parent;
    DBusMessageIter child;
    char *actual_signature;
    int actual;
    int wanted = type;
    if (!m || m->read_depth + 1U >= 32U)
        return -EINVAL;
    parent = rustd_read_iter(m);
    actual = dbus_message_iter_get_arg_type(parent);
    if (type == SD_BUS_TYPE_STRUCT)
        wanted = DBUS_TYPE_STRUCT;
    else if (type == SD_BUS_TYPE_DICT_ENTRY)
        wanted = DBUS_TYPE_DICT_ENTRY;
    if (actual == DBUS_TYPE_INVALID)
        return 0;
    if (actual != wanted)
        return -ENXIO;
    dbus_message_iter_recurse(parent, &child);
    if (contents && *contents) {
        actual_signature = dbus_message_iter_get_signature(
            actual == DBUS_TYPE_VARIANT ? &child : parent);
        if (!actual_signature)
            return -ENOMEM;
        {
            const char *inner = actual_signature;
            size_t inner_length = strlen(actual_signature);
            size_t contents_length = strlen(contents);
            if (actual == DBUS_TYPE_ARRAY) {
                inner++;
                inner_length--;
            } else if (actual == DBUS_TYPE_STRUCT || actual == DBUS_TYPE_DICT_ENTRY) {
                inner++;
                inner_length -= 2U;
            }
            if (inner_length != contents_length ||
                strncmp(inner, contents, contents_length) != 0) {
                dbus_free(actual_signature);
                return -ENXIO;
            }
        }
        dbus_free(actual_signature);
    }
    ++m->read_depth;
    m->read_stack[m->read_depth] = child;
    return 1;
}

int sd_bus_message_exit_container(sd_bus_message *m) {
    DBusMessageIter *parent;
    if (!m || !m->read_initialized || m->read_depth == 0U)
        return -EINVAL;
    if (dbus_message_iter_get_arg_type(&m->read_stack[m->read_depth]) != DBUS_TYPE_INVALID)
        return -EBUSY;
    --m->read_depth;
    parent = &m->read_stack[m->read_depth];
    dbus_message_iter_next(parent);
    return 1;
}

int sd_bus_message_at_end(sd_bus_message *m, int complete) {
    (void)complete;
    if (!m)
        return -EINVAL;
    return dbus_message_iter_get_arg_type(rustd_read_iter(m)) == DBUS_TYPE_INVALID;
}

int sd_bus_message_skip(sd_bus_message *m, const char *types) {
    DBusMessageIter *iter;
    const char *cursor;
    const char *end;
    int skipped = 0;
    if (!m || !types || !dbus_signature_validate(types, NULL))
        return -EINVAL;
    iter = rustd_read_iter(m);
    cursor = types;
    while (*cursor) {
        if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_INVALID)
            return -ENXIO;
        end = rustd_signature_end(cursor);
        if (!end)
            return -EINVAL;
        dbus_message_iter_next(iter);
        cursor = end;
        ++skipped;
    }
    return skipped;
}

static void rustd_slot_unlink(sd_bus_slot *slot) {
    sd_bus_slot **cursor;
    if (!slot || !slot->bus)
        return;
    cursor = &slot->bus->slots;
    while (*cursor) {
        if (*cursor == slot) {
            *cursor = slot->next;
            slot->next = NULL;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

sd_bus_slot *sd_bus_slot_ref(sd_bus_slot *slot) {
    if (slot)
        ++slot->refs;
    return slot;
}

sd_bus_slot *sd_bus_slot_unref(sd_bus_slot *slot) {
    if (!slot)
        return NULL;
    if (--slot->refs > 0U)
        return NULL;
    rustd_slot_unlink(slot);
    if (slot->pending) {
        dbus_pending_call_cancel(slot->pending);
        dbus_pending_call_unref(slot->pending);
    }
    free(slot->sender);
    free(slot->path);
    free(slot->interface);
    free(slot->member);
    if (slot->match && slot->bus && slot->bus->connection) {
        DBusError error = DBUS_ERROR_INIT;
        dbus_bus_remove_match(slot->bus->connection, slot->match, &error);
        dbus_error_free(&error);
    }
    free(slot->match);
    free(slot);
    return NULL;
}

static sd_bus_slot *rustd_slot_new(sd_bus *bus, enum rustd_slot_kind kind) {
    sd_bus_slot *slot;
    if (!bus)
        return NULL;
    slot = calloc(1, sizeof(*slot));
    if (!slot)
        return NULL;
    slot->refs = 1U;
    slot->kind = kind;
    slot->bus = bus;
    slot->next = bus->slots;
    bus->slots = slot;
    return slot;
}

sd_bus *sd_bus_ref(sd_bus *bus) {
    if (bus)
        ++bus->refs;
    return bus;
}

void sd_bus_close(sd_bus *bus) {
    if (!bus)
        return;
    if (bus->event_source && sd_event_source_unref)
        bus->event_source = sd_event_source_unref(bus->event_source);
    else
        bus->event_source = NULL;
    if (bus->event_timer_source && sd_event_source_unref)
        bus->event_timer_source = sd_event_source_unref(bus->event_timer_source);
    else
        bus->event_timer_source = NULL;
    bus->event = NULL;
    if (bus->connection) {
        dbus_connection_close(bus->connection);
        dbus_connection_unref(bus->connection);
        bus->connection = NULL;
    }
    if (bus->owns_input_fd && bus->input_fd >= 0)
        close(bus->input_fd);
    if (bus->owns_output_fd && bus->output_fd >= 0 && bus->output_fd != bus->input_fd)
        close(bus->output_fd);
    bus->input_fd = -1;
    bus->output_fd = -1;
    bus->owns_input_fd = false;
    bus->owns_output_fd = false;
    bus->started = false;
}

sd_bus *sd_bus_unref(sd_bus *bus) {
    sd_bus_slot *slot;
    if (!bus)
        return NULL;
    if (--bus->refs > 0U)
        return NULL;
    while ((slot = bus->slots) != NULL) {
        bus->slots = slot->next;
        slot->bus = NULL;
        slot->next = NULL;
        sd_bus_slot_unref(slot);
    }
    sd_bus_close(bus);
    free(bus->address);
    free(bus);
    return NULL;
}

int sd_bus_new(sd_bus **ret) {
    sd_bus *bus;
    if (!ret)
        return -EINVAL;
    *ret = NULL;
    bus = calloc(1, sizeof(*bus));
    if (!bus)
        return -ENOMEM;
    bus->refs = 1U;
    bus->input_fd = -1;
    bus->output_fd = -1;
    bus->next_serial = 1U;
    bus->method_call_timeout = UINT64_C(25000000);
    *ret = bus;
    return 0;
}

static DBusHandlerResult rustd_dbus_filter(DBusConnection *connection, DBusMessage *raw, void *userdata) {
    sd_bus *bus = userdata;
    sd_bus_message *message;
    int r;
    (void)connection;
    if (!bus || !raw)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    message = rustd_message_wrap(bus, raw, true);
    if (!message)
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    r = rustd_dispatch_message(bus, message);
    sd_bus_message_unref(message);
    if (r < 0)
        return r == -ENOMEM ? DBUS_HANDLER_RESULT_NEED_MEMORY : DBUS_HANDLER_RESULT_HANDLED;
    return r > 0 ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int rustd_bus_open_kind(sd_bus **ret, DBusBusType type) {
    DBusError error = DBUS_ERROR_INIT;
    DBusConnection *connection;
    sd_bus *bus;
    int r;
    if (!ret)
        return -EINVAL;
    *ret = NULL;
    connection = dbus_bus_get_private(type, &error);
    if (!connection) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        return r;
    }
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
    r = sd_bus_new(&bus);
    if (r < 0) {
        dbus_connection_close(connection);
        dbus_connection_unref(connection);
        return r;
    }
    bus->connection = connection;
    if (!dbus_connection_add_filter(connection, rustd_dbus_filter, bus, NULL)) {
        sd_bus_unref(bus);
        return -ENOMEM;
    }
    bus->started = true;
    *ret = bus;
    return 0;
}

int sd_bus_open_system(sd_bus **ret) {
    return rustd_bus_open_kind(ret, DBUS_BUS_SYSTEM);
}

int sd_bus_open(sd_bus **ret) {
    const char *starter = getenv("DBUS_STARTER_BUS_TYPE");
    return starter && strcmp(starter, "session") == 0
        ? sd_bus_open_user(ret) : sd_bus_open_system(ret);
}

int sd_bus_open_system_remote(sd_bus **ret, const char *host) {
    DBusError error = DBUS_ERROR_INIT;
    DBusConnection *connection;
    sd_bus *bus;
    char address[1024];
    int r;
    if (!ret || !host || !*host || strspn(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@") != strlen(host))
        return -EINVAL;
    if (snprintf(address, sizeof(address),
                 "unixexec:path=ssh,argv1=-x,argv2=%s,argv3=dbus-daemon,argv4=--system,argv5=--nofork",
                 host) >= (int)sizeof(address))
        return -ENAMETOOLONG;
    connection = dbus_connection_open_private(address, &error);
    if (!connection) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        return r;
    }
    if (!dbus_bus_register(connection, &error)) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        dbus_connection_close(connection);
        dbus_connection_unref(connection);
        return r;
    }
    r = sd_bus_new(&bus);
    if (r < 0) {
        dbus_connection_close(connection);
        dbus_connection_unref(connection);
        return r;
    }
    bus->connection = connection;
    bus->started = true;
    dbus_connection_set_exit_on_disconnect(connection, FALSE);
    if (!dbus_connection_add_filter(connection, rustd_dbus_filter, bus, NULL)) {
        sd_bus_unref(bus);
        return -ENOMEM;
    }
    *ret = bus;
    return 0;
}

int sd_bus_open_user(sd_bus **ret) {
    return rustd_bus_open_kind(ret, DBUS_BUS_SESSION);
}

int sd_bus_default_user(sd_bus **ret) {
    return sd_bus_open_user(ret);
}

int sd_bus_default_system(sd_bus **ret) {
    return sd_bus_open_system(ret);
}

sd_bus *sd_bus_flush_close_unref(sd_bus *bus) {
    if (!bus)
        return NULL;
    if (bus->connection)
        dbus_connection_flush(bus->connection);
    sd_bus_close(bus);
    return sd_bus_unref(bus);
}

sd_bus *sd_bus_close_unref(sd_bus *bus) {
    if (bus)
        sd_bus_close(bus);
    return sd_bus_unref(bus);
}

int sd_bus_flush(sd_bus *bus) {
    if (!bus)
        return -EINVAL;
    if (bus->connection)
        dbus_connection_flush(bus->connection);
    return bus->connection || bus->output_fd >= 0 ? 0 : -ENOTCONN;
}

int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec) {
    sd_bus_slot *slot;
    uint64_t nearest = UINT64_MAX;
    if (!bus || !timeout_usec)
        return -EINVAL;
    for (slot = bus->slots; slot; slot = slot->next)
        if (slot->kind == RUSTD_SLOT_ASYNC && slot->pending &&
            !dbus_pending_call_get_completed(slot->pending) &&
            slot->deadline_usec < nearest)
            nearest = slot->deadline_usec;
    *timeout_usec = nearest;
    return 0;
}

int sd_bus_get_method_call_timeout(sd_bus *bus, uint64_t *timeout_usec) {
    if (!bus || !timeout_usec)
        return -EINVAL;
    *timeout_usec = bus->method_call_timeout;
    return 0;
}

int sd_bus_set_method_call_timeout(sd_bus *bus, uint64_t timeout_usec) {
    if (!bus || timeout_usec == 0)
        return -EINVAL;
    bus->method_call_timeout = timeout_usec;
    return 0;
}

int sd_bus_set_address(sd_bus *bus, const char *address) {
    char *copy;
    if (!bus || !address || bus->started || bus->connection)
        return -EINVAL;
    copy = strdup(address);
    if (!copy)
        return -ENOMEM;
    free(bus->address);
    bus->address = copy;
    return 0;
}

int sd_bus_set_bus_client(sd_bus *bus, int b) {
    if (!bus || (b != 0 && b != 1) || bus->started)
        return -EINVAL;
    bus->bus_client = b != 0;
    return 0;
}

int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id) {
    if (!bus || (b != 0 && b != 1) || bus->started)
        return -EINVAL;
    bus->server = b != 0;
    bus->server_id = server_id;
    return 0;
}

int sd_bus_set_trusted(sd_bus *bus, int b) {
    if (!bus || (b != 0 && b != 1) || bus->started)
        return -EINVAL;
    bus->trusted = b != 0;
    return 0;
}

int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
    if (!bus || input_fd < 0 || output_fd < 0 || bus->started || bus->connection)
        return -EINVAL;
    if (fcntl(input_fd, F_GETFD) < 0 || fcntl(output_fd, F_GETFD) < 0)
        return -EBADF;
    bus->input_fd = input_fd;
    bus->output_fd = output_fd;
    bus->owns_input_fd = true;
    bus->owns_output_fd = true;
    return 0;
}

int sd_bus_start(sd_bus *bus) {
    DBusError error = DBUS_ERROR_INIT;
    int r;
    if (!bus)
        return -EINVAL;
    if (bus->started)
        return 0;
    if (!bus->connection && bus->input_fd < 0 && !bus->address)
        return -ENOTCONN;
    if (!bus->connection && bus->address) {
        bus->connection = dbus_connection_open_private(bus->address, &error);
        if (!bus->connection) {
            r = rustd_dbus_error_result(&error);
            dbus_error_free(&error);
            return r;
        }
        dbus_connection_set_exit_on_disconnect(bus->connection, FALSE);
        if (bus->bus_client && !dbus_bus_register(bus->connection, &error)) {
            r = rustd_dbus_error_result(&error);
            dbus_error_free(&error);
            dbus_connection_close(bus->connection);
            dbus_connection_unref(bus->connection);
            bus->connection = NULL;
            return r;
        }
        if (!dbus_connection_add_filter(bus->connection, rustd_dbus_filter, bus, NULL)) {
            dbus_connection_close(bus->connection);
            dbus_connection_unref(bus->connection);
            bus->connection = NULL;
            return -ENOMEM;
        }
    }
    if (!bus->connection) {
        r = bus->server ? rustd_raw_authenticate_server(bus)
                        : rustd_raw_authenticate(bus);
        if (r < 0)
            return r;
    }
    bus->started = true;
    return 0;
}

int sd_bus_get_fd(sd_bus *bus) {
    int fd = -1;
    if (!bus)
        return -EINVAL;
    if (bus->connection) {
        if (!dbus_connection_get_unix_fd(bus->connection, &fd))
            return -ENOTSUP;
        return fd;
    }
    return bus->input_fd >= 0 ? bus->input_fd : -ENOTCONN;
}

int sd_bus_get_events(sd_bus *bus) {
    if (!bus || (!bus->connection && bus->input_fd < 0))
        return -ENOTCONN;
    return POLLIN |
           (bus->connection && dbus_connection_has_messages_to_send(bus->connection)
                ? POLLOUT : 0);
}

int sd_bus_get_n_queued_read(sd_bus *bus, uint64_t *ret) {
    if (!bus || !ret)
        return -EINVAL;
    if (!bus->connection)
        return -ENOTCONN;
    *ret = dbus_connection_get_dispatch_status(bus->connection) ==
           DBUS_DISPATCH_DATA_REMAINS ? 1U : 0U;
    return 0;
}

int sd_bus_get_n_queued_write(sd_bus *bus, uint64_t *ret) {
    if (!bus || !ret)
        return -EINVAL;
    if (!bus->connection)
        return -ENOTCONN;
    *ret = dbus_connection_has_messages_to_send(bus->connection) ? 1U : 0U;
    return 0;
}

int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {
    struct pollfd descriptor;
    int timeout_ms;
    int fd = sd_bus_get_fd(bus);
    int events;
    int result;
    if (fd < 0)
        return fd;
    events = sd_bus_get_events(bus);
    if (events < 0)
        return events;
    descriptor.fd = fd;
    descriptor.events = (short)events;
    descriptor.revents = 0;
    if (timeout_usec == UINT64_MAX)
        timeout_ms = -1;
    else if (timeout_usec / 1000U > (uint64_t)INT_MAX)
        timeout_ms = INT_MAX;
    else
        timeout_ms = (int)((timeout_usec + 999U) / 1000U);
    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    return result < 0 ? -errno : result;
}

static int rustd_bus_event_io(sd_event_source *source, int fd, uint32_t revents,
                              void *userdata) {
    sd_bus *bus = userdata;
    int r;
    (void)source;
    (void)fd;
    (void)revents;
    do {
        r = sd_bus_process(bus, NULL);
    } while (r > 0);
    return r < 0 ? r : 1;
}

static int rustd_bus_update_event_sources(sd_bus *bus);

static int rustd_bus_event_timer(sd_event_source *source, uint64_t usec,
                                 void *userdata) {
    sd_bus *bus = userdata;
    int r;
    (void)source;
    (void)usec;
    r = sd_bus_process(bus, NULL);
    if (r < 0)
        return r;
    r = rustd_bus_update_event_sources(bus);
    return r < 0 ? r : 1;
}

static int rustd_bus_event_prepare(sd_event_source *source, void *userdata) {
    (void)source;
    return rustd_bus_update_event_sources(userdata);
}

static int rustd_bus_update_event_sources(sd_bus *bus) {
    uint64_t timeout;
    int events;
    int r;
    if (!bus || !bus->event)
        return 0;
    events = sd_bus_get_events(bus);
    if (events < 0)
        return events;
    if (bus->event_source && sd_event_source_set_io_events) {
        r = sd_event_source_set_io_events(bus->event_source, (uint32_t)events);
        if (r < 0)
            return r;
    }
    r = sd_bus_get_timeout(bus, &timeout);
    if (r < 0)
        return r;
    if (timeout == UINT64_MAX) {
        if (bus->event_timer_source && sd_event_source_set_enabled)
            return sd_event_source_set_enabled(bus->event_timer_source, 0);
        return 0;
    }
    if (!bus->event_timer_source) {
        if (!sd_event_add_time)
            return -EOPNOTSUPP;
        return sd_event_add_time(bus->event, &bus->event_timer_source,
                                 CLOCK_MONOTONIC, timeout, 0U,
                                 rustd_bus_event_timer, bus);
    }
    if (!sd_event_source_set_time || !sd_event_source_set_enabled)
        return -EOPNOTSUPP;
    r = sd_event_source_set_time(bus->event_timer_source, timeout);
    if (r < 0)
        return r;
    return sd_event_source_set_enabled(bus->event_timer_source, -1);
}

int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority) {
    int fd;
    int r;
    if (!bus || !event)
        return -EINVAL;
    if (!sd_event_add_io || !sd_event_source_set_priority || !sd_event_source_unref ||
        !sd_event_source_set_prepare || !sd_event_source_set_io_events)
        return -EOPNOTSUPP;
    if (bus->event_source)
        return -EBUSY;
    fd = sd_bus_get_fd(bus);
    if (fd < 0)
        return fd;
    r = sd_event_add_io(event, &bus->event_source, fd, POLLIN,
                        rustd_bus_event_io, bus);
    if (r < 0)
        return r;
    r = sd_event_source_set_priority(bus->event_source, priority);
    if (r < 0) {
        bus->event_source = sd_event_source_unref(bus->event_source);
        return r;
    }
    bus->event = event;
    r = sd_event_source_set_prepare(bus->event_source, rustd_bus_event_prepare);
    if (r < 0) {
        bus->event_source = sd_event_source_unref(bus->event_source);
        bus->event = NULL;
        return r;
    }
    return rustd_bus_update_event_sources(bus);
}

int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
    const char *name;
    if (!bus || !unique || !bus->connection)
        return -EINVAL;
    name = dbus_bus_get_unique_name(bus->connection);
    if (!name)
        return -ENODATA;
    *unique = name;
    return 0;
}

sd_bus_message *sd_bus_get_current_message(sd_bus *bus) {
    return bus ? bus->current_message : NULL;
}

int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) {
    DBusError error = DBUS_ERROR_INIT;
    int reply;
    int r;
    if (!bus || !bus->connection || !name)
        return -EINVAL;
    reply = dbus_bus_request_name(bus->connection, name, (unsigned)flags, &error);
    if (dbus_error_is_set(&error)) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        return r;
    }
    return reply == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ||
           reply == DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER ? 1 : 0;
}

int sd_bus_release_name(sd_bus *bus, const char *name) {
    DBusError error = DBUS_ERROR_INIT;
    int reply;
    int r;
    if (!bus || !bus->connection || !name)
        return -EINVAL;
    reply = dbus_bus_release_name(bus->connection, name, &error);
    if (dbus_error_is_set(&error)) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        return r;
    }
    return reply == DBUS_RELEASE_NAME_REPLY_RELEASED ? 1 : 0;
}

int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *cookie) {
    dbus_uint32_t serial = 0;
    if (!m)
        return -EINVAL;
    if (rustd_commit_string_space(m) < 0)
        return -ENOMEM;
    if (!bus)
        bus = m->bus;
    if (!bus)
        return -ENOTCONN;
    if (!bus->connection) {
        char *wire = NULL;
        int wire_length = 0;
        int r;
        if (bus->output_fd < 0 || !bus->started)
            return -ENOTCONN;
        serial = dbus_message_get_serial(m->message);
        if (serial == 0U) {
            serial = bus->next_serial++;
            dbus_message_set_serial(m->message, serial);
        }
        if (!dbus_message_marshal(m->message, &wire, &wire_length))
            return -ENOMEM;
        r = rustd_raw_send_message(bus->output_fd, wire, (size_t)wire_length,
                                   m->unix_fds, m->n_unix_fds, 25000);
        dbus_free(wire);
        if (r < 0)
            return r;
        if (cookie)
            *cookie = serial;
        m->sealed = true;
        return 1;
    }
    if (!dbus_connection_send(bus->connection, m->message, &serial))
        return -ENOMEM;
    if (cookie)
        *cookie = serial;
    m->sealed = true;
    return 1;
}

static int rustd_append_string_array(DBusMessageIter *parent, char **values) {
    DBusMessageIter array;
    size_t i;
    if (!dbus_message_iter_open_container(parent, DBUS_TYPE_ARRAY, "s", &array))
        return -ENOMEM;
    for (i = 0U; values && values[i]; ++i) {
        const char *value = values[i];
        if (!dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &value))
            return -ENOMEM;
    }
    return dbus_message_iter_close_container(parent, &array) ? 0 : -ENOMEM;
}

int sd_bus_emit_properties_changed_strv(sd_bus *bus, const char *path,
                                        const char *interface, char **names) {
    sd_bus_message *message = NULL;
    DBusMessageIter *root;
    DBusMessageIter changed;
    const char *interface_value = interface;
    int r;
    if (!bus || !path || !interface)
        return -EINVAL;
    r = sd_bus_message_new_signal(bus, &message, path,
                                  DBUS_INTERFACE_PROPERTIES, "PropertiesChanged");
    if (r < 0)
        return r;
    root = rustd_append_iter(message);
    if (!dbus_message_iter_append_basic(root, DBUS_TYPE_STRING, &interface_value) ||
        !dbus_message_iter_open_container(root, DBUS_TYPE_ARRAY, "{sv}", &changed) ||
        !dbus_message_iter_close_container(root, &changed))
        r = -ENOMEM;
    else
        r = rustd_append_string_array(root, names);
    if (r >= 0)
        r = sd_bus_send(bus, message, NULL);
    sd_bus_message_unref(message);
    return r;
}

static int rustd_emit_interfaces_added_at(sd_bus *bus, const char *manager_path,
                                          const char *path, char **interfaces) {
    sd_bus_message *message = NULL;
    DBusMessageIter *root;
    DBusMessageIter entries;
    size_t i;
    const char *path_value = path;
    int r;
    if (!bus || !path)
        return -EINVAL;
    r = sd_bus_message_new_signal(bus, &message, manager_path,
                                  "org.freedesktop.DBus.ObjectManager", "InterfacesAdded");
    if (r < 0)
        return r;
    root = rustd_append_iter(message);
    if (!dbus_message_iter_append_basic(root, DBUS_TYPE_OBJECT_PATH, &path_value) ||
        !dbus_message_iter_open_container(root, DBUS_TYPE_ARRAY, "{sa{sv}}", &entries))
        r = -ENOMEM;
    else {
        r = 0;
        for (i = 0U; interfaces && interfaces[i] && r >= 0; ++i) {
            DBusMessageIter entry;
            DBusMessageIter properties;
            const char *name = interfaces[i];
            if (!dbus_message_iter_open_container(&entries, DBUS_TYPE_DICT_ENTRY, NULL, &entry) ||
                !dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name) ||
                !dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sv}", &properties) ||
                !dbus_message_iter_close_container(&entry, &properties) ||
                !dbus_message_iter_close_container(&entries, &entry))
                r = -ENOMEM;
        }
        if (r >= 0 && !dbus_message_iter_close_container(root, &entries))
            r = -ENOMEM;
    }
    if (r >= 0)
        r = sd_bus_send(bus, message, NULL);
    sd_bus_message_unref(message);
    return r;
}

static int rustd_emit_interfaces_removed_at(sd_bus *bus, const char *manager_path,
                                            const char *path, char **interfaces) {
    sd_bus_message *message = NULL;
    DBusMessageIter *root;
    const char *path_value = path;
    int r;
    if (!bus || !path)
        return -EINVAL;
    r = sd_bus_message_new_signal(bus, &message, manager_path,
                                  "org.freedesktop.DBus.ObjectManager", "InterfacesRemoved");
    if (r < 0)
        return r;
    root = rustd_append_iter(message);
    if (!dbus_message_iter_append_basic(root, DBUS_TYPE_OBJECT_PATH, &path_value))
        r = -ENOMEM;
    else
        r = rustd_append_string_array(root, interfaces);
    if (r >= 0)
        r = sd_bus_send(bus, message, NULL);
    sd_bus_message_unref(message);
    return r;
}

int sd_bus_emit_interfaces_added_strv(sd_bus *bus, const char *path, char **interfaces) {
    sd_bus_slot *manager;
    int emitted = 0;
    if (!bus || !path)
        return -EINVAL;
    for (manager = bus->slots; manager; manager = manager->next) {
        int r;
        if (manager->kind != RUSTD_SLOT_MANAGER ||
            !rustd_object_path_below(manager->path, path))
            continue;
        r = rustd_emit_interfaces_added_at(bus, manager->path, path, interfaces);
        if (r < 0)
            return r;
        emitted++;
    }
    return emitted > 0 ? emitted : -ESRCH;
}

int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces) {
    sd_bus_slot *manager;
    int emitted = 0;
    if (!bus || !path)
        return -EINVAL;
    for (manager = bus->slots; manager; manager = manager->next) {
        int r;
        if (manager->kind != RUSTD_SLOT_MANAGER ||
            !rustd_object_path_below(manager->path, path))
            continue;
        r = rustd_emit_interfaces_removed_at(bus, manager->path, path, interfaces);
        if (r < 0)
            return r;
        emitted++;
    }
    return emitted > 0 ? emitted : -ESRCH;
}

static int rustd_bus_emit_object(sd_bus *bus, const char *path, bool added) {
    sd_bus_slot *slot;
    char **interfaces = NULL;
    size_t count = 0U;
    int r;
    if (!bus || !path)
        return -EINVAL;
    for (slot = bus->slots; slot; slot = slot->next)
        if (slot->kind == RUSTD_SLOT_OBJECT && slot->path && slot->interface &&
            strcmp(slot->path, path) == 0)
            count++;
    interfaces = calloc(count + 1U, sizeof(*interfaces));
    if (!interfaces)
        return -ENOMEM;
    count = 0U;
    for (slot = bus->slots; slot; slot = slot->next)
        if (slot->kind == RUSTD_SLOT_OBJECT && slot->path && slot->interface &&
            strcmp(slot->path, path) == 0)
            interfaces[count++] = slot->interface;
    r = added ? sd_bus_emit_interfaces_added_strv(bus, path, interfaces)
              : sd_bus_emit_interfaces_removed_strv(bus, path, interfaces);
    free(interfaces);
    return r;
}

int sd_bus_emit_object_added(sd_bus *bus, const char *path) {
    return rustd_bus_emit_object(bus, path, true);
}

int sd_bus_emit_object_removed(sd_bus *bus, const char *path) {
    return rustd_bus_emit_object(bus, path, false);
}

static bool rustd_message_matches_slot(sd_bus_message *m, const sd_bus_slot *slot) {
    if (!m || !slot)
        return false;
    if (slot->sender) {
        const char *sender = dbus_message_get_sender(m->message);
        if (!sender || strcmp(sender, slot->sender) != 0)
            return false;
    }
    if (slot->path) {
        const char *path = dbus_message_get_path(m->message);
        if (!path || strcmp(path, slot->path) != 0)
            return false;
    }
    if (slot->interface) {
        const char *interface = dbus_message_get_interface(m->message);
        if (!interface || strcmp(interface, slot->interface) != 0)
            return false;
    }
    if (slot->member) {
        const char *member = dbus_message_get_member(m->message);
        if (!member || strcmp(member, slot->member) != 0)
            return false;
    }
    return true;
}

static bool rustd_match_rule_field(const char *rule, const char *key, const char *actual) {
    char needle[64];
    const char *start;
    const char *end;
    size_t length;
    snprintf(needle, sizeof(needle), "%s='", key);
    start = strstr(rule, needle);
    if (!start)
        return true;
    start += strlen(needle);
    end = strchr(start, '\'');
    if (!end || !actual)
        return false;
    length = (size_t)(end - start);
    return strlen(actual) == length && strncmp(start, actual, length) == 0;
}

static bool rustd_message_matches_rule(sd_bus_message *m, const char *rule) {
    const char *type = NULL;
    switch (dbus_message_get_type(m->message)) {
    case DBUS_MESSAGE_TYPE_SIGNAL: type = "signal"; break;
    case DBUS_MESSAGE_TYPE_METHOD_CALL: type = "method_call"; break;
    case DBUS_MESSAGE_TYPE_METHOD_RETURN: type = "method_return"; break;
    case DBUS_MESSAGE_TYPE_ERROR: type = "error"; break;
    default: break;
    }
    return rustd_match_rule_field(rule, "type", type) &&
           rustd_match_rule_field(rule, "sender", dbus_message_get_sender(m->message)) &&
           rustd_match_rule_field(rule, "path", dbus_message_get_path(m->message)) &&
           rustd_match_rule_field(rule, "interface", dbus_message_get_interface(m->message)) &&
           rustd_match_rule_field(rule, "member", dbus_message_get_member(m->message));
}

static int rustd_dispatch_object(sd_bus *bus, sd_bus_slot *slot, sd_bus_message *m) {
    const sd_bus_vtable *v;
    const char *member;
    const char *interface;
    const char *path;
    if (!slot->vtable || !dbus_message_get_member(m->message))
        return 0;
    path = dbus_message_get_path(m->message);
    interface = dbus_message_get_interface(m->message);
    member = dbus_message_get_member(m->message);
    if (!path || !slot->path || strcmp(path, slot->path) != 0)
        return 0;
    if (slot->interface && (!interface || strcmp(interface, slot->interface) != 0))
        return 0;
    for (v = slot->vtable; v->type != _SD_BUS_VTABLE_END; ++v) {
        if (v->type != _SD_BUS_VTABLE_METHOD || !v->x.method.member ||
            strcmp(v->x.method.member, member) != 0)
            continue;
        if (v->x.method.handler) {
            sd_bus_error error = SD_BUS_ERROR_NULL;
            void *userdata = slot->userdata;
            int r;
            if (userdata && !(v->flags & SD_BUS_VTABLE_ABSOLUTE_OFFSET))
                userdata = (uint8_t *)userdata + v->x.method.offset;
            else if (!userdata || (v->flags & SD_BUS_VTABLE_ABSOLUTE_OFFSET))
                userdata = (void *)(uintptr_t)v->x.method.offset;
            r = v->x.method.handler(m, userdata, &error);
            sd_bus_error_free(&error);
            return r;
        }
    }
    (void)bus;
    return 0;
}

static int rustd_append_object_properties(sd_bus *bus, sd_bus_slot *slot,
                                          sd_bus_message *reply) {
    const sd_bus_vtable *v;
    int r;
    r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
    if (r < 0)
        return r;
    for (v = slot->vtable; v && v->type != _SD_BUS_VTABLE_END; ++v) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        void *userdata;
        if ((v->type != _SD_BUS_VTABLE_PROPERTY &&
             v->type != _SD_BUS_VTABLE_WRITABLE_PROPERTY) ||
            !v->x.property.member || !v->x.property.signature || !v->x.property.get)
            continue;
        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv");
        if (r < 0)
            return r;
        r = sd_bus_message_append(reply, "s", v->x.property.member);
        if (r < 0)
            return r;
        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_VARIANT,
                                          v->x.property.signature);
        if (r < 0)
            return r;
        userdata = slot->userdata;
        if (userdata && !(v->flags & SD_BUS_VTABLE_ABSOLUTE_OFFSET))
            userdata = (uint8_t *)userdata + v->x.property.offset;
        else if (!userdata || (v->flags & SD_BUS_VTABLE_ABSOLUTE_OFFSET))
            userdata = (void *)(uintptr_t)v->x.property.offset;
        r = v->x.property.get(bus, slot->path, slot->interface,
                              v->x.property.member, reply, userdata, &error);
        sd_bus_error_free(&error);
        if (r < 0)
            return r;
        r = sd_bus_message_close_container(reply);
        if (r < 0)
            return r;
        r = sd_bus_message_close_container(reply);
        if (r < 0)
            return r;
    }
    return sd_bus_message_close_container(reply);
}

static bool rustd_object_path_below(const char *manager, const char *path) {
    size_t length;
    if (!manager || !path)
        return false;
    length = strlen(manager);
    if (strncmp(manager, path, length) != 0)
        return false;
    return length == 1U || path[length] == '\0' || path[length] == '/';
}

static int rustd_dispatch_object_manager(sd_bus *bus, sd_bus_slot *manager,
                                         sd_bus_message *call) {
    sd_bus_message *reply = NULL;
    sd_bus_slot *object;
    int r;
    if (!manager->path ||
        !dbus_message_has_path(call->message, manager->path) ||
        !dbus_message_has_interface(call->message,
                                    "org.freedesktop.DBus.ObjectManager") ||
        !dbus_message_has_member(call->message, "GetManagedObjects"))
        return 0;
    r = sd_bus_message_new_method_return(call, &reply);
    if (r < 0)
        return r;
    r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}");
    for (object = bus->slots; r >= 0 && object; object = object->next) {
        sd_bus_slot *earlier;
        sd_bus_slot *interface_slot;
        bool duplicate = false;
        if (object->kind != RUSTD_SLOT_OBJECT || !object->path ||
            !rustd_object_path_below(manager->path, object->path))
            continue;
        for (earlier = bus->slots; earlier && earlier != object; earlier = earlier->next)
            if (earlier->kind == RUSTD_SLOT_OBJECT && earlier->path &&
                strcmp(earlier->path, object->path) == 0) {
                duplicate = true;
                break;
            }
        if (duplicate)
            continue;
        r = sd_bus_message_open_container(reply, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}");
        if (r >= 0)
            r = sd_bus_message_append(reply, "o", object->path);
        if (r >= 0)
            r = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}");
        for (interface_slot = bus->slots; r >= 0 && interface_slot;
             interface_slot = interface_slot->next) {
            if (interface_slot->kind != RUSTD_SLOT_OBJECT ||
                !interface_slot->path || !interface_slot->interface ||
                strcmp(interface_slot->path, object->path) != 0)
                continue;
            r = sd_bus_message_open_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}");
            if (r >= 0)
                r = sd_bus_message_append(reply, "s", interface_slot->interface);
            if (r >= 0)
                r = rustd_append_object_properties(bus, interface_slot, reply);
            if (r >= 0)
                r = sd_bus_message_close_container(reply);
        }
        if (r >= 0)
            r = sd_bus_message_close_container(reply);
        if (r >= 0)
            r = sd_bus_message_close_container(reply);
    }
    if (r >= 0)
        r = sd_bus_message_close_container(reply);
    if (r >= 0)
        r = sd_bus_send(bus, reply, NULL);
    sd_bus_message_unref(reply);
    return r < 0 ? r : 1;
}

static int rustd_dispatch_message(sd_bus *bus, sd_bus_message *m) {
    sd_bus_slot *slot;
    sd_bus_message *previous;
    int handled = 0;
    previous = bus->current_message;
    bus->current_message = m;
    for (slot = bus->slots; slot; slot = slot->next) {
        int r = 0;
        if (slot->kind == RUSTD_SLOT_FILTER && slot->callback)
            r = slot->callback(m, slot->userdata, NULL);
        else if (slot->kind == RUSTD_SLOT_MATCH && slot->callback &&
                 ((slot->match && rustd_message_matches_rule(m, slot->match)) ||
                  (!slot->match && rustd_message_matches_slot(m, slot))))
            r = slot->callback(m, slot->userdata, NULL);
        else if (slot->kind == RUSTD_SLOT_OBJECT && dbus_message_get_type(m->message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
            r = rustd_dispatch_object(bus, slot, m);
        else if (slot->kind == RUSTD_SLOT_MANAGER &&
                 dbus_message_get_type(m->message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
            r = rustd_dispatch_object_manager(bus, slot, m);
        if (r < 0) {
            bus->current_message = previous;
            return r;
        }
        if (r > 0)
            handled = 1;
    }
    bus->current_message = previous;
    return handled;
}

int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
    DBusDispatchStatus before;
    DBusDispatchStatus after;
    if (ret)
        *ret = NULL;
    if (!bus)
        return -EINVAL;
    if (!bus->connection) {
        DBusMessage *raw = NULL;
        sd_bus_message *message;
        int r;
        if (bus->input_fd < 0)
            return -ENOTCONN;
        r = rustd_raw_receive_message(bus->input_fd, 0, &raw);
        if (r == -ETIMEDOUT || r == -EAGAIN || r == -EWOULDBLOCK)
            return 0;
        if (r < 0)
            return r;
        message = rustd_message_wrap(bus, raw, false);
        if (!message) {
            dbus_message_unref(raw);
            return -ENOMEM;
        }
        r = rustd_dispatch_message(bus, message);
        if (ret) {
            ++message->refs;
            *ret = message;
        }
        sd_bus_message_unref(message);
        return r < 0 ? r : 1;
    }
    before = dbus_connection_get_dispatch_status(bus->connection);
    if (before == DBUS_DISPATCH_NEED_MEMORY)
        return -ENOMEM;
    if (!dbus_connection_read_write_dispatch(bus->connection, 0))
        return -ECONNRESET;
    after = dbus_connection_get_dispatch_status(bus->connection);
    if (after == DBUS_DISPATCH_NEED_MEMORY)
        return -ENOMEM;
    return (before == DBUS_DISPATCH_DATA_REMAINS || after == DBUS_DISPATCH_DATA_REMAINS) ? 1 : 0;
}

int sd_bus_add_filter(sd_bus *bus, sd_bus_slot **ret_slot, sd_bus_message_handler_t callback, void *userdata) {
    sd_bus_slot *slot;
    if (!bus || !callback)
        return -EINVAL;
    slot = rustd_slot_new(bus, RUSTD_SLOT_FILTER);
    if (!slot)
        return -ENOMEM;
    slot->callback = callback;
    slot->userdata = userdata;
    if (ret_slot)
        *ret_slot = slot;
    return 0;
}

static int rustd_bus_add_match(sd_bus *bus, sd_bus_slot **ret, const char *match,
                               sd_bus_message_handler_t callback,
                               sd_bus_message_handler_t install_callback,
                               void *userdata) {
    DBusError error = DBUS_ERROR_INIT;
    sd_bus_slot *slot;
    int r;
    if (!bus || !match || !callback)
        return -EINVAL;
    if (bus->connection) {
        dbus_bus_add_match(bus->connection, match, &error);
        if (dbus_error_is_set(&error)) {
            r = rustd_dbus_error_result(&error);
            dbus_error_free(&error);
            return r;
        }
        dbus_connection_flush(bus->connection);
    }
    slot = rustd_slot_new(bus, RUSTD_SLOT_MATCH);
    if (!slot)
        return -ENOMEM;
    slot->match = strdup(match);
    if (!slot->match) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    slot->callback = callback;
    slot->install_callback = install_callback;
    slot->userdata = userdata;
    if (ret)
        *ret = slot;
    if (install_callback) {
        r = install_callback(NULL, userdata, NULL);
        if (r < 0) {
            if (ret)
                *ret = NULL;
            sd_bus_slot_unref(slot);
            return r;
        }
    }
    return 0;
}

int sd_bus_add_match(sd_bus *bus, sd_bus_slot **ret, const char *match,
                     sd_bus_message_handler_t callback, void *userdata) {
    return rustd_bus_add_match(bus, ret, match, callback, NULL, userdata);
}

int sd_bus_add_match_async(sd_bus *bus, sd_bus_slot **ret, const char *match,
                           sd_bus_message_handler_t callback,
                           sd_bus_message_handler_t install_callback, void *userdata) {
    return rustd_bus_add_match(bus, ret, match, callback, install_callback, userdata);
}

int sd_bus_add_object_manager(sd_bus *bus, sd_bus_slot **ret, const char *path) {
    sd_bus_slot *slot;
    if (!bus || !path || !sd_bus_object_path_is_valid(path))
        return -EINVAL;
    slot = rustd_slot_new(bus, RUSTD_SLOT_MANAGER);
    if (!slot)
        return -ENOMEM;
    slot->path = strdup(path);
    if (!slot->path) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    if (ret)
        *ret = slot;
    return 0;
}

static int rustd_match_signal(sd_bus *bus, sd_bus_slot **ret, const char *sender, const char *path,
                              const char *interface, const char *member,
                              sd_bus_message_handler_t callback,
                              sd_bus_message_handler_t install_callback, void *userdata) {
    sd_bus_slot *slot;
    DBusError error = DBUS_ERROR_INIT;
    char rule[2048];
    size_t used = 0U;
    if (!bus || !callback)
        return -EINVAL;
    used += (size_t)snprintf(rule + used, sizeof(rule) - used, "type='signal'");
#define ADD_MATCH_FIELD(name_, value_) do { \
        if ((value_)) \
            used += (size_t)snprintf(rule + used, sizeof(rule) - used, "," name_ "='%s'", (value_)); \
    } while (0)
    ADD_MATCH_FIELD("sender", sender);
    ADD_MATCH_FIELD("path", path);
    ADD_MATCH_FIELD("interface", interface);
    ADD_MATCH_FIELD("member", member);
#undef ADD_MATCH_FIELD
    if (used >= sizeof(rule))
        return -ENOBUFS;
    if (bus->connection) {
        dbus_bus_add_match(bus->connection, rule, &error);
        dbus_connection_flush(bus->connection);
        if (dbus_error_is_set(&error)) {
            int r = rustd_dbus_error_result(&error);
            dbus_error_free(&error);
            return r;
        }
    }
    slot = rustd_slot_new(bus, RUSTD_SLOT_MATCH);
    if (!slot)
        return -ENOMEM;
    slot->callback = callback;
    slot->install_callback = install_callback;
    slot->userdata = userdata;
    slot->sender = sender ? strdup(sender) : NULL;
    slot->path = path ? strdup(path) : NULL;
    slot->interface = interface ? strdup(interface) : NULL;
    slot->member = member ? strdup(member) : NULL;
    if ((sender && !slot->sender) || (path && !slot->path) || (interface && !slot->interface) ||
        (member && !slot->member)) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    if (ret)
        *ret = slot;
    if (install_callback) {
        int r = install_callback(NULL, userdata, NULL);
        if (r < 0)
            return r;
    }
    return 0;
}

int sd_bus_match_signal(sd_bus *bus, sd_bus_slot **ret, const char *sender, const char *path,
                        const char *interface, const char *member,
                        sd_bus_message_handler_t callback, void *userdata) {
    return rustd_match_signal(bus, ret, sender, path, interface, member, callback, NULL, userdata);
}

int sd_bus_match_signal_async(sd_bus *bus, sd_bus_slot **ret, const char *sender, const char *path,
                              const char *interface, const char *member,
                              sd_bus_message_handler_t match_callback,
                              sd_bus_message_handler_t install_callback, void *userdata) {
    return rustd_match_signal(bus, ret, sender, path, interface, member,
                              match_callback, install_callback, userdata);
}

int sd_bus_add_object_vtable(sd_bus *bus, sd_bus_slot **ret_slot, const char *path,
                             const char *interface, const sd_bus_vtable *vtable, void *userdata) {
    sd_bus_slot *slot;
    if (!bus || !path || !interface || !vtable || !dbus_validate_path(path, NULL) ||
        !dbus_validate_interface(interface, NULL))
        return -EINVAL;
    slot = rustd_slot_new(bus, RUSTD_SLOT_OBJECT);
    if (!slot)
        return -ENOMEM;
    slot->path = strdup(path);
    slot->interface = strdup(interface);
    slot->vtable = vtable;
    slot->userdata = userdata;
    if (!slot->path || !slot->interface) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    if (ret_slot)
        *ret_slot = slot;
    return 0;
}

int sd_bus_message_new_method_call(sd_bus *bus, sd_bus_message **ret, const char *destination,
                                   const char *path, const char *interface, const char *member) {
    DBusMessage *message;
    sd_bus_message *wrapped;
    if (!ret || !path || !interface || !member)
        return -EINVAL;
    *ret = NULL;
    message = dbus_message_new_method_call(destination, path, interface, member);
    if (!message)
        return -ENOMEM;
    wrapped = rustd_message_wrap(bus, message, false);
    if (!wrapped) {
        dbus_message_unref(message);
        return -ENOMEM;
    }
    *ret = wrapped;
    return 0;
}

int sd_bus_message_new(sd_bus *bus, sd_bus_message **ret, uint8_t type) {
    DBusMessage *message;
    sd_bus_message *wrapped;
    if (!ret || type < DBUS_MESSAGE_TYPE_METHOD_CALL || type > DBUS_MESSAGE_TYPE_SIGNAL)
        return -EINVAL;
    *ret = NULL;
    message = dbus_message_new(type);
    if (!message)
        return -ENOMEM;
    wrapped = rustd_message_wrap(bus, message, false);
    if (!wrapped) {
        dbus_message_unref(message);
        return -ENOMEM;
    }
    *ret = wrapped;
    return 0;
}

int sd_bus_message_new_signal(sd_bus *bus, sd_bus_message **ret, const char *path,
                              const char *interface, const char *member) {
    DBusMessage *message;
    sd_bus_message *wrapped;
    if (!ret || !path || !interface || !member)
        return -EINVAL;
    *ret = NULL;
    message = dbus_message_new_signal(path, interface, member);
    if (!message)
        return -ENOMEM;
    wrapped = rustd_message_wrap(bus, message, false);
    if (!wrapped) {
        dbus_message_unref(message);
        return -ENOMEM;
    }
    *ret = wrapped;
    return 0;
}

int sd_bus_message_new_method_return(sd_bus_message *call, sd_bus_message **ret) {
    DBusMessage *message;
    if (!call || !ret)
        return -EINVAL;
    message = dbus_message_new_method_return(call->message);
    if (!message)
        return -ENOMEM;
    *ret = rustd_message_wrap(call->bus, message, false);
    if (!*ret) {
        dbus_message_unref(message);
        return -ENOMEM;
    }
    return 0;
}

int sd_bus_message_new_method_error(sd_bus_message *call, sd_bus_message **ret,
                                    const sd_bus_error *error) {
    DBusMessage *message;
    if (!call || !ret || !error || !error->name)
        return -EINVAL;
    message = dbus_message_new_error(call->message, error->name,
                                     error->message ? error->message : "");
    if (!message)
        return -ENOMEM;
    *ret = rustd_message_wrap(call->bus, message, false);
    if (!*ret) {
        dbus_message_unref(message);
        return -ENOMEM;
    }
    return 0;
}

sd_bus_message *sd_bus_message_ref(sd_bus_message *m) {
    if (m)
        m->refs++;
    return m;
}

sd_bus_message *sd_bus_message_unref(sd_bus_message *m) {
    if (!m)
        return NULL;
    if (--m->refs > 0U)
        return NULL;
    sd_bus_error_free(&m->cached_error);
    if (m->message)
        dbus_message_unref(m->message);
    if (m->bus)
        sd_bus_unref(m->bus);
    for (unsigned i = 0; i < m->n_unix_fds; ++i)
        close(m->unix_fds[i]);
    free(m->string_space);
    free(m->peek_contents);
    free(m);
    return NULL;
}

const char *sd_bus_message_get_path(sd_bus_message *m) {
    return m ? dbus_message_get_path(m->message) : NULL;
}

const char *sd_bus_message_get_interface(sd_bus_message *m) {
    return m ? dbus_message_get_interface(m->message) : NULL;
}

const char *sd_bus_message_get_member(sd_bus_message *m) {
    return m ? dbus_message_get_member(m->message) : NULL;
}

const char *sd_bus_message_get_destination(sd_bus_message *m) {
    return m ? dbus_message_get_destination(m->message) : NULL;
}

const char *sd_bus_message_get_sender(sd_bus_message *m) {
    return m ? dbus_message_get_sender(m->message) : NULL;
}

int sd_bus_message_get_cookie(sd_bus_message *m, uint64_t *cookie) {
    if (!m || !cookie)
        return -EINVAL;
    *cookie = dbus_message_get_serial(m->message);
    return *cookie ? 0 : -ENODATA;
}

int sd_bus_message_get_reply_cookie(sd_bus_message *m, uint64_t *cookie) {
    if (!m || !cookie)
        return -EINVAL;
    *cookie = dbus_message_get_reply_serial(m->message);
    return *cookie ? 0 : -ENODATA;
}

int sd_bus_message_get_expect_reply(sd_bus_message *m) {
    if (!m)
        return -EINVAL;
    return !dbus_message_get_no_reply(m->message);
}

int sd_bus_message_set_expect_reply(sd_bus_message *m, int b) {
    if (!m || (b != 0 && b != 1))
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    dbus_message_set_no_reply(m->message, !b);
    return 0;
}

int sd_bus_message_set_destination(sd_bus_message *m, const char *destination) {
    if (!m || !destination)
        return -EINVAL;
    if (m->sealed)
        return -EPERM;
    return dbus_message_set_destination(m->message, destination) ? 0 : -ENOMEM;
}

int sd_bus_message_is_empty(sd_bus_message *m) {
    DBusMessageIter iter;
    int r;
    if (!m)
        return -EINVAL;
    r = rustd_commit_string_space(m);
    if (r < 0)
        return r;
    return !dbus_message_iter_init(m->message, &iter);
}

int sd_bus_message_rewind(sd_bus_message *m, int complete) {
    (void)complete;
    if (!m)
        return -EINVAL;
    m->read_initialized = false;
    m->read_depth = 0U;
    return 1;
}

int sd_bus_message_seal(sd_bus_message *m, uint64_t cookie, uint64_t timeout_usec) {
    (void)timeout_usec;
    if (!m || cookie > UINT32_MAX)
        return -EINVAL;
    if (rustd_commit_string_space(m) < 0)
        return -ENOMEM;
    if (cookie != 0)
        dbus_message_set_serial(m->message, (dbus_uint32_t)cookie);
    if (dbus_message_get_serial(m->message) == 0 && m->bus)
        dbus_message_set_serial(m->message, m->bus->next_serial++);
    m->sealed = true;
    return 0;
}

const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
    const char *name;
    DBusMessageIter iter;
    const char *text = NULL;
    if (!m || dbus_message_get_type(m->message) != DBUS_MESSAGE_TYPE_ERROR)
        return NULL;
    name = dbus_message_get_error_name(m->message);
    if (!name)
        return NULL;
    m->cached_error.name = name;
    m->cached_error.message = NULL;
    m->cached_error._need_free = 0;
    if (dbus_message_iter_init(m->message, &iter) && dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
        dbus_message_iter_get_basic(&iter, &text);
        m->cached_error.message = text;
    }
    return &m->cached_error;
}

int sd_bus_message_get_errno(sd_bus_message *m) {
    const sd_bus_error *error = sd_bus_message_get_error(m);
    return error ? sd_bus_error_get_errno(error) : 0;
}

sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *creds);

static void rustd_creds_read_proc(sd_bus_creds *creds) {
    char path[64];
    char *line = NULL;
    size_t capacity = 0U;
    FILE *file;
    if (!creds || creds->pid <= 0)
        return;
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)creds->pid);
    file = fopen(path, "re");
    if (!file)
        return;
    while (getline(&line, &capacity, file) >= 0) {
        unsigned real_id;
        unsigned effective_id;
        if (sscanf(line, "Uid:\t%u\t%u", &real_id, &effective_id) == 2) {
            creds->uid = (uid_t)real_id;
            creds->euid = (uid_t)effective_id;
            creds->mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID;
        } else if (sscanf(line, "Gid:\t%u\t%u", &real_id, &effective_id) == 2) {
            creds->gid = (gid_t)real_id;
            creds->egid = (gid_t)effective_id;
            creds->mask |= SD_BUS_CREDS_GID | SD_BUS_CREDS_EGID;
        } else if (strncmp(line, "Groups:", 7U) == 0) {
            char *cursor = line + 7U;
            gid_t *groups = NULL;
            int count = 0;
            while (*cursor) {
                char *end;
                unsigned long value;
                while (*cursor == ' ' || *cursor == '\t')
                    cursor++;
                if (*cursor == '\0' || *cursor == '\n')
                    break;
                errno = 0;
                value = strtoul(cursor, &end, 10);
                if (errno || end == cursor || value > UINT_MAX)
                    break;
                gid_t *grown = realloc(groups, (size_t)(count + 1) * sizeof(*groups));
                if (!grown) {
                    free(groups);
                    groups = NULL;
                    count = 0;
                    break;
                }
                groups = grown;
                groups[count++] = (gid_t)value;
                cursor = end;
            }
            creds->supplementary_gids = groups;
            creds->n_supplementary_gids = count;
            creds->mask |= SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
        }
    }
    free(line);
    fclose(file);
    snprintf(path, sizeof(path), "/proc/%ld/attr/current", (long)creds->pid);
    file = fopen(path, "re");
    if (file) {
        line = NULL;
        capacity = 0U;
        if (getline(&line, &capacity, file) >= 0) {
            line[strcspn(line, "\r\n")] = '\0';
            creds->selinux_context = line;
            creds->mask |= SD_BUS_CREDS_SELINUX_CONTEXT;
            line = NULL;
        }
        free(line);
        fclose(file);
    }
}

int sd_bus_query_sender_creds(sd_bus_message *m, uint64_t requested, sd_bus_creds **ret) {
    const char *sender;
    sd_bus_message *reply = NULL;
    sd_bus_creds *creds;
    uint32_t pid = 0;
    unsigned long uid;
    int r;
    if (!m || !m->bus || !m->bus->connection || !ret)
        return -EINVAL;
    *ret = NULL;
    sender = dbus_message_get_sender(m->message);
    if (!sender)
        return -ENODATA;
    creds = calloc(1, sizeof(*creds));
    if (!creds)
        return -ENOMEM;
    creds->refs = 1U;
    if (requested & SD_BUS_CREDS_PID) {
        r = sd_bus_call_method(m->bus, DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
                               DBUS_INTERFACE_DBUS, "GetConnectionUnixProcessID",
                               NULL, &reply, "s", sender);
        if (r >= 0 && reply && sd_bus_message_read(reply, "u", &pid) > 0) {
            creds->pid = (pid_t)pid;
            creds->mask |= SD_BUS_CREDS_PID;
        }
        sd_bus_message_unref(reply);
        reply = NULL;
    }
    uid = dbus_bus_get_unix_user(m->bus->connection, sender, NULL);
    if (uid != (unsigned long)-1) {
        creds->uid = (uid_t)uid;
        creds->euid = (uid_t)uid;
        creds->mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID;
    }
    rustd_creds_read_proc(creds);
    if ((requested & creds->mask) != requested) {
        sd_bus_creds_unref(creds);
        return -ENODATA;
    }
    *ret = creds;
    return 0;
}

sd_bus_creds *sd_bus_creds_ref(sd_bus_creds *creds) {
    if (creds)
        creds->refs++;
    return creds;
}

sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *creds) {
    if (!creds || --creds->refs > 0U)
        return NULL;
    free(creds->supplementary_gids);
    free(creds->selinux_context);
    free(creds);
    return NULL;
}

int sd_bus_creds_get_pid(sd_bus_creds *creds, pid_t *ret) {
    if (!creds || !ret) return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_PID)) return -ENODATA;
    *ret = creds->pid;
    return 0;
}

int sd_bus_creds_get_uid(sd_bus_creds *creds, uid_t *ret) {
    if (!creds || !ret) return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_UID)) return -ENODATA;
    *ret = creds->uid;
    return 0;
}

int sd_bus_creds_get_euid(sd_bus_creds *creds, uid_t *ret) {
    if (!creds || !ret) return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_EUID)) return -ENODATA;
    *ret = creds->euid;
    return 0;
}

int sd_bus_creds_get_gid(sd_bus_creds *creds, gid_t *ret) {
    if (!creds || !ret) return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_GID)) return -ENODATA;
    *ret = creds->gid;
    return 0;
}

int sd_bus_creds_get_egid(sd_bus_creds *creds, gid_t *ret) {
    if (!creds || !ret) return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_EGID)) return -ENODATA;
    *ret = creds->egid;
    return 0;
}

int sd_bus_creds_get_supplementary_gids(sd_bus_creds *creds, const gid_t **ret) {
    if (!creds || !ret)
        return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_SUPPLEMENTARY_GIDS))
        return -ENODATA;
    *ret = creds->supplementary_gids;
    return creds->n_supplementary_gids;
}

int sd_bus_creds_get_selinux_context(sd_bus_creds *creds, const char **ret) {
    if (!creds || !ret)
        return -EINVAL;
    if (!(creds->mask & SD_BUS_CREDS_SELINUX_CONTEXT))
        return -ENODATA;
    *ret = creds->selinux_context;
    return 0;
}

int sd_bus_message_is_signal(sd_bus_message *m, const char *interface, const char *member) {
    if (!m || dbus_message_get_type(m->message) != DBUS_MESSAGE_TYPE_SIGNAL)
        return 0;
    if (interface && !dbus_message_has_interface(m->message, interface))
        return 0;
    if (member && (!dbus_message_get_member(m->message) || strcmp(dbus_message_get_member(m->message), member) != 0))
        return 0;
    return 1;
}

static int rustd_raw_wait(int fd, short events, int timeout) {
    struct pollfd descriptor = {.fd = fd, .events = events, .revents = 0};
    int r;
    do
        r = poll(&descriptor, 1, timeout);
    while (r < 0 && errno == EINTR);
    if (r < 0)
        return -errno;
    if (r == 0)
        return -ETIMEDOUT;
    if (descriptor.revents & (POLLERR | POLLNVAL))
        return -EIO;
    if (descriptor.revents & POLLHUP)
        return -ECONNRESET;
    return 0;
}

static int rustd_raw_write_all(int fd, const void *data, size_t length, int timeout) {
    const unsigned char *cursor = data;
    while (length > 0U) {
        ssize_t written = send(fd, cursor, length, MSG_NOSIGNAL);
        if (written > 0) {
            cursor += (size_t)written;
            length -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int r = rustd_raw_wait(fd, POLLOUT, timeout);
            if (r < 0)
                return r;
            continue;
        }
        return written == 0 ? -ECONNRESET : -errno;
    }
    return 0;
}

static int rustd_raw_send_message(int fd, const void *data, size_t length,
                                  const int *fds, unsigned n_fds, int timeout) {
    union {
        struct cmsghdr header;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 64U)];
    } control;
    struct iovec iov = {.iov_base = (void *)data, .iov_len = length};
    struct msghdr message;
    ssize_t written;
    if (n_fds == 0U)
        return rustd_raw_write_all(fd, data, length, timeout);
    if (!fds || n_fds > 64U)
        return -EINVAL;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * n_fds);
    {
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * n_fds);
    }
    do
        written = sendmsg(fd, &message, MSG_NOSIGNAL);
    while (written < 0 && errno == EINTR);
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        int r = rustd_raw_wait(fd, POLLOUT, timeout);
        if (r < 0)
            return r;
        return rustd_raw_send_message(fd, data, length, fds, n_fds, timeout);
    }
    if (written <= 0)
        return written == 0 ? -ECONNRESET : -errno;
    return rustd_raw_write_all(fd, (const unsigned char *)data + (size_t)written,
                               length - (size_t)written, timeout);
}

static int rustd_raw_read_all(int fd, void *data, size_t length, int timeout) {
    unsigned char *cursor = data;
    while (length > 0U) {
        ssize_t received = recv(fd, cursor, length, 0);
        if (received > 0) {
            cursor += (size_t)received;
            length -= (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int r = rustd_raw_wait(fd, POLLIN, timeout);
            if (r < 0)
                return r;
            continue;
        }
        return received == 0 ? -ECONNRESET : -errno;
    }
    return 0;
}

static int rustd_raw_authenticate(sd_bus *bus) {
    static const unsigned char request[] =
        "\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    unsigned char response[4096];
    size_t used = 0U;
    int r;
    if (!bus || bus->input_fd < 0 || bus->output_fd < 0)
        return -ENOTCONN;
    r = rustd_raw_write_all(bus->output_fd, request, sizeof(request) - 1U, 25000);
    if (r < 0)
        return r;
    while (used < sizeof(response) - 1U) {
        ssize_t received = recv(bus->input_fd, response + used,
                                sizeof(response) - 1U - used, 0);
        if (received > 0) {
            used += (size_t)received;
            response[used] = 0;
            if (strstr((const char *)response, "AGREE_UNIX_FD\r\n"))
                return 0;
            if (strstr((const char *)response, "ERROR") ||
                strstr((const char *)response, "REJECTED"))
                return -EACCES;
            continue;
        }
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            r = rustd_raw_wait(bus->input_fd, POLLIN, 25000);
            if (r < 0)
                return r;
            continue;
        }
        return received == 0 ? -ECONNRESET : -errno;
    }
    return -ENOBUFS;
}

static int rustd_raw_read_auth_line(int fd, char *line, size_t capacity) {
    size_t used = 0U;
    if (!line || capacity < 3U)
        return -EINVAL;
    while (used + 1U < capacity) {
        unsigned char byte;
        int r = rustd_raw_read_all(fd, &byte, 1U, 25000);
        if (r < 0)
            return r;
        if (used == 0U && byte == 0U)
            continue;
        line[used++] = (char)byte;
        if (used >= 2U && line[used - 2U] == '\r' && line[used - 1U] == '\n') {
            line[used - 2U] = '\0';
            return 0;
        }
    }
    return -ENOBUFS;
}

static int rustd_raw_authenticate_server(sd_bus *bus) {
    char line[4096];
    char id[33];
    char response[64];
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    size_t i;
    int r;
    if (!bus || bus->input_fd < 0 || bus->output_fd < 0)
        return -ENOTCONN;
    if (!bus->trusted &&
        getsockopt(bus->input_fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) < 0)
        return -errno;
    r = rustd_raw_read_auth_line(bus->input_fd, line, sizeof(line));
    if (r < 0)
        return r;
    if (strncmp(line, "AUTH EXTERNAL", strlen("AUTH EXTERNAL")) != 0)
        return -EACCES;
    r = rustd_raw_write_all(bus->output_fd, "DATA\r\n", 6U, 25000);
    if (r < 0)
        return r;
    r = rustd_raw_read_auth_line(bus->input_fd, line, sizeof(line));
    if (r < 0)
        return r;
    if (strncmp(line, "DATA", 4U) != 0)
        return -EACCES;
    for (i = 0U; i < sizeof(bus->server_id.bytes); ++i)
        snprintf(id + i * 2U, 3U, "%02x", bus->server_id.bytes[i]);
    id[32] = '\0';
    snprintf(response, sizeof(response), "OK %s\r\n", id);
    r = rustd_raw_write_all(bus->output_fd, response, strlen(response), 25000);
    if (r < 0)
        return r;
    r = rustd_raw_read_auth_line(bus->input_fd, line, sizeof(line));
    if (r < 0)
        return r;
    if (strcmp(line, "NEGOTIATE_UNIX_FD") == 0) {
        r = rustd_raw_write_all(bus->output_fd, "AGREE_UNIX_FD\r\n", 15U, 25000);
        if (r < 0)
            return r;
        r = rustd_raw_read_auth_line(bus->input_fd, line, sizeof(line));
        if (r < 0)
            return r;
    }
    return strcmp(line, "BEGIN") == 0 ? 0 : -EACCES;
}

static int rustd_raw_receive_message(int fd, int timeout, DBusMessage **ret) {
    unsigned char header[16];
    unsigned char *wire = NULL;
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *message;
    int needed;
    int r;
    if (!ret)
        return -EINVAL;
    *ret = NULL;
    r = rustd_raw_read_all(fd, header, sizeof(header), timeout);
    if (r < 0)
        return r;
    needed = dbus_message_demarshal_bytes_needed((const char *)header, sizeof(header));
    if (needed < (int)sizeof(header) || needed > 128 * 1024 * 1024)
        return needed < 0 ? needed : -EBADMSG;
    wire = malloc((size_t)needed);
    if (!wire)
        return -ENOMEM;
    memcpy(wire, header, sizeof(header));
    r = rustd_raw_read_all(fd, wire + sizeof(header), (size_t)needed - sizeof(header), timeout);
    if (r < 0) {
        free(wire);
        return r;
    }
    message = dbus_message_demarshal((const char *)wire, needed, &error);
    free(wire);
    if (!message) {
        r = rustd_dbus_error_result(&error);
        dbus_error_free(&error);
        return r;
    }
    *ret = message;
    return 0;
}

static int rustd_raw_call(sd_bus *bus, sd_bus_message *m, int timeout,
                          sd_bus_error *ret_error, sd_bus_message **ret_reply) {
    DBusMessage *raw_reply = NULL;
    sd_bus_message *wrapped;
    char *wire = NULL;
    int wire_length = 0;
    uint32_t serial;
    int r;
    if (!bus || !m || bus->output_fd < 0 || bus->input_fd < 0)
        return -ENOTCONN;
    serial = bus->next_serial++;
    if (serial == 0U)
        serial = bus->next_serial++;
    dbus_message_set_serial(m->message, serial);
    if (!dbus_message_marshal(m->message, &wire, &wire_length))
        return -ENOMEM;
    r = rustd_raw_send_message(bus->output_fd, wire, (size_t)wire_length,
                               m->unix_fds, m->n_unix_fds, timeout);
    dbus_free(wire);
    if (r < 0)
        return r;
    for (;;) {
        r = rustd_raw_receive_message(bus->input_fd, timeout, &raw_reply);
        if (r < 0)
            return r;
        if (dbus_message_get_reply_serial(raw_reply) == serial)
            break;
        wrapped = rustd_message_wrap(bus, raw_reply, false);
        if (!wrapped) {
            dbus_message_unref(raw_reply);
            return -ENOMEM;
        }
        r = rustd_dispatch_message(bus, wrapped);
        sd_bus_message_unref(wrapped);
        raw_reply = NULL;
        if (r < 0)
            return r;
    }
    wrapped = rustd_message_wrap(bus, raw_reply, false);
    if (!wrapped) {
        dbus_message_unref(raw_reply);
        return -ENOMEM;
    }
    if (dbus_message_get_type(raw_reply) == DBUS_MESSAGE_TYPE_ERROR) {
        const sd_bus_error *message_error = sd_bus_message_get_error(wrapped);
        r = message_error ? -sd_bus_error_get_errno(message_error) : -EIO;
        if (ret_error && message_error && !rustd_bus_error_dirty(ret_error)) {
            ret_error->name = message_error->name ? strdup(message_error->name) : NULL;
            ret_error->message = message_error->message ? strdup(message_error->message) : NULL;
            ret_error->_need_free = (ret_error->name || ret_error->message) ? 1 : 0;
        }
        if (ret_reply)
            *ret_reply = wrapped;
        else
            sd_bus_message_unref(wrapped);
        return r;
    }
    if (ret_reply)
        *ret_reply = wrapped;
    else
        sd_bus_message_unref(wrapped);
    return 1;
}

static int rustd_bus_call_internal(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                                   sd_bus_error *ret_error, sd_bus_message **ret_reply) {
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage *reply;
    sd_bus_message *wrapped;
    int timeout;
    if (ret_reply)
        *ret_reply = NULL;
    if (!bus || !m)
        return -ENOTCONN;
    timeout = (usec == 0U || usec == UINT64_MAX) ? -1 :
              (usec / 1000U > (uint64_t)INT_MAX ? INT_MAX : (int)((usec + 999U) / 1000U));
    if (!bus->connection)
        return rustd_raw_call(bus, m, timeout, ret_error, ret_reply);
    reply = dbus_connection_send_with_reply_and_block(bus->connection, m->message, timeout, &error);
    if (!reply) {
        int r = rustd_dbus_error_result(&error);
        rustd_set_dbus_error(ret_error, &error);
        dbus_error_free(&error);
        return r;
    }
    wrapped = rustd_message_wrap(bus, reply, false);
    if (!wrapped) {
        dbus_message_unref(reply);
        return -ENOMEM;
    }
    if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
        const sd_bus_error *message_error = sd_bus_message_get_error(wrapped);
        int r = message_error ? -sd_bus_error_get_errno(message_error) : -EIO;
        if (ret_error && message_error && !rustd_bus_error_dirty(ret_error)) {
            ret_error->name = message_error->name ? strdup(message_error->name) : NULL;
            ret_error->message = message_error->message ? strdup(message_error->message) : NULL;
            ret_error->_need_free = (ret_error->name || ret_error->message) ? 1 : 0;
        }
        if (ret_reply)
            *ret_reply = wrapped;
        else
            sd_bus_message_unref(wrapped);
        return r;
    }
    if (ret_reply)
        *ret_reply = wrapped;
    else
        sd_bus_message_unref(wrapped);
    return 1;
}

int sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec,
                sd_bus_error *ret_error, sd_bus_message **ret_reply) {
    return rustd_bus_call_internal(bus, m, usec, ret_error, ret_reply);
}

static void rustd_async_notify(DBusPendingCall *pending, void *userdata) {
    sd_bus_slot *slot = userdata;
    DBusMessage *reply;
    sd_bus_message *wrapped;
    if (!slot || !slot->callback)
        return;
    reply = dbus_pending_call_steal_reply(pending);
    if (!reply)
        return;
    wrapped = rustd_message_wrap(slot->bus, reply, false);
    if (!wrapped) {
        dbus_message_unref(reply);
        return;
    }
    (void)slot->callback(wrapped, slot->userdata, NULL);
    sd_bus_message_unref(wrapped);
}

int sd_bus_call_async(sd_bus *bus, sd_bus_slot **ret_slot, sd_bus_message *m,
                      sd_bus_message_handler_t callback, void *userdata, uint64_t usec) {
    DBusPendingCall *pending = NULL;
    sd_bus_slot *slot;
    int timeout;
    if (!bus || !bus->connection || !m)
        return -EINVAL;
    if (!callback) {
        dbus_uint32_t serial = 0U;
        if (!dbus_connection_send(bus->connection, m->message, &serial))
            return -ENOMEM;
        dbus_connection_flush(bus->connection);
        return serial != 0U ? 1 : 0;
    }
    timeout = (usec == 0U || usec == UINT64_MAX) ? -1 :
              (usec / 1000U > (uint64_t)INT_MAX ? INT_MAX : (int)((usec + 999U) / 1000U));
    if (!dbus_connection_send_with_reply(bus->connection, m->message, &pending, timeout) || !pending)
        return -ENOMEM;
    slot = rustd_slot_new(bus, RUSTD_SLOT_ASYNC);
    if (!slot) {
        dbus_pending_call_cancel(pending);
        dbus_pending_call_unref(pending);
        return -ENOMEM;
    }
    slot->callback = callback;
    slot->userdata = userdata;
    slot->pending = pending;
    if (usec != UINT64_MAX) {
        uint64_t effective = usec == 0U ? bus->method_call_timeout : usec;
        uint64_t now = rustd_bus_monotonic_usec();
        slot->deadline_usec = UINT64_MAX - now < effective
            ? UINT64_MAX : now + effective;
    } else
        slot->deadline_usec = UINT64_MAX;
    if (!dbus_pending_call_set_notify(pending, rustd_async_notify, slot, NULL)) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    if (ret_slot)
        *ret_slot = slot;
    return rustd_bus_update_event_sources(bus);
}

int sd_bus_call_method(sd_bus *bus, const char *destination, const char *path,
                       const char *interface, const char *member,
                       sd_bus_error *ret_error, sd_bus_message **ret_reply,
                       const char *types, ...) {
    sd_bus_message *message = NULL;
    va_list ap;
    int r;
    r = sd_bus_message_new_method_call(bus, &message, destination, path, interface, member);
    if (r < 0)
        return r;
    if (types && *types) {
        va_start(ap, types);
        r = rustd_message_appendv(message, types, ap);
        va_end(ap);
        if (r < 0) {
            sd_bus_message_unref(message);
            return r;
        }
    }
    r = sd_bus_call(bus, message, 0U, ret_error, ret_reply);
    sd_bus_message_unref(message);
    return r;
}

int sd_bus_call_method_async(sd_bus *bus, sd_bus_slot **ret_slot, const char *destination,
                             const char *path, const char *interface, const char *member,
                             sd_bus_message_handler_t callback, void *userdata,
                             const char *types, ...) {
    sd_bus_message *message = NULL;
    va_list ap;
    int r;
    r = sd_bus_message_new_method_call(bus, &message, destination, path, interface, member);
    if (r < 0)
        return r;
    if (types && *types) {
        va_start(ap, types);
        r = rustd_message_appendv(message, types, ap);
        va_end(ap);
        if (r < 0) {
            sd_bus_message_unref(message);
            return r;
        }
    }
    r = sd_bus_call_async(bus, ret_slot, message, callback, userdata, 0U);
    sd_bus_message_unref(message);
    return r;
}

int sd_bus_get_property_trivial(sd_bus *bus, const char *destination, const char *path,
                                const char *interface, const char *member,
                                sd_bus_error *ret_error, char type, void *ret) {
    sd_bus_message *reply = NULL;
    char signature[2] = {type, '\0'};
    int r;
    if (!ret)
        return -EINVAL;
    r = sd_bus_call_method(bus, destination, path, DBUS_INTERFACE_PROPERTIES, "Get",
                           ret_error, &reply, "ss", interface, member);
    if (r < 0)
        return r;
    r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, signature);
    if (r > 0) {
        r = sd_bus_message_read_basic(reply, type, ret);
        if (r >= 0)
            r = sd_bus_message_exit_container(reply);
    }
    sd_bus_message_unref(reply);
    return r < 0 ? r : 0;
}

int sd_bus_get_property_string(sd_bus *bus, const char *destination, const char *path,
                               const char *interface, const char *member,
                               sd_bus_error *ret_error, char **ret) {
    sd_bus_message *reply = NULL;
    const char *value = NULL;
    char *copy;
    int r;
    if (!ret)
        return -EINVAL;
    *ret = NULL;
    r = sd_bus_call_method(bus, destination, path, DBUS_INTERFACE_PROPERTIES, "Get",
                           ret_error, &reply, "ss", interface, member);
    if (r < 0)
        return r;
    r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, "s");
    if (r > 0)
        r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_STRING, &value);
    if (r <= 0 || !value) {
        sd_bus_message_unref(reply);
        return r < 0 ? r : -EBADMSG;
    }
    copy = strdup(value);
    sd_bus_message_unref(reply);
    if (!copy)
        return -ENOMEM;
    *ret = copy;
    return 0;
}

static int rustd_send_reply(sd_bus_message *call, DBusMessage *reply) {
    dbus_uint32_t serial = 0;
    if (!call || !reply || !call->bus || !call->bus->connection) {
        if (reply)
            dbus_message_unref(reply);
        return -ENOTCONN;
    }
    if (!dbus_connection_send(call->bus->connection, reply, &serial)) {
        dbus_message_unref(reply);
        return -ENOMEM;
    }
    dbus_connection_flush(call->bus->connection);
    dbus_message_unref(reply);
    return serial > 0U ? 1 : 0;
}

int sd_bus_reply_method_return(sd_bus_message *call, const char *types, ...) {
    DBusMessage *raw;
    sd_bus_message *reply;
    va_list ap;
    int r;
    if (!call)
        return -EINVAL;
    raw = dbus_message_new_method_return(call->message);
    if (!raw)
        return -ENOMEM;
    reply = rustd_message_wrap(call->bus, raw, false);
    if (!reply) {
        dbus_message_unref(raw);
        return -ENOMEM;
    }
    if (types && *types) {
        va_start(ap, types);
        r = rustd_message_appendv(reply, types, ap);
        va_end(ap);
        if (r < 0) {
            sd_bus_message_unref(reply);
            return r;
        }
    }
    dbus_message_ref(reply->message);
    r = rustd_send_reply(call, reply->message);
    sd_bus_message_unref(reply);
    return r;
}

int sd_bus_reply_method_errorf(sd_bus_message *call, const char *name,
                               const char *format, ...) {
    DBusMessage *reply;
    char *message = NULL;
    va_list ap;
    int r;
    if (!call || !name || !format)
        return -EINVAL;
    va_start(ap, format);
    if (vasprintf(&message, format, ap) < 0)
        message = NULL;
    va_end(ap);
    if (!message)
        return -ENOMEM;
    reply = dbus_message_new_error(call->message, name, message);
    free(message);
    if (!reply)
        return -ENOMEM;
    r = rustd_send_reply(call, reply);
    return r;
}
