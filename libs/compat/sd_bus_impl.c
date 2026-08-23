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
#include <unistd.h>

typedef struct sd_event_source sd_event_source;
extern int sd_event_add_io(sd_event *event, sd_event_source **ret, int fd,
                           uint32_t events, void *callback, void *userdata)
    __attribute__((weak));
extern int sd_event_source_set_priority(sd_event_source *source, int64_t priority)
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
};

struct sd_bus_message {
    unsigned refs;
    sd_bus *bus;
    DBusMessage *message;
    DBusMessageIter append_stack[32];
    unsigned append_depth;
    bool append_initialized;
    DBusMessageIter read_stack[32];
    unsigned read_depth;
    bool read_initialized;
    sd_bus_error cached_error;
    int unix_fds[64];
    unsigned n_unix_fds;
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
    const sd_bus_vtable *vtable;
    DBusPendingCall *pending;
    struct sd_bus_slot *next;
};

struct sd_bus {
    unsigned refs;
    DBusConnection *connection;
    int input_fd;
    int output_fd;
    bool owns_input_fd;
    bool owns_output_fd;
    bool started;
    uint32_t next_serial;
    sd_event *event;
    sd_event_source *event_source;
    struct sd_bus_slot *slots;
};

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
static int rustd_raw_receive_message(int fd, int timeout, DBusMessage **ret);

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

static DBusMessageIter *rustd_read_iter(sd_bus_message *m) {
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

int sd_bus_message_open_container(sd_bus_message *m, char type, const char *contents) {
    DBusMessageIter child;
    DBusMessageIter *parent;
    int dbus_type = type;
    if (!m || m->append_depth + 1U >= 32U)
        return -EINVAL;
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
        actual_signature = dbus_message_iter_get_signature(&child);
        if (!actual_signature)
            return -ENOMEM;
        if (strcmp(actual_signature, contents) != 0) {
            dbus_free(actual_signature);
            return -ENXIO;
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

int sd_bus_open_user(sd_bus **ret) {
    return rustd_bus_open_kind(ret, DBUS_BUS_SESSION);
}

int sd_bus_default_user(sd_bus **ret) {
    return sd_bus_open_user(ret);
}

sd_bus *sd_bus_flush_close_unref(sd_bus *bus) {
    if (!bus)
        return NULL;
    if (bus->connection)
        dbus_connection_flush(bus->connection);
    sd_bus_close(bus);
    return sd_bus_unref(bus);
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
    int r;
    if (!bus)
        return -EINVAL;
    if (bus->started)
        return 0;
    if (!bus->connection && bus->input_fd < 0)
        return -ENOTCONN;
    if (!bus->connection) {
        r = rustd_raw_authenticate(bus);
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
    return POLLIN | POLLOUT;
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

int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority) {
    int fd;
    int r;
    if (!bus || !event)
        return -EINVAL;
    if (!sd_event_add_io || !sd_event_source_set_priority || !sd_event_source_unref)
        return -ENOSYS;
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
    return 0;
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

static int rustd_dispatch_message(sd_bus *bus, sd_bus_message *m) {
    sd_bus_slot *slot;
    int handled = 0;
    for (slot = bus->slots; slot; slot = slot->next) {
        int r = 0;
        if (slot->kind == RUSTD_SLOT_FILTER && slot->callback)
            r = slot->callback(m, slot->userdata, NULL);
        else if (slot->kind == RUSTD_SLOT_MATCH && slot->callback && rustd_message_matches_slot(m, slot))
            r = slot->callback(m, slot->userdata, NULL);
        else if (slot->kind == RUSTD_SLOT_OBJECT && dbus_message_get_type(m->message) == DBUS_MESSAGE_TYPE_METHOD_CALL)
            r = rustd_dispatch_object(bus, slot, m);
        if (r < 0)
            return r;
        if (r > 0)
            handled = 1;
    }
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
    if (!dbus_pending_call_set_notify(pending, rustd_async_notify, slot, NULL)) {
        sd_bus_slot_unref(slot);
        return -ENOMEM;
    }
    if (ret_slot)
        *ret_slot = slot;
    return 0;
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
