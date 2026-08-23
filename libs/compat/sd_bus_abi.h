/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct sd_bus sd_bus;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_vtable sd_bus_vtable;
typedef struct sd_event sd_event;

typedef struct sd_bus_error {
    const char *name;
    const char *message;
    int _need_free;
} sd_bus_error;

#define SD_BUS_ERROR_NULL ((sd_bus_error){NULL, NULL, 0})

enum {
    SD_BUS_TYPE_BYTE = 'y',
    SD_BUS_TYPE_BOOLEAN = 'b',
    SD_BUS_TYPE_INT16 = 'n',
    SD_BUS_TYPE_UINT16 = 'q',
    SD_BUS_TYPE_INT32 = 'i',
    SD_BUS_TYPE_UINT32 = 'u',
    SD_BUS_TYPE_INT64 = 'x',
    SD_BUS_TYPE_UINT64 = 't',
    SD_BUS_TYPE_DOUBLE = 'd',
    SD_BUS_TYPE_STRING = 's',
    SD_BUS_TYPE_OBJECT_PATH = 'o',
    SD_BUS_TYPE_SIGNATURE = 'g',
    SD_BUS_TYPE_UNIX_FD = 'h',
    SD_BUS_TYPE_ARRAY = 'a',
    SD_BUS_TYPE_VARIANT = 'v',
    SD_BUS_TYPE_STRUCT = 'r',
    SD_BUS_TYPE_STRUCT_BEGIN = '(',
    SD_BUS_TYPE_STRUCT_END = ')',
    SD_BUS_TYPE_DICT_ENTRY = 'e',
    SD_BUS_TYPE_DICT_ENTRY_BEGIN = '{',
    SD_BUS_TYPE_DICT_ENTRY_END = '}',
};

enum {
    _SD_BUS_VTABLE_START = '<',
    _SD_BUS_VTABLE_END = '>',
    _SD_BUS_VTABLE_METHOD = 'M',
    _SD_BUS_VTABLE_SIGNAL = 'S',
    _SD_BUS_VTABLE_PROPERTY = 'P',
    _SD_BUS_VTABLE_WRITABLE_PROPERTY = 'W',
};

enum {
    SD_BUS_VTABLE_DEPRECATED = 1ULL << 0,
    SD_BUS_VTABLE_HIDDEN = 1ULL << 1,
    SD_BUS_VTABLE_UNPRIVILEGED = 1ULL << 2,
    SD_BUS_VTABLE_METHOD_NO_REPLY = 1ULL << 3,
    SD_BUS_VTABLE_PROPERTY_CONST = 1ULL << 4,
    SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE = 1ULL << 5,
    SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION = 1ULL << 6,
    SD_BUS_VTABLE_PROPERTY_EXPLICIT = 1ULL << 7,
    SD_BUS_VTABLE_SENSITIVE = 1ULL << 8,
    SD_BUS_VTABLE_ABSOLUTE_OFFSET = 1ULL << 9,
};

typedef int (*sd_bus_message_handler_t)(sd_bus_message *, void *, sd_bus_error *);
typedef int (*sd_bus_property_get_t)(sd_bus *, const char *, const char *, const char *,
                                     sd_bus_message *, void *, sd_bus_error *);
typedef int (*sd_bus_property_set_t)(sd_bus *, const char *, const char *, const char *,
                                     sd_bus_message *, void *, sd_bus_error *);

struct sd_bus_vtable {
    __extension__ uint8_t type:8;
    __extension__ uint64_t flags:56;
    union {
        struct {
            size_t element_size;
            uint64_t features;
            const unsigned *vtable_format_reference;
        } start;
        struct { size_t _reserved; } end;
        struct {
            const char *member;
            const char *signature;
            const char *result;
            sd_bus_message_handler_t handler;
            size_t offset;
            const char *names;
        } method;
        struct {
            const char *member;
            const char *signature;
            const char *names;
        } signal;
        struct {
            const char *member;
            const char *signature;
            sd_bus_property_get_t get;
            sd_bus_property_set_t set;
            size_t offset;
        } property;
    } x;
};

extern const unsigned sd_bus_object_vtable_format;

int sd_bus_new(sd_bus **ret);
int sd_bus_open_system(sd_bus **ret);
int sd_bus_open_user(sd_bus **ret);
int sd_bus_default_user(sd_bus **ret);
int sd_bus_start(sd_bus *bus);
void sd_bus_close(sd_bus *bus);
sd_bus *sd_bus_flush_close_unref(sd_bus *bus);
sd_bus *sd_bus_ref(sd_bus *bus);
sd_bus *sd_bus_unref(sd_bus *bus);
int sd_bus_get_fd(sd_bus *bus);
int sd_bus_get_events(sd_bus *bus);
int sd_bus_process(sd_bus *bus, sd_bus_message **ret);
int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec);
int sd_bus_get_unique_name(sd_bus *bus, const char **unique);
int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd);
int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority);
int sd_bus_call(sd_bus *bus, sd_bus_message *message, uint64_t usec,
                sd_bus_error *error, sd_bus_message **reply);
int sd_bus_call_async(sd_bus *bus, sd_bus_slot **slot, sd_bus_message *message,
                      sd_bus_message_handler_t callback, void *userdata, uint64_t usec);
int sd_bus_call_method(sd_bus *bus, const char *destination, const char *path,
                       const char *interface, const char *member, sd_bus_error *error,
                       sd_bus_message **reply, const char *types, ...);
int sd_bus_call_method_async(sd_bus *bus, sd_bus_slot **slot, const char *destination,
                             const char *path, const char *interface, const char *member,
                             sd_bus_message_handler_t callback, void *userdata,
                             const char *types, ...);
int sd_bus_get_property_trivial(sd_bus *bus, const char *destination, const char *path,
                                const char *interface, const char *member,
                                sd_bus_error *error, char type, void *ret);
int sd_bus_get_property_string(sd_bus *bus, const char *destination, const char *path,
                               const char *interface, const char *member,
                               sd_bus_error *error, char **ret);
int sd_bus_add_filter(sd_bus *bus, sd_bus_slot **slot, sd_bus_message_handler_t callback, void *userdata);
int sd_bus_match_signal(sd_bus *bus, sd_bus_slot **slot, const char *sender,
                        const char *path, const char *interface, const char *member,
                        sd_bus_message_handler_t callback, void *userdata);
int sd_bus_match_signal_async(sd_bus *bus, sd_bus_slot **slot, const char *sender,
                              const char *path, const char *interface, const char *member,
                              sd_bus_message_handler_t callback,
                              sd_bus_message_handler_t install_callback, void *userdata);
int sd_bus_add_object_vtable(sd_bus *bus, sd_bus_slot **slot, const char *path,
                             const char *interface, const sd_bus_vtable *vtable, void *userdata);
sd_bus_slot *sd_bus_slot_ref(sd_bus_slot *slot);
sd_bus_slot *sd_bus_slot_unref(sd_bus_slot *slot);
int sd_bus_message_new_method_call(sd_bus *bus, sd_bus_message **ret, const char *destination,
                                   const char *path, const char *interface, const char *member);
sd_bus_message *sd_bus_message_unref(sd_bus_message *message);
int sd_bus_message_append(sd_bus_message *message, const char *types, ...);
int sd_bus_message_read(sd_bus_message *message, const char *types, ...);
int sd_bus_message_read_basic(sd_bus_message *message, char type, void *ret);
int sd_bus_message_skip(sd_bus_message *message, const char *types);
int sd_bus_message_at_end(sd_bus_message *message, int complete);
int sd_bus_message_open_container(sd_bus_message *message, char type, const char *contents);
int sd_bus_message_close_container(sd_bus_message *message);
int sd_bus_message_enter_container(sd_bus_message *message, char type, const char *contents);
int sd_bus_message_exit_container(sd_bus_message *message);
int sd_bus_message_get_errno(sd_bus_message *message);
const sd_bus_error *sd_bus_message_get_error(sd_bus_message *message);
const char *sd_bus_message_get_interface(sd_bus_message *message);
const char *sd_bus_message_get_member(sd_bus_message *message);
const char *sd_bus_message_get_path(sd_bus_message *message);
int sd_bus_message_is_signal(sd_bus_message *message, const char *interface, const char *member);
int sd_bus_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...);
int sd_bus_reply_method_return(sd_bus_message *call, const char *types, ...);
void sd_bus_error_free(sd_bus_error *error);
int sd_bus_error_get_errno(const sd_bus_error *error);
int sd_bus_error_has_name(const sd_bus_error *error, const char *name);
int sd_bus_error_set_errno(sd_bus_error *error, int code);
