/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct sd_bus sd_bus;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_vtable sd_bus_vtable;
typedef struct sd_event sd_event;
#ifndef RUSTD_SD_ID128_T_DEFINED
#define RUSTD_SD_ID128_T_DEFINED 1
typedef struct sd_id128 { uint8_t bytes[16]; } sd_id128_t;
#endif

typedef struct sd_bus_error {
    const char *name;
    const char *message;
    int _need_free;
} sd_bus_error;

#define SD_BUS_ERROR_NULL ((sd_bus_error){NULL, NULL, 0})

enum {
    SD_BUS_CREDS_PID = 1ULL << 0,
    SD_BUS_CREDS_UID = 1ULL << 3,
    SD_BUS_CREDS_EUID = 1ULL << 4,
    SD_BUS_CREDS_GID = 1ULL << 7,
    SD_BUS_CREDS_EGID = 1ULL << 8,
    SD_BUS_CREDS_SUPPLEMENTARY_GIDS = 1ULL << 11,
    SD_BUS_CREDS_SELINUX_CONTEXT = 1ULL << 27,
};

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
int sd_bus_open(sd_bus **ret);
int sd_bus_open_system(sd_bus **ret);
int sd_bus_open_system_remote(sd_bus **ret, const char *host);
int sd_bus_open_user(sd_bus **ret);
int sd_bus_default_user(sd_bus **ret);
int sd_bus_default_system(sd_bus **ret);
int sd_bus_start(sd_bus *bus);
void sd_bus_close(sd_bus *bus);
sd_bus *sd_bus_flush_close_unref(sd_bus *bus);
sd_bus *sd_bus_close_unref(sd_bus *bus);
int sd_bus_flush(sd_bus *bus);
sd_bus *sd_bus_ref(sd_bus *bus);
sd_bus *sd_bus_unref(sd_bus *bus);
int sd_bus_get_fd(sd_bus *bus);
int sd_bus_get_events(sd_bus *bus);
int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec);
int sd_bus_get_n_queued_read(sd_bus *bus, uint64_t *ret);
int sd_bus_get_n_queued_write(sd_bus *bus, uint64_t *ret);
int sd_bus_get_method_call_timeout(sd_bus *bus, uint64_t *timeout_usec);
int sd_bus_set_method_call_timeout(sd_bus *bus, uint64_t timeout_usec);
int sd_bus_process(sd_bus *bus, sd_bus_message **ret);
int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec);
int sd_bus_get_unique_name(sd_bus *bus, const char **unique);
sd_bus_message *sd_bus_get_current_message(sd_bus *bus);
int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd);
int sd_bus_set_address(sd_bus *bus, const char *address);
int sd_bus_set_bus_client(sd_bus *bus, int b);
int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id);
int sd_bus_set_trusted(sd_bus *bus, int b);
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
int sd_bus_add_match(sd_bus *bus, sd_bus_slot **slot, const char *match,
                     sd_bus_message_handler_t callback, void *userdata);
int sd_bus_add_match_async(sd_bus *bus, sd_bus_slot **slot, const char *match,
                           sd_bus_message_handler_t callback,
                           sd_bus_message_handler_t install_callback, void *userdata);
int sd_bus_add_object_manager(sd_bus *bus, sd_bus_slot **slot, const char *path);
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
int sd_bus_message_new(sd_bus *bus, sd_bus_message **ret, uint8_t type);
int sd_bus_message_new_signal(sd_bus *bus, sd_bus_message **ret, const char *path,
                              const char *interface, const char *member);
int sd_bus_message_new_method_return(sd_bus_message *call, sd_bus_message **ret);
int sd_bus_message_new_method_error(sd_bus_message *call, sd_bus_message **ret,
                                    const sd_bus_error *error);
sd_bus_message *sd_bus_message_ref(sd_bus_message *message);
sd_bus_message *sd_bus_message_unref(sd_bus_message *message);
int sd_bus_message_append(sd_bus_message *message, const char *types, ...);
int sd_bus_message_append_basic(sd_bus_message *message, char type, const void *value);
int sd_bus_message_append_array(sd_bus_message *message, char type, const void *ptr, size_t size);
int sd_bus_message_append_string_space(sd_bus_message *message, size_t size, char **ret);
int sd_bus_message_append_strv(sd_bus_message *message, char **values);
int sd_bus_message_copy(sd_bus_message *message, sd_bus_message *source, int all);
int sd_bus_message_read(sd_bus_message *message, const char *types, ...);
int sd_bus_message_read_basic(sd_bus_message *message, char type, void *ret);
int sd_bus_message_read_array(sd_bus_message *message, char type, const void **ptr, size_t *size);
int sd_bus_message_peek_type(sd_bus_message *message, char *type, const char **contents);
int sd_bus_message_rewind(sd_bus_message *message, int complete);
int sd_bus_message_seal(sd_bus_message *message, uint64_t cookie, uint64_t timeout_usec);
int sd_bus_message_get_cookie(sd_bus_message *message, uint64_t *cookie);
int sd_bus_message_get_reply_cookie(sd_bus_message *message, uint64_t *cookie);
const char *sd_bus_message_get_destination(sd_bus_message *message);
const char *sd_bus_message_get_sender(sd_bus_message *message);
int sd_bus_message_get_expect_reply(sd_bus_message *message);
int sd_bus_message_set_expect_reply(sd_bus_message *message, int b);
int sd_bus_message_set_destination(sd_bus_message *message, const char *destination);
int sd_bus_message_is_empty(sd_bus_message *message);
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
int sd_bus_error_set(sd_bus_error *error, const char *name, const char *message);
int sd_bus_error_is_set(const sd_bus_error *error);
int sd_bus_send(sd_bus *bus, sd_bus_message *message, uint64_t *cookie);
int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags);
int sd_bus_release_name(sd_bus *bus, const char *name);
int sd_bus_query_sender_creds(sd_bus_message *message, uint64_t mask, sd_bus_creds **creds);
sd_bus_creds *sd_bus_creds_ref(sd_bus_creds *creds);
sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *creds);
int sd_bus_creds_get_pid(sd_bus_creds *creds, pid_t *pid);
int sd_bus_creds_get_uid(sd_bus_creds *creds, uid_t *uid);
int sd_bus_creds_get_euid(sd_bus_creds *creds, uid_t *uid);
int sd_bus_creds_get_gid(sd_bus_creds *creds, gid_t *gid);
int sd_bus_creds_get_egid(sd_bus_creds *creds, gid_t *gid);
int sd_bus_creds_get_supplementary_gids(sd_bus_creds *creds, const gid_t **gids);
int sd_bus_creds_get_selinux_context(sd_bus_creds *creds, const char **context);
int sd_bus_service_name_is_valid(const char *name);
int sd_bus_interface_name_is_valid(const char *name);
int sd_bus_member_name_is_valid(const char *name);
int sd_bus_object_path_is_valid(const char *path);
int sd_bus_emit_properties_changed_strv(sd_bus *bus, const char *path,
                                        const char *interface, char **names);
int sd_bus_emit_interfaces_added_strv(sd_bus *bus, const char *path, char **interfaces);
int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces);
int sd_bus_emit_object_added(sd_bus *bus, const char *path);
int sd_bus_emit_object_removed(sd_bus *bus, const char *path);
