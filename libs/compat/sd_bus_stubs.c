/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Fail-closed placeholders for sd_bus / sd_json / sd_varlink.
 * These exist only so preview SONAMEs can close host symbol audits.
 * They are NOT a D-Bus/JSON/Varlink implementation. Retain systemd-libs
 * for Tier C exclusive cutover until a real native bus stack lands.
 */
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef struct sd_bus sd_bus;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_vtable sd_bus_vtable;
typedef struct sd_event sd_event;
typedef struct sd_json_variant sd_json_variant;
typedef struct sd_varlink sd_varlink;
typedef struct sd_varlink_interface sd_varlink_interface;

typedef struct sd_bus_error {
    const char *name;
    const char *message;
    int _need_free;
} sd_bus_error;

typedef int (*sd_bus_message_handler_t)(sd_bus_message *m, void *userdata, sd_bus_error *ret_error);

const unsigned sd_bus_object_vtable_format = 0;

static int rustd_bus_enosys(sd_bus_error *error) {
    if (error) {
        error->name = "org.freedesktop.DBus.Error.NotSupported";
        error->message = "rustd-compat bus stubs are fail-closed";
        error->_need_free = 0;
    }
    return -ENOSYS;
}

int sd_bus_error_set_errno(sd_bus_error *e, int error) {
    (void)rustd_bus_enosys(e);
    return error < 0 ? error : -ENOSYS;
}

void sd_bus_error_free(sd_bus_error *e) {
    if (!e)
        return;
    e->name = NULL;
    e->message = NULL;
    e->_need_free = 0;
}

int sd_bus_error_get_errno(const sd_bus_error *e) {
    (void)e;
    return ENOSYS;
}

int sd_bus_error_has_name(const sd_bus_error *e, const char *name) {
    (void)e;
    (void)name;
    return 0;
}

void sd_bus_close(sd_bus *bus) {
    (void)bus;
}

sd_bus *sd_bus_ref(sd_bus *bus) {
    return bus;
}

sd_bus *sd_bus_unref(sd_bus *bus) {
    (void)bus;
    return NULL;
}

sd_bus_slot *sd_bus_slot_ref(sd_bus_slot *slot) {
    return slot;
}

sd_bus_slot *sd_bus_slot_unref(sd_bus_slot *slot) {
    (void)slot;
    return NULL;
}

sd_bus_message *sd_bus_message_unref(sd_bus_message *m) {
    (void)m;
    return NULL;
}

int sd_bus_new(sd_bus **ret) {
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_open_system(sd_bus **ret) {
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_open_user(sd_bus **ret) {
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_start(sd_bus *bus) {
    (void)bus;
    return -ENOSYS;
}

int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
    (void)bus;
    (void)input_fd;
    (void)output_fd;
    return -ENOSYS;
}

int sd_bus_get_fd(sd_bus *bus) {
    (void)bus;
    return -ENOSYS;
}

int sd_bus_get_events(sd_bus *bus) {
    (void)bus;
    return -ENOSYS;
}

int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
    (void)bus;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_attach_event(sd_bus *bus, sd_event *e, int priority) {
    (void)bus;
    (void)e;
    (void)priority;
    return -ENOSYS;
}

int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
    (void)bus;
    if (unique)
        *unique = NULL;
    return -ENOSYS;
}

int sd_bus_add_filter(sd_bus *bus, sd_bus_slot **ret_slot, sd_bus_message_handler_t callback, void *userdata) {
    (void)bus;
    (void)callback;
    (void)userdata;
    if (ret_slot)
        *ret_slot = NULL;
    return -ENOSYS;
}

int sd_bus_add_object_vtable(sd_bus *bus, sd_bus_slot **ret_slot, const char *path, const char *interface, const sd_bus_vtable *vtable, void *userdata) {
    (void)bus;
    (void)path;
    (void)interface;
    (void)vtable;
    (void)userdata;
    if (ret_slot)
        *ret_slot = NULL;
    return -ENOSYS;
}

int sd_bus_call(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_bus_error *reterr_error, sd_bus_message **ret_reply) {
    (void)bus;
    (void)m;
    (void)usec;
    if (ret_reply)
        *ret_reply = NULL;
    return rustd_bus_enosys(reterr_error);
}

int sd_bus_call_async(sd_bus *bus, sd_bus_slot **ret_slot, sd_bus_message *m, sd_bus_message_handler_t callback, void *userdata, uint64_t usec) {
    (void)bus;
    (void)m;
    (void)callback;
    (void)userdata;
    (void)usec;
    if (ret_slot)
        *ret_slot = NULL;
    return -ENOSYS;
}

int sd_bus_call_method(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *reterr_error, sd_bus_message **ret_reply, const char *types, ...) {
    va_list ap;
    (void)bus;
    (void)destination;
    (void)path;
    (void)interface;
    (void)member;
    (void)types;
    if (ret_reply)
        *ret_reply = NULL;
    va_start(ap, types);
    va_end(ap);
    return rustd_bus_enosys(reterr_error);
}

int sd_bus_call_method_async(sd_bus *bus, sd_bus_slot **ret_slot, const char *destination, const char *path, const char *interface, const char *member, sd_bus_message_handler_t callback, void *userdata, const char *types, ...) {
    va_list ap;
    (void)bus;
    (void)destination;
    (void)path;
    (void)interface;
    (void)member;
    (void)callback;
    (void)userdata;
    (void)types;
    if (ret_slot)
        *ret_slot = NULL;
    va_start(ap, types);
    va_end(ap);
    return -ENOSYS;
}

int sd_bus_get_property_trivial(sd_bus *bus, const char *destination, const char *path, const char *interface, const char *member, sd_bus_error *reterr_error, char type, void *ret) {
    (void)bus;
    (void)destination;
    (void)path;
    (void)interface;
    (void)member;
    (void)type;
    (void)ret;
    return rustd_bus_enosys(reterr_error);
}

int sd_bus_match_signal(sd_bus *bus, sd_bus_slot **ret, const char *sender, const char *path, const char *interface, const char *member, sd_bus_message_handler_t callback, void *userdata) {
    (void)bus;
    (void)sender;
    (void)path;
    (void)interface;
    (void)member;
    (void)callback;
    (void)userdata;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_match_signal_async(sd_bus *bus, sd_bus_slot **ret, const char *sender, const char *path, const char *interface, const char *member, sd_bus_message_handler_t match_callback, sd_bus_message_handler_t install_callback, void *userdata) {
    (void)bus;
    (void)sender;
    (void)path;
    (void)interface;
    (void)member;
    (void)match_callback;
    (void)install_callback;
    (void)userdata;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_message_new_method_call(sd_bus *bus, sd_bus_message **ret, const char *destination, const char *path, const char *interface, const char *member) {
    (void)bus;
    (void)destination;
    (void)path;
    (void)interface;
    (void)member;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
    va_list ap;
    (void)m;
    (void)types;
    va_start(ap, types);
    va_end(ap);
    return -ENOSYS;
}

int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
    va_list ap;
    (void)m;
    (void)types;
    va_start(ap, types);
    va_end(ap);
    return -ENOSYS;
}

int sd_bus_message_read_basic(sd_bus_message *m, char type, void *ret) {
    (void)m;
    (void)type;
    (void)ret;
    return -ENOSYS;
}

int sd_bus_message_skip(sd_bus_message *m, const char *types) {
    (void)m;
    (void)types;
    return -ENOSYS;
}

int sd_bus_message_at_end(sd_bus_message *m, int complete) {
    (void)m;
    (void)complete;
    return 1;
}

int sd_bus_message_open_container(sd_bus_message *m, char type, const char *contents) {
    (void)m;
    (void)type;
    (void)contents;
    return -ENOSYS;
}

int sd_bus_message_close_container(sd_bus_message *m) {
    (void)m;
    return -ENOSYS;
}

int sd_bus_message_enter_container(sd_bus_message *m, char type, const char *contents) {
    (void)m;
    (void)type;
    (void)contents;
    return -ENOSYS;
}

int sd_bus_message_exit_container(sd_bus_message *m) {
    (void)m;
    return -ENOSYS;
}

int sd_bus_message_get_errno(sd_bus_message *m) {
    (void)m;
    return ENOSYS;
}

const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
    (void)m;
    return NULL;
}

const char *sd_bus_message_get_interface(sd_bus_message *m) {
    (void)m;
    return NULL;
}

const char *sd_bus_message_get_member(sd_bus_message *m) {
    (void)m;
    return NULL;
}

const char *sd_bus_message_get_path(sd_bus_message *m) {
    (void)m;
    return NULL;
}

int sd_bus_message_is_signal(sd_bus_message *m, const char *interface, const char *member) {
    (void)m;
    (void)interface;
    (void)member;
    return 0;
}

int sd_bus_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...) {
    va_list ap;
    (void)call;
    (void)name;
    (void)format;
    va_start(ap, format);
    va_end(ap);
    return -ENOSYS;
}

int sd_bus_reply_method_return(sd_bus_message *call, const char *types, ...) {
    va_list ap;
    (void)call;
    (void)types;
    va_start(ap, types);
    va_end(ap);
    return -ENOSYS;
}

sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index) {
    (void)v;
    (void)index;
    return NULL;
}

sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key) {
    (void)v;
    (void)key;
    return NULL;
}

size_t sd_json_variant_elements(sd_json_variant *v) {
    (void)v;
    return 0;
}

const char *sd_json_variant_string(sd_json_variant *v) {
    (void)v;
    return NULL;
}

int sd_varlink_connect_address(sd_varlink **ret, const char *address) {
    (void)address;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

int sd_varlink_call(sd_varlink *v, const char *method, sd_json_variant *parameters, sd_json_variant **ret_parameters, const char **ret_error_id) {
    (void)v;
    (void)method;
    (void)parameters;
    if (ret_parameters)
        *ret_parameters = NULL;
    if (ret_error_id)
        *ret_error_id = "io.rustd.NotSupported";
    return -ENOSYS;
}

int sd_varlink_callb(sd_varlink *v, const char *method, sd_json_variant **ret_parameters, const char **ret_error_id, ...) {
    va_list ap;
    (void)v;
    (void)method;
    if (ret_parameters)
        *ret_parameters = NULL;
    if (ret_error_id)
        *ret_error_id = "io.rustd.NotSupported";
    va_start(ap, ret_error_id);
    va_end(ap);
    return -ENOSYS;
}

int sd_varlink_collect(sd_varlink *v, const char *method, sd_json_variant *parameters, sd_json_variant **ret_parameters, const char **ret_error_id) {
    (void)v;
    (void)method;
    (void)parameters;
    if (ret_parameters)
        *ret_parameters = NULL;
    if (ret_error_id)
        *ret_error_id = "io.rustd.NotSupported";
    return -ENOSYS;
}

sd_varlink *sd_varlink_unref(sd_varlink *v) {
    (void)v;
    return NULL;
}

int sd_varlink_idl_parse(const char *text, unsigned *reterr_line, unsigned *reterr_column, sd_varlink_interface **ret) {
    (void)text;
    if (reterr_line)
        *reterr_line = 0;
    if (reterr_column)
        *reterr_column = 0;
    if (ret)
        *ret = NULL;
    return -ENOSYS;
}

sd_varlink_interface *sd_varlink_interface_free(sd_varlink_interface *interface) {
    (void)interface;
    return NULL;
}
