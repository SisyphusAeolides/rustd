/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "sd_json_varlink_abi.h"

#include <json-c/json.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct sd_json_variant {
    unsigned refs;
    struct json_object *object;
    struct sd_json_variant *borrowed;
    struct sd_json_variant *next_borrowed;
};

struct sd_varlink {
    unsigned refs;
    int fd;
    char *input;
    size_t input_length;
    size_t input_capacity;
    sd_json_variant *last_parameters;
    char *last_error_id;
};

static sd_json_variant *variant_wrap(struct json_object *object) {
    sd_json_variant *variant;
    if (!object)
        return NULL;
    variant = calloc(1, sizeof(*variant));
    if (!variant)
        return NULL;
    variant->refs = 1U;
    variant->object = json_object_get(object);
    if (!variant->object) {
        free(variant);
        return NULL;
    }
    return variant;
}

static sd_json_variant *variant_borrow(sd_json_variant *parent, struct json_object *object) {
    sd_json_variant *child;
    if (!parent || !object)
        return NULL;
    for (child = parent->borrowed; child; child = child->next_borrowed)
        if (child->object == object)
            return child;
    child = variant_wrap(object);
    if (!child)
        return NULL;
    child->next_borrowed = parent->borrowed;
    parent->borrowed = child;
    return child;
}

static sd_json_variant *variant_borrow_key(sd_json_variant *parent, const char *key) {
    struct json_object *string;
    sd_json_variant *child;
    string = json_object_new_string(key ? key : "");
    if (!string)
        return NULL;
    child = variant_wrap(string);
    json_object_put(string);
    if (!child)
        return NULL;
    child->next_borrowed = parent->borrowed;
    parent->borrowed = child;
    return child;
}

sd_json_variant *sd_json_variant_ref(sd_json_variant *v) {
    if (v)
        ++v->refs;
    return v;
}

sd_json_variant *sd_json_variant_unref(sd_json_variant *v) {
    sd_json_variant *child;
    if (!v)
        return NULL;
    if (--v->refs > 0U)
        return NULL;
    while ((child = v->borrowed) != NULL) {
        v->borrowed = child->next_borrowed;
        child->next_borrowed = NULL;
        sd_json_variant_unref(child);
    }
    json_object_put(v->object);
    free(v);
    return NULL;
}

const char *sd_json_variant_string(sd_json_variant *v) {
    if (!v || !v->object || json_object_get_type(v->object) != json_type_string)
        return NULL;
    return json_object_get_string(v->object);
}

size_t sd_json_variant_elements(sd_json_variant *v) {
    enum json_type type;
    if (!v || !v->object)
        return 0U;
    type = json_object_get_type(v->object);
    if (type == json_type_array)
        return json_object_array_length(v->object);
    if (type == json_type_object)
        return (size_t)json_object_object_length(v->object) * 2U;
    return 0U;
}

sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key) {
    struct json_object *value = NULL;
    if (!v || !key || !v->object || json_object_get_type(v->object) != json_type_object)
        return NULL;
    if (!json_object_object_get_ex(v->object, key, &value) || !value)
        return NULL;
    return variant_borrow(v, value);
}

sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index) {
    enum json_type type;
    if (!v || !v->object)
        return NULL;
    type = json_object_get_type(v->object);
    if (type == json_type_array) {
        struct json_object *value;
        if (index >= json_object_array_length(v->object))
            return NULL;
        value = json_object_array_get_idx(v->object, index);
        return value ? variant_borrow(v, value) : NULL;
    }
    if (type == json_type_object) {
        size_t cursor = 0U;
        json_object_object_foreach(v->object, key, value) {
            if (cursor == index)
                return variant_borrow_key(v, key);
            ++cursor;
            if (cursor == index)
                return variant_borrow(v, value);
            ++cursor;
        }
    }
    return NULL;
}

static int write_full(int fd, const void *data, size_t length) {
    const char *cursor = data;
    while (length > 0U) {
        ssize_t n = send(fd, cursor, length, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EPIPE;
        cursor += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int varlink_send_json(sd_varlink *v, struct json_object *object) {
    const char *text;
    int r;
    if (!v || v->fd < 0 || !object)
        return -EINVAL;
    text = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    if (!text)
        return -ENOMEM;
    r = write_full(v->fd, text, strlen(text));
    if (r < 0)
        return r;
    return write_full(v->fd, "\0", 1U);
}

static int varlink_reserve_input(sd_varlink *v, size_t needed) {
    size_t capacity;
    char *resized;
    if (v->input_capacity >= needed)
        return 0;
    capacity = v->input_capacity ? v->input_capacity : 4096U;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2U)
            return -EOVERFLOW;
        capacity *= 2U;
    }
    resized = realloc(v->input, capacity);
    if (!resized)
        return -ENOMEM;
    v->input = resized;
    v->input_capacity = capacity;
    return 0;
}

static int varlink_read_json(sd_varlink *v, struct json_object **ret) {
    char *nul;
    struct json_object *object;
    struct json_tokener *tokener;
    enum json_tokener_error error;
    int r;
    if (!v || !ret)
        return -EINVAL;
    *ret = NULL;
    for (;;) {
        nul = v->input_length > 0U ? memchr(v->input, '\0', v->input_length) : NULL;
        if (nul) {
            size_t frame_length = (size_t)(nul - v->input);
            size_t consumed = frame_length + 1U;
            tokener = json_tokener_new();
            if (!tokener)
                return -ENOMEM;
            object = json_tokener_parse_ex(tokener, v->input, (int)frame_length);
            error = json_tokener_get_error(tokener);
            json_tokener_free(tokener);
            memmove(v->input, v->input + consumed, v->input_length - consumed);
            v->input_length -= consumed;
            if (error != json_tokener_success || !object)
                return -EBADMSG;
            if (json_object_get_type(object) != json_type_object) {
                json_object_put(object);
                return -EBADMSG;
            }
            *ret = object;
            return 0;
        }
        if (v->input_length >= 16U * 1024U * 1024U)
            return -EMSGSIZE;
        r = varlink_reserve_input(v, v->input_length + 4096U);
        if (r < 0)
            return r;
        for (;;) {
            ssize_t n = recv(v->fd, v->input + v->input_length,
                             v->input_capacity - v->input_length, 0);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0)
                return -errno;
            if (n == 0)
                return -ECONNRESET;
            v->input_length += (size_t)n;
            break;
        }
    }
}

int sd_varlink_connect_address(sd_varlink **ret, const char *address) {
    struct sockaddr_un sa;
    socklen_t length;
    size_t address_length;
    sd_varlink *v;
    int fd;
    if (!ret || !address || (address[0] != '/' && address[0] != '@') || address[1] == '\0')
        return -EINVAL;
    *ret = NULL;
    address_length = strlen(address);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (address[0] == '@') {
        if (address_length > sizeof(sa.sun_path))
            return -ENAMETOOLONG;
        memcpy(sa.sun_path + 1, address + 1, address_length - 1U);
        length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + address_length);
    } else {
        if (address_length >= sizeof(sa.sun_path))
            return -ENAMETOOLONG;
        memcpy(sa.sun_path, address, address_length + 1U);
        length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + address_length + 1U);
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    if (connect(fd, (const struct sockaddr *)&sa, length) < 0) {
        int saved = -errno;
        close(fd);
        return saved;
    }
    v = calloc(1, sizeof(*v));
    if (!v) {
        close(fd);
        return -ENOMEM;
    }
    v->refs = 1U;
    v->fd = fd;
    *ret = v;
    return 0;
}

sd_varlink *sd_varlink_unref(sd_varlink *v) {
    if (!v)
        return NULL;
    if (--v->refs > 0U)
        return NULL;
    if (v->fd >= 0)
        close(v->fd);
    free(v->input);
    sd_json_variant_unref(v->last_parameters);
    free(v->last_error_id);
    free(v);
    return NULL;
}

static void varlink_clear_reply(sd_varlink *v) {
    sd_json_variant_unref(v->last_parameters);
    v->last_parameters = NULL;
    free(v->last_error_id);
    v->last_error_id = NULL;
}

static int varlink_request(sd_varlink *v, const char *method, sd_json_variant *parameters,
                           bool more) {
    struct json_object *request;
    struct json_object *parameter_object;
    int r;
    if (!v || !method || !*method)
        return -EINVAL;
    request = json_object_new_object();
    if (!request)
        return -ENOMEM;
    json_object_object_add(request, "method", json_object_new_string(method));
    if (parameters && parameters->object)
        parameter_object = json_object_get(parameters->object);
    else
        parameter_object = json_object_new_object();
    if (!parameter_object) {
        json_object_put(request);
        return -ENOMEM;
    }
    json_object_object_add(request, "parameters", parameter_object);
    if (more)
        json_object_object_add(request, "more", json_object_new_boolean(1));
    r = varlink_send_json(v, request);
    json_object_put(request);
    return r;
}

static int varlink_store_reply(sd_varlink *v, struct json_object *reply,
                               sd_json_variant **ret_parameters, const char **ret_error_id,
                               int *ret_continues) {
    struct json_object *parameters = NULL;
    struct json_object *error = NULL;
    struct json_object *continues = NULL;
    int protocol_error = 0;
    varlink_clear_reply(v);
    if (json_object_object_get_ex(reply, "parameters", &parameters) && parameters) {
        v->last_parameters = variant_wrap(parameters);
        if (!v->last_parameters)
            return -ENOMEM;
    }
    if (json_object_object_get_ex(reply, "error", &error) && error) {
        const char *text;
        if (json_object_get_type(error) != json_type_string)
            return -EBADMSG;
        text = json_object_get_string(error);
        v->last_error_id = strdup(text ? text : "");
        if (!v->last_error_id)
            return -ENOMEM;
        protocol_error = 1;
    }
    if (ret_continues) {
        *ret_continues = 0;
        if (json_object_object_get_ex(reply, "continues", &continues) && continues)
            *ret_continues = json_object_get_boolean(continues) != 0;
    }
    if (ret_parameters)
        *ret_parameters = v->last_parameters;
    if (ret_error_id)
        *ret_error_id = v->last_error_id;
    return protocol_error ? 0 : 1;
}

int sd_varlink_call(sd_varlink *v, const char *method, sd_json_variant *parameters,
                    sd_json_variant **ret_parameters, const char **ret_error_id) {
    struct json_object *reply = NULL;
    int r;
    if (ret_parameters)
        *ret_parameters = NULL;
    if (ret_error_id)
        *ret_error_id = NULL;
    r = varlink_request(v, method, parameters, false);
    if (r < 0)
        return r;
    r = varlink_read_json(v, &reply);
    if (r < 0)
        return r;
    r = varlink_store_reply(v, reply, ret_parameters, ret_error_id, NULL);
    json_object_put(reply);
    return r;
}

static struct json_object *json_build_value(va_list *ap, int token);

static struct json_object *json_build_object(va_list *ap) {
    struct json_object *object = json_object_new_object();
    if (!object)
        return NULL;
    for (;;) {
        int token = va_arg(*ap, int);
        const char *name;
        struct json_object *value;
        if (token == _SD_JSON_BUILD_OBJECT_END)
            return object;
        if (token == _SD_JSON_BUILD_PAIR_CONDITION) {
            int condition = va_arg(*ap, int);
            name = va_arg(*ap, const char *);
            token = va_arg(*ap, int);
            value = json_build_value(ap, token);
            if (!value) {
                json_object_put(object);
                return NULL;
            }
            if (condition)
                json_object_object_add(object, name ? name : "", value);
            else
                json_object_put(value);
            continue;
        }
        if (token != _SD_JSON_BUILD_PAIR) {
            json_object_put(object);
            return NULL;
        }
        name = va_arg(*ap, const char *);
        token = va_arg(*ap, int);
        value = json_build_value(ap, token);
        if (!value) {
            json_object_put(object);
            return NULL;
        }
        json_object_object_add(object, name ? name : "", value);
    }
}

static struct json_object *json_build_array(va_list *ap) {
    struct json_object *array = json_object_new_array();
    if (!array)
        return NULL;
    for (;;) {
        int token = va_arg(*ap, int);
        struct json_object *value;
        if (token == _SD_JSON_BUILD_ARRAY_END)
            return array;
        value = json_build_value(ap, token);
        if (!value) {
            json_object_put(array);
            return NULL;
        }
        json_object_array_add(array, value);
    }
}

static struct json_object *json_build_value(va_list *ap, int token) {
    switch (token) {
    case _SD_JSON_BUILD_STRING: {
        const char *value = va_arg(*ap, const char *);
        return value ? json_object_new_string(value) : json_object_new_null();
    }
    case _SD_JSON_BUILD_INTEGER:
        return json_object_new_int64(va_arg(*ap, int64_t));
    case _SD_JSON_BUILD_UNSIGNED:
        return json_object_new_uint64(va_arg(*ap, uint64_t));
    case _SD_JSON_BUILD_REAL:
        return json_object_new_double(va_arg(*ap, double));
    case _SD_JSON_BUILD_BOOLEAN:
        return json_object_new_boolean(va_arg(*ap, int));
    case _SD_JSON_BUILD_NULL:
        return json_object_new_null();
    case _SD_JSON_BUILD_ARRAY_BEGIN:
        return json_build_array(ap);
    case _SD_JSON_BUILD_OBJECT_BEGIN:
        return json_build_object(ap);
    case _SD_JSON_BUILD_VARIANT: {
        sd_json_variant *variant = va_arg(*ap, sd_json_variant *);
        return variant && variant->object ? json_object_get(variant->object) : json_object_new_null();
    }
    case _SD_JSON_BUILD_LITERAL: {
        const char *literal = va_arg(*ap, const char *);
        return literal ? json_tokener_parse(literal) : NULL;
    }
    default:
        return NULL;
    }
}

int sd_varlink_callb(sd_varlink *v, const char *method,
                     sd_json_variant **ret_parameters, const char **ret_error_id, ...) {
    va_list ap;
    struct json_object *object;
    sd_json_variant *parameters;
    int token;
    int r;
    va_start(ap, ret_error_id);
    token = va_arg(ap, int);
    object = json_build_value(&ap, token);
    va_end(ap);
    if (!object)
        return -EINVAL;
    parameters = variant_wrap(object);
    json_object_put(object);
    if (!parameters)
        return -ENOMEM;
    r = sd_varlink_call(v, method, parameters, ret_parameters, ret_error_id);
    sd_json_variant_unref(parameters);
    return r;
}

int sd_varlink_collect(sd_varlink *v, const char *method, sd_json_variant *parameters,
                       sd_json_variant **ret_parameters, const char **ret_error_id) {
    struct json_object *array;
    int r;
    if (ret_parameters)
        *ret_parameters = NULL;
    if (ret_error_id)
        *ret_error_id = NULL;
    r = varlink_request(v, method, parameters, true);
    if (r < 0)
        return r;
    array = json_object_new_array();
    if (!array)
        return -ENOMEM;
    for (;;) {
        struct json_object *reply = NULL;
        struct json_object *reply_parameters = NULL;
        struct json_object *error = NULL;
        struct json_object *continues = NULL;
        int more = 0;
        r = varlink_read_json(v, &reply);
        if (r < 0) {
            json_object_put(array);
            return r;
        }
        if (json_object_object_get_ex(reply, "error", &error) && error) {
            const char *text = json_object_get_string(error);
            varlink_clear_reply(v);
            v->last_error_id = strdup(text ? text : "");
            if (ret_error_id)
                *ret_error_id = v->last_error_id;
            json_object_put(reply);
            json_object_put(array);
            return v->last_error_id ? 0 : -ENOMEM;
        }
        if (json_object_object_get_ex(reply, "parameters", &reply_parameters) && reply_parameters)
            json_object_array_add(array, json_object_get(reply_parameters));
        if (json_object_object_get_ex(reply, "continues", &continues) && continues)
            more = json_object_get_boolean(continues) != 0;
        json_object_put(reply);
        if (!more)
            break;
    }
    varlink_clear_reply(v);
    v->last_parameters = variant_wrap(array);
    json_object_put(array);
    if (!v->last_parameters)
        return -ENOMEM;
    if (ret_parameters)
        *ret_parameters = v->last_parameters;
    return 1;
}
