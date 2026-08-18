/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Public ABI declarations required by RustD's measured libsystemd surface. */
typedef struct sd_json_variant sd_json_variant;
typedef struct sd_varlink sd_varlink;
typedef struct sd_varlink_interface sd_varlink_interface;

/* Keep numeric layout synchronized with the public sd-json builder ABI. */
enum {
    _SD_JSON_BUILD_STRING,
    _SD_JSON_BUILD_INTEGER,
    _SD_JSON_BUILD_UNSIGNED,
    _SD_JSON_BUILD_REAL,
    _SD_JSON_BUILD_BOOLEAN,
    _SD_JSON_BUILD_ARRAY_BEGIN,
    _SD_JSON_BUILD_ARRAY_END,
    _SD_JSON_BUILD_OBJECT_BEGIN,
    _SD_JSON_BUILD_OBJECT_END,
    _SD_JSON_BUILD_PAIR,
    _SD_JSON_BUILD_PAIR_CONDITION,
    _SD_JSON_BUILD_NULL,
    _SD_JSON_BUILD_VARIANT,
    _SD_JSON_BUILD_VARIANT_ARRAY,
    _SD_JSON_BUILD_LITERAL,
    _SD_JSON_BUILD_STRV,
    _SD_JSON_BUILD_BASE64,
    _SD_JSON_BUILD_BASE32HEX,
    _SD_JSON_BUILD_HEX,
    _SD_JSON_BUILD_OCTESCAPE,
    _SD_JSON_BUILD_BYTE_ARRAY,
    _SD_JSON_BUILD_ID128,
    _SD_JSON_BUILD_UUID,
    _SD_JSON_BUILD_CALLBACK,
    _SD_JSON_BUILD_MAX
};

#define SD_JSON_BUILD_STRING(s) _SD_JSON_BUILD_STRING, (const char *){s}
#define SD_JSON_BUILD_INTEGER(i) _SD_JSON_BUILD_INTEGER, (int64_t){i}
#define SD_JSON_BUILD_UNSIGNED(u) _SD_JSON_BUILD_UNSIGNED, (uint64_t){u}
#define SD_JSON_BUILD_REAL(d) _SD_JSON_BUILD_REAL, (double){d}
#define SD_JSON_BUILD_BOOLEAN(b) _SD_JSON_BUILD_BOOLEAN, (int){b}
#define SD_JSON_BUILD_ARRAY(...) _SD_JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_EMPTY_ARRAY _SD_JSON_BUILD_ARRAY_BEGIN, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_OBJECT(...) _SD_JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_EMPTY_OBJECT _SD_JSON_BUILD_OBJECT_BEGIN, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_PAIR(n, ...) _SD_JSON_BUILD_PAIR, (const char *){n}, __VA_ARGS__
#define SD_JSON_BUILD_PAIR_CONDITION(c, n, ...) \
    _SD_JSON_BUILD_PAIR_CONDITION, (int){c}, (const char *){n}, __VA_ARGS__
#define SD_JSON_BUILD_NULL _SD_JSON_BUILD_NULL
#define SD_JSON_BUILD_VARIANT(v) _SD_JSON_BUILD_VARIANT, (sd_json_variant *){v}
#define SD_JSON_BUILD_LITERAL(l) _SD_JSON_BUILD_LITERAL, (const char *){l}
#define SD_JSON_BUILD_PAIR_STRING(name, s) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRING(s))
#define SD_JSON_BUILD_PAIR_INTEGER(name, i) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_INTEGER(i))
#define SD_JSON_BUILD_PAIR_UNSIGNED(name, u) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_UNSIGNED(u))
#define SD_JSON_BUILD_PAIR_REAL(name, d) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_REAL(d))
#define SD_JSON_BUILD_PAIR_BOOLEAN(name, b) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BOOLEAN(b))
#define SD_JSON_BUILD_PAIR_OBJECT(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_OBJECT(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_ARRAY(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ARRAY(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_NULL(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_NULL)

sd_json_variant *sd_json_variant_ref(sd_json_variant *v);
sd_json_variant *sd_json_variant_unref(sd_json_variant *v);
const char *sd_json_variant_string(sd_json_variant *v);
size_t sd_json_variant_elements(sd_json_variant *v);
sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index);
sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key);

int sd_varlink_connect_address(sd_varlink **ret, const char *address);
sd_varlink *sd_varlink_unref(sd_varlink *v);
int sd_varlink_call(sd_varlink *v, const char *method, sd_json_variant *parameters,
                    sd_json_variant **ret_parameters, const char **ret_error_id);
int sd_varlink_callb(sd_varlink *v, const char *method,
                     sd_json_variant **ret_parameters, const char **ret_error_id, ...);
int sd_varlink_collect(sd_varlink *v, const char *method, sd_json_variant *parameters,
                       sd_json_variant **ret_parameters, const char **ret_error_id);
int sd_varlink_idl_parse(const char *text, unsigned *reterr_line,
                         unsigned *reterr_column, sd_varlink_interface **ret);
sd_varlink_interface *sd_varlink_interface_free(sd_varlink_interface *interface);
