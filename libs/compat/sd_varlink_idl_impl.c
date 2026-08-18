/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sd_json_varlink_abi.h"

struct sd_varlink_interface {
    const char *name;
    int64_t interface_flags;
    const void *symbols[];
};

struct idl_parser {
    const char *text;
    size_t pos;
    unsigned line;
    unsigned column;
    unsigned error_line;
    unsigned error_column;
};

static int parser_fail(struct idl_parser *p) {
    if (p->error_line == 0U) {
        p->error_line = p->line;
        p->error_column = p->column;
    }
    return -EINVAL;
}

static char parser_peek(const struct idl_parser *p) {
    return p->text[p->pos];
}

static char parser_take(struct idl_parser *p) {
    char c = p->text[p->pos];
    if (!c)
        return 0;
    p->pos++;
    if (c == '\n') {
        p->line++;
        p->column = 1U;
    } else
        p->column++;
    return c;
}

static void parser_skip(struct idl_parser *p) {
    for (;;) {
        char c = parser_peek(p);
        if (c == '#') {
            while (parser_peek(p) && parser_take(p) != '\n') {}
            continue;
        }
        if (c && isspace((unsigned char)c)) {
            parser_take(p);
            continue;
        }
        break;
    }
}

static int parser_keyword(struct idl_parser *p, const char *word) {
    size_t n = strlen(word);
    parser_skip(p);
    if (strncmp(p->text + p->pos, word, n) != 0)
        return 0;
    if (isalnum((unsigned char)p->text[p->pos + n]) || p->text[p->pos + n] == '_')
        return 0;
    for (size_t i = 0; i < n; ++i)
        parser_take(p);
    return 1;
}

static int parser_literal(struct idl_parser *p, const char *literal) {
    size_t n = strlen(literal);
    parser_skip(p);
    if (strncmp(p->text + p->pos, literal, n) != 0)
        return 0;
    for (size_t i = 0; i < n; ++i)
        parser_take(p);
    return 1;
}

static int parser_ident(struct idl_parser *p, int upper, char **ret) {
    size_t start;
    size_t length;
    char *copy;
    parser_skip(p);
    if (!isalpha((unsigned char)parser_peek(p)))
        return parser_fail(p);
    if (upper && !isupper((unsigned char)parser_peek(p)))
        return parser_fail(p);
    start = p->pos;
    parser_take(p);
    while (isalnum((unsigned char)parser_peek(p)) || parser_peek(p) == '_')
        parser_take(p);
    length = p->pos - start;
    if (p->text[p->pos - 1U] == '_')
        return parser_fail(p);
    for (size_t i = start; i + 1U < p->pos; ++i)
        if (p->text[i] == '_' && p->text[i + 1U] == '_')
            return parser_fail(p);
    if (!ret)
        return 0;
    copy = malloc(length + 1U);
    if (!copy)
        return -ENOMEM;
    memcpy(copy, p->text + start, length);
    copy[length] = 0;
    *ret = copy;
    return 0;
}

static int interface_name_valid(const char *s, size_t n) {
    size_t start = 0U;
    unsigned dots = 0U;
    if (n == 0U || !isalpha((unsigned char)s[0]))
        return 0;
    for (size_t i = 0U; i <= n; ++i) {
        if (i == n || s[i] == '.') {
            size_t len = i - start;
            if (len == 0U)
                return 0;
            if (!isalnum((unsigned char)s[start]))
                return 0;
            if (!isalnum((unsigned char)s[i - 1U]))
                return 0;
            for (size_t j = start; j < i; ++j)
                if (!isalnum((unsigned char)s[j]) && s[j] != '-')
                    return 0;
            if (i < n)
                dots++;
            start = i + 1U;
        }
    }
    return dots > 0U;
}

static int parser_interface_name(struct idl_parser *p, char **ret) {
    size_t start;
    size_t length;
    char *copy;
    parser_skip(p);
    start = p->pos;
    while (parser_peek(p) && !isspace((unsigned char)parser_peek(p)) && parser_peek(p) != '#')
        parser_take(p);
    length = p->pos - start;
    if (!interface_name_valid(p->text + start, length))
        return parser_fail(p);
    copy = malloc(length + 1U);
    if (!copy)
        return -ENOMEM;
    memcpy(copy, p->text + start, length);
    copy[length] = 0;
    *ret = copy;
    return 0;
}

static int parser_type(struct idl_parser *p);

static int parser_group(struct idl_parser *p, int *is_struct) {
    int r;
    size_t save_pos;
    unsigned save_line, save_column;
    if (!parser_literal(p, "("))
        return parser_fail(p);
    parser_skip(p);
    if (parser_literal(p, ")")) {
        if (is_struct)
            *is_struct = 1;
        return 0;
    }
    save_pos = p->pos;
    save_line = p->line;
    save_column = p->column;
    r = parser_ident(p, 0, NULL);
    if (r < 0)
        return r;
    parser_skip(p);
    if (parser_literal(p, ":")) {
        if (is_struct)
            *is_struct = 1;
        r = parser_type(p);
        if (r < 0)
            return r;
        while (parser_literal(p, ",")) {
            r = parser_ident(p, 0, NULL);
            if (r < 0)
                return r;
            if (!parser_literal(p, ":"))
                return parser_fail(p);
            r = parser_type(p);
            if (r < 0)
                return r;
        }
    } else {
        if (is_struct)
            *is_struct = 0;
        p->pos = save_pos;
        p->line = save_line;
        p->column = save_column;
        r = parser_ident(p, 0, NULL);
        if (r < 0)
            return r;
        while (parser_literal(p, ",")) {
            r = parser_ident(p, 0, NULL);
            if (r < 0)
                return r;
        }
    }
    if (!parser_literal(p, ")"))
        return parser_fail(p);
    return 0;
}

static int parser_type(struct idl_parser *p) {
    int group_kind;
    parser_skip(p);
    if (parser_literal(p, "?"))
        return parser_type(p);
    if (parser_literal(p, "[]"))
        return parser_type(p);
    if (parser_literal(p, "[string]"))
        return parser_type(p);
    if (parser_peek(p) == '(')
        return parser_group(p, &group_kind);
    if (parser_keyword(p, "bool") || parser_keyword(p, "int") ||
        parser_keyword(p, "float") || parser_keyword(p, "string") ||
        parser_keyword(p, "object") || parser_keyword(p, "any"))
        return 0;
    return parser_ident(p, 1, NULL);
}

static int parser_type_member(struct idl_parser *p) {
    int r, group_kind;
    r = parser_ident(p, 1, NULL);
    if (r < 0)
        return r;
    r = parser_group(p, &group_kind);
    return r;
}

static int parser_method_member(struct idl_parser *p) {
    int r, group_kind;
    r = parser_ident(p, 1, NULL);
    if (r < 0)
        return r;
    r = parser_group(p, &group_kind);
    if (r < 0 || !group_kind)
        return r < 0 ? r : parser_fail(p);
    if (!parser_literal(p, "->"))
        return parser_fail(p);
    r = parser_group(p, &group_kind);
    if (r < 0 || !group_kind)
        return r < 0 ? r : parser_fail(p);
    return 0;
}

static int parser_error_member(struct idl_parser *p) {
    int r, group_kind;
    r = parser_ident(p, 1, NULL);
    if (r < 0)
        return r;
    r = parser_group(p, &group_kind);
    if (r < 0 || !group_kind)
        return r < 0 ? r : parser_fail(p);
    return 0;
}

int sd_varlink_idl_parse(const char *text, unsigned *reterr_line,
                         unsigned *reterr_column, sd_varlink_interface **ret) {
    struct idl_parser p = {.text = text, .line = 1U, .column = 1U};
    sd_varlink_interface *interface = NULL;
    char *name = NULL;
    unsigned members = 0U;
    int r;
    if (reterr_line)
        *reterr_line = 0U;
    if (reterr_column)
        *reterr_column = 0U;
    if (ret)
        *ret = NULL;
    if (!text || !ret)
        return -EINVAL;
    if (!parser_keyword(&p, "interface")) {
        r = parser_fail(&p);
        goto fail;
    }
    r = parser_interface_name(&p, &name);
    if (r < 0)
        goto fail;
    for (;;) {
        parser_skip(&p);
        if (!parser_peek(&p))
            break;
        if (parser_keyword(&p, "type"))
            r = parser_type_member(&p);
        else if (parser_keyword(&p, "method"))
            r = parser_method_member(&p);
        else if (parser_keyword(&p, "error"))
            r = parser_error_member(&p);
        else {
            r = parser_fail(&p);
            goto fail;
        }
        if (r < 0)
            goto fail;
        members++;
    }
    if (members == 0U) {
        r = parser_fail(&p);
        goto fail;
    }
    interface = calloc(1U, sizeof(*interface) + sizeof(interface->symbols[0]));
    if (!interface) {
        r = -ENOMEM;
        goto fail;
    }
    interface->name = name;
    interface->interface_flags = 0;
    interface->symbols[0] = NULL;
    *ret = interface;
    return 0;
fail:
    free(name);
    if (reterr_line)
        *reterr_line = p.error_line ? p.error_line : p.line;
    if (reterr_column)
        *reterr_column = p.error_column ? p.error_column : p.column;
    return r;
}

sd_varlink_interface *sd_varlink_interface_free(sd_varlink_interface *interface) {
    if (!interface)
        return NULL;
    free((void *)interface->name);
    free(interface);
    return NULL;
}
