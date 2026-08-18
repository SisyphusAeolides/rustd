/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <printf.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <wchar.h>

#include <rustd/journal.h>

static int advance_printf_args(const char *format, va_list *ap) {
    int argtypes[128];
    size_t count;
    size_t i;

    if (!format || !ap)
        return -EINVAL;
    count = parse_printf_format(format, sizeof(argtypes) / sizeof(argtypes[0]), argtypes);
    if (count >= sizeof(argtypes) / sizeof(argtypes[0]))
        return -E2BIG;

    for (i = 0; i < count; ++i) {
        if (argtypes[i] & PA_FLAG_PTR) {
            (void)va_arg(*ap, void *);
            continue;
        }
        switch (argtypes[i]) {
        case PA_INT:
        case PA_INT | PA_FLAG_SHORT:
        case PA_CHAR:
            (void)va_arg(*ap, int);
            break;
        case PA_INT | PA_FLAG_LONG:
            (void)va_arg(*ap, long int);
            break;
        case PA_INT | PA_FLAG_LONG_LONG:
            (void)va_arg(*ap, long long int);
            break;
        case PA_WCHAR:
            (void)va_arg(*ap, wchar_t);
            break;
        case PA_WSTRING:
        case PA_STRING:
        case PA_POINTER:
            (void)va_arg(*ap, void *);
            break;
        case PA_FLOAT:
        case PA_DOUBLE:
            (void)va_arg(*ap, double);
            break;
        case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
            (void)va_arg(*ap, long double);
            break;
        default:
            return -EINVAL;
        }
    }
    return 0;
}

static void trim_trailing_whitespace(char *text) {
    size_t n;
    if (!text)
        return;
    n = strlen(text);
    while (n > 0U) {
        unsigned char c = (unsigned char)text[n - 1U];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f')
            break;
        text[--n] = 0;
    }
}

static void free_iov(struct iovec *iov, size_t n, size_t skip) {
    size_t i;
    if (!iov)
        return;
    for (i = skip; i < n; ++i)
        free(iov[i].iov_base);
    free(iov);
}

static int format_fields(const char *format, va_list ap, size_t extra,
                         struct iovec **ret_iov, size_t *ret_n) {
    struct iovec *iov = NULL;
    size_t n = extra;
    va_list cursor;
    int r = 0;

    if (!ret_iov || !ret_n)
        return -EINVAL;
    *ret_iov = NULL;
    *ret_n = 0U;
    if (extra > 0U) {
        iov = calloc(extra, sizeof(*iov));
        if (!iov)
            return -ENOMEM;
    }

    va_copy(cursor, ap);
    while (format) {
        va_list copy;
        char *buffer = NULL;
        struct iovec *grown;
        int length;

        va_copy(copy, cursor);
        length = vasprintf(&buffer, format, copy);
        va_end(copy);
        if (length < 0) {
            r = -ENOMEM;
            goto fail;
        }
        trim_trailing_whitespace(buffer);
        r = advance_printf_args(format, &cursor);
        if (r < 0) {
            free(buffer);
            goto fail;
        }
        format = va_arg(cursor, const char *);
        grown = realloc(iov, (n + 1U) * sizeof(*iov));
        if (!grown) {
            free(buffer);
            r = -ENOMEM;
            goto fail;
        }
        iov = grown;
        iov[n].iov_base = buffer;
        iov[n].iov_len = strlen(buffer);
        n++;
    }
    va_end(cursor);
    *ret_iov = iov;
    *ret_n = n;
    return 0;

fail:
    va_end(cursor);
    free_iov(iov, n, extra);
    return r;
}

static char *code_func_field(const char *func) {
    char *field;
    size_t n;
    if (!func)
        return NULL;
    n = strlen(func);
    field = malloc(n + sizeof("CODE_FUNC="));
    if (!field)
        return NULL;
    memcpy(field, "CODE_FUNC=", sizeof("CODE_FUNC=") - 1U);
    memcpy(field + sizeof("CODE_FUNC=") - 1U, func, n + 1U);
    return field;
}

int sd_journal_send(const char *format, ...) {
    struct iovec *iov = NULL;
    size_t n = 0U;
    va_list ap;
    int r;
    if (!format)
        return -EINVAL;
    va_start(ap, format);
    r = format_fields(format, ap, 0U, &iov, &n);
    va_end(ap);
    if (r < 0)
        return r;
    if (n == 0U) {
        free(iov);
        return -EINVAL;
    }
    r = rustd_journal_sendv(iov, (int)n);
    free_iov(iov, n, 0U);
    return r;
}

int sd_journal_send_with_location(const char *file, const char *line, const char *func,
                                  const char *format, ...) {
    struct iovec *iov = NULL;
    size_t n = 0U;
    char *func_field;
    va_list ap;
    int r;
    if (!file || !line || !func || !format)
        return -EINVAL;
    va_start(ap, format);
    r = format_fields(format, ap, 3U, &iov, &n);
    va_end(ap);
    if (r < 0)
        return r;
    func_field = code_func_field(func);
    if (!func_field) {
        free_iov(iov, n, 3U);
        return -ENOMEM;
    }
    iov[0].iov_base = (void *)file;
    iov[0].iov_len = strlen(file);
    iov[1].iov_base = (void *)line;
    iov[1].iov_len = strlen(line);
    iov[2].iov_base = func_field;
    iov[2].iov_len = strlen(func_field);
    r = rustd_journal_sendv(iov, (int)n);
    free(func_field);
    free_iov(iov, n, 3U);
    return r;
}

int sd_journal_printv_with_location(int priority, const char *file, const char *line,
                                    const char *func, const char *format, va_list ap) {
    struct iovec iov[5];
    char priority_field[32];
    char *message = NULL;
    char *message_field = NULL;
    char *func_field = NULL;
    va_list copy;
    int length;
    int r;

    if (priority < 0 || priority > 7 || !file || !line || !func || !format)
        return -EINVAL;
    va_copy(copy, ap);
    length = vasprintf(&message, format, copy);
    va_end(copy);
    if (length < 0)
        return -ENOMEM;
    trim_trailing_whitespace(message);
    if (!*message) {
        free(message);
        return 0;
    }
    if (asprintf(&message_field, "MESSAGE=%s", message) < 0) {
        free(message);
        return -ENOMEM;
    }
    free(message);
    if (snprintf(priority_field, sizeof(priority_field), "PRIORITY=%d", priority) < 0) {
        free(message_field);
        return -EINVAL;
    }
    func_field = code_func_field(func);
    if (!func_field) {
        free(message_field);
        return -ENOMEM;
    }
    iov[0] = (struct iovec){message_field, strlen(message_field)};
    iov[1] = (struct iovec){priority_field, strlen(priority_field)};
    iov[2] = (struct iovec){(void *)file, strlen(file)};
    iov[3] = (struct iovec){(void *)line, strlen(line)};
    iov[4] = (struct iovec){func_field, strlen(func_field)};
    r = rustd_journal_sendv(iov, 5);
    free(message_field);
    free(func_field);
    return r;
}

int sd_journal_print_with_location(int priority, const char *file, const char *line,
                                   const char *func, const char *format, ...) {
    va_list ap;
    int r;
    va_start(ap, format);
    r = sd_journal_printv_with_location(priority, file, line, func, format, ap);
    va_end(ap);
    return r;
}
