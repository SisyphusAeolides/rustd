/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned rustd_journal_abi_version(void);

/* Structured field for binary journal helpers and sendv. */
typedef struct rustd_journal_field {
    const char *key;
    const uint8_t *value;
    size_t value_len;
} rustd_journal_field;

/* Submit iovec KEY=VALUE fields to /run/rustd/journal/socket.
 * Fields whose key starts with '_' are rejected (-EPERM). */
int rustd_journal_sendv(const struct iovec *iov, int n);

/* printf-style helper that builds MESSAGE=... and optional PRIORITY=. */
int rustd_journal_print(int priority, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

/* Opaque journal reader handle. */
typedef struct rustd_journal rustd_journal;

int rustd_journal_open(rustd_journal **ret, const char *directory);
void rustd_journal_unref(rustd_journal *journal);
int rustd_journal_seek_tail(rustd_journal *journal);
int rustd_journal_next(rustd_journal *journal);
int rustd_journal_previous(rustd_journal *journal);
int rustd_journal_previous_skip(rustd_journal *journal, uint64_t skip);
int rustd_journal_get_data(rustd_journal *journal, const char *field,
                           const void **data, size_t *length);
int rustd_journal_get_realtime_usec(rustd_journal *journal, uint64_t *usec);

#ifdef __cplusplus
}
#endif
