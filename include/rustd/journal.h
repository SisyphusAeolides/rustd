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
int rustd_journal_seek_head(rustd_journal *journal);
int rustd_journal_seek_realtime_usec(rustd_journal *journal, uint64_t usec);
int rustd_journal_seek_monotonic_usec(rustd_journal *journal, uint64_t usec);
int rustd_journal_seek_cursor(rustd_journal *journal, const char *cursor);
int rustd_journal_next(rustd_journal *journal);
int rustd_journal_next_skip(rustd_journal *journal, uint64_t skip);
int rustd_journal_previous(rustd_journal *journal);
int rustd_journal_previous_skip(rustd_journal *journal, uint64_t skip);
int rustd_journal_get_data(rustd_journal *journal, const char *field,
                           const void **data, size_t *length);
int rustd_journal_get_realtime_usec(rustd_journal *journal, uint64_t *usec);
int rustd_journal_get_monotonic_usec(rustd_journal *journal, uint64_t *usec,
                                     uint8_t boot_id[16]);
int rustd_journal_get_cursor(rustd_journal *journal, char **cursor);
int rustd_journal_test_cursor(rustd_journal *journal, const char *cursor);
int rustd_journal_get_cutoff_realtime_usec(rustd_journal *journal,
                                            uint64_t *from, uint64_t *to);
int rustd_journal_get_usage(rustd_journal *journal, uint64_t *bytes);
int rustd_journal_add_match(rustd_journal *journal, const void *data, size_t size);
int rustd_journal_add_disjunction(rustd_journal *journal);
int rustd_journal_add_conjunction(rustd_journal *journal);
void rustd_journal_flush_matches(rustd_journal *journal);
int rustd_journal_enumerate_data(rustd_journal *journal, const void **data, size_t *length);
void rustd_journal_restart_data(rustd_journal *journal);
int rustd_journal_enumerate_fields(rustd_journal *journal, const char **field);
void rustd_journal_restart_fields(rustd_journal *journal);
int rustd_journal_query_unique(rustd_journal *journal, const char *field);
int rustd_journal_enumerate_unique(rustd_journal *journal,
                                   const void **data, size_t *length);
void rustd_journal_restart_unique(rustd_journal *journal);
size_t rustd_journal_get_data_threshold(rustd_journal *journal);
int rustd_journal_set_data_threshold(rustd_journal *journal, size_t threshold);
int rustd_journal_has_runtime_files(rustd_journal *journal);
int rustd_journal_has_persistent_files(rustd_journal *journal);
int rustd_journal_get_fd(rustd_journal *journal);
int rustd_journal_get_events(rustd_journal *journal);
int rustd_journal_get_timeout(rustd_journal *journal, uint64_t *timeout);
int rustd_journal_process(rustd_journal *journal);
int rustd_journal_wait(rustd_journal *journal, uint64_t timeout_usec);

#ifdef __cplusplus
}
#endif
