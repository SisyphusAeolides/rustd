/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rustd/journal.h>

static void write_fixture(const char *directory) {
    char path[512];
    FILE *f;
    snprintf(path, sizeof(path), "%s/entries.log", directory);
    f = fopen(path, "w");
    assert(f);
    fputs("MESSAGE=alpha\nPRIORITY=5\nUNIT=one.service\nREALTIME_USEC=100\nMONOTONIC_USEC=10\n\n", f);
    fputs("MESSAGE=beta\nPRIORITY=6\nUNIT=two.service\nREALTIME_USEC=200\nMONOTONIC_USEC=20\n\n", f);
    fputs("MESSAGE=gamma\nPRIORITY=5\nUNIT=two.service\nREALTIME_USEC=300\nMONOTONIC_USEC=30\n\n", f);
    assert(fclose(f) == 0);
}

static const char *field_string(rustd_journal *j, const char *field, char *buf, size_t cap) {
    const void *data = NULL;
    size_t length = 0;
    assert(rustd_journal_get_data(j, field, &data, &length) == 0);
    {
        const char *equals = memchr(data, '=', length);
        size_t value_length;
        assert(equals != NULL);
        value_length = length - (size_t)(equals + 1 - (const char *)data);
        assert(value_length + 1U <= cap);
        memcpy(buf, equals + 1, value_length);
        buf[value_length] = '\0';
    }
    return buf;
}

int main(void) {
    char template[] = "/tmp/rustd-journal-filter-XXXXXX";
    char *directory = mkdtemp(template);
    rustd_journal *j = NULL;
    char value[128];
    char path[512];
    uint64_t usec = 0;

    assert(directory);
    write_fixture(directory);
    assert(rustd_journal_open(&j, directory) == 0);
    assert(j);

    /* Framed multi-field entries are readable. */
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "alpha") == 0);
    assert(rustd_journal_get_realtime_usec(j, &usec) == 0 && usec == 100U);

    {
        char *cursor = NULL;
        const void *data;
        const char *field;
        size_t length;
        uint64_t from = 0, to = 0, bytes = 0;
        assert(rustd_journal_get_cursor(j, &cursor) == 0);
        assert(rustd_journal_test_cursor(j, cursor) == 1);
        assert(rustd_journal_get_cutoff_realtime_usec(j, &from, &to) == 1);
        assert(from == 100U && to == 300U);
        assert(rustd_journal_get_usage(j, &bytes) == 0 && bytes > 0U);
        assert(rustd_journal_get_data_threshold(j) == 64U * 1024U);
        assert(rustd_journal_set_data_threshold(j, 8U) == 0);
        assert(rustd_journal_enumerate_data(j, &data, &length) == 1 && length == 8U);
        rustd_journal_restart_data(j);
        assert(rustd_journal_enumerate_data(j, &data, &length) == 1);
        assert(memcmp(data, "MESSAGE=", 8U) == 0);
        assert(rustd_journal_enumerate_fields(j, &field) == 1 && field != NULL);
        rustd_journal_restart_fields(j);
        assert(rustd_journal_query_unique(j, "PRIORITY") == 0);
        assert(rustd_journal_enumerate_unique(j, &data, &length) == 1);
        assert(length == strlen("PRIORITY=5"));
        rustd_journal_restart_unique(j);
        assert(rustd_journal_set_data_threshold(j, 0U) == 0);
        assert(rustd_journal_seek_cursor(j, cursor) == 0);
        assert(rustd_journal_next(j) == 1);
        assert(rustd_journal_test_cursor(j, cursor) == 1);
        free(cursor);
    }

    assert(rustd_journal_seek_realtime_usec(j, 200U) == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "beta") == 0);
    assert(rustd_journal_seek_monotonic_usec(j, 30U) == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "gamma") == 0);

    /* Same-field matches are an implicit OR. */
    assert(rustd_journal_add_match(j, "MESSAGE=alpha", 0) == 0);
    assert(rustd_journal_add_match(j, "MESSAGE=gamma", 0) == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "alpha") == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "gamma") == 0);
    assert(rustd_journal_next(j) == 0);

    /* Different fields are ANDed. */
    rustd_journal_flush_matches(j);
    assert(rustd_journal_add_match(j, "PRIORITY=5", 0) == 0);
    assert(rustd_journal_add_match(j, "UNIT=two.service", 0) == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "gamma") == 0);
    assert(rustd_journal_next(j) == 0);

    /* Explicit disjunction creates an OR term. */
    rustd_journal_flush_matches(j);
    assert(rustd_journal_add_match(j, "MESSAGE=alpha", 0) == 0);
    assert(rustd_journal_add_disjunction(j) == 0);
    assert(rustd_journal_add_match(j, "MESSAGE=beta", 0) == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "alpha") == 0);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "beta") == 0);
    assert(rustd_journal_next(j) == 0);

    /* Flush restores unfiltered iteration and resets position. */
    rustd_journal_flush_matches(j);
    assert(rustd_journal_next(j) == 1);
    assert(strcmp(field_string(j, "MESSAGE", value, sizeof(value)), "alpha") == 0);

    rustd_journal_unref(j);
    snprintf(path, sizeof(path), "%s/entries.log", directory);
    assert(unlink(path) == 0);
    assert(rmdir(directory) == 0);
    return 0;
}
