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
    fputs("MESSAGE=alpha\nPRIORITY=5\nUNIT=one.service\nREALTIME_USEC=100\n\n", f);
    fputs("MESSAGE=beta\nPRIORITY=6\nUNIT=two.service\nREALTIME_USEC=200\n\n", f);
    fputs("MESSAGE=gamma\nPRIORITY=5\nUNIT=two.service\nREALTIME_USEC=300\n\n", f);
    assert(fclose(f) == 0);
}

static const char *field_string(rustd_journal *j, const char *field, char *buf, size_t cap) {
    const void *data = NULL;
    size_t length = 0;
    assert(rustd_journal_get_data(j, field, &data, &length) == 0);
    assert(length + 1U <= cap);
    memcpy(buf, data, length);
    buf[length] = '\0';
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
