/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* certification trigger */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

static char *captured[32];
static int captured_n;
static int capture_result;

static void clear_capture(void) {
    for (int i = 0; i < captured_n; ++i)
        free(captured[i]);
    memset(captured, 0, sizeof(captured));
    captured_n = 0;
    capture_result = 0;
}

int rustd_journal_sendv(const struct iovec *iov, int n) {
    assert(iov != NULL);
    assert(n > 0 && n <= (int)(sizeof(captured) / sizeof(captured[0])));
    clear_capture();
    captured_n = n;
    for (int i = 0; i < n; ++i) {
        captured[i] = malloc(iov[i].iov_len + 1U);
        assert(captured[i] != NULL);
        memcpy(captured[i], iov[i].iov_base, iov[i].iov_len);
        captured[i][iov[i].iov_len] = 0;
    }
    return capture_result;
}

int sd_journal_send(const char *format, ...);
int sd_journal_send_with_location(const char *file, const char *line, const char *func,
                                  const char *format, ...);
int sd_journal_print_with_location(int priority, const char *file, const char *line,
                                   const char *func, const char *format, ...);
int sd_journal_printv_with_location(int priority, const char *file, const char *line,
                                    const char *func, const char *format, va_list ap);

static int call_printv(int priority, const char *file, const char *line, const char *func,
                       const char *format, ...) {
    va_list ap;
    int r;
    va_start(ap, format);
    r = sd_journal_printv_with_location(priority, file, line, func, format, ap);
    va_end(ap);
    return r;
}

static void assert_field(int index, const char *expected) {
    assert(index >= 0 && index < captured_n);
    assert(strcmp(captured[index], expected) == 0);
}

int main(void) {
    assert(sd_journal_send("MESSAGE=%s   ", "hello",
                           "PRIORITY=%d", 5,
                           "COUNT=%lld", (long long)1234567890123LL,
                           "PTR=%p", (void *)(uintptr_t)0x1234,
                           NULL) == 0);
    assert(captured_n == 4);
    assert_field(0, "MESSAGE=hello");
    assert_field(1, "PRIORITY=5");
    assert_field(2, "COUNT=1234567890123");
    assert(strncmp(captured[3], "PTR=", 4) == 0);

    assert(sd_journal_send_with_location(
               "CODE_FILE=source.c", "CODE_LINE=77", "worker",
               "MESSAGE=%s", "located",
               "VALUE=%lu", (unsigned long)42,
               NULL) == 0);
    assert(captured_n == 5);
    assert_field(0, "CODE_FILE=source.c");
    assert_field(1, "CODE_LINE=77");
    assert_field(2, "CODE_FUNC=worker");
    assert_field(3, "MESSAGE=located");
    assert_field(4, "VALUE=42");

    assert(sd_journal_print_with_location(
               4, "CODE_FILE=print.c", "CODE_LINE=8", "printer",
               "%s %d   ", "hello", 9) == 0);
    assert(captured_n == 5);
    assert_field(0, "MESSAGE=hello 9");
    assert_field(1, "PRIORITY=4");
    assert_field(2, "CODE_FILE=print.c");
    assert_field(3, "CODE_LINE=8");
    assert_field(4, "CODE_FUNC=printer");

    assert(call_printv(2, "CODE_FILE=v.c", "CODE_LINE=3", "vf", "%s", "vector") == 0);
    assert(captured_n == 5);
    assert_field(0, "MESSAGE=vector");
    assert_field(1, "PRIORITY=2");
    assert_field(4, "CODE_FUNC=vf");

    clear_capture();
    assert(sd_journal_print_with_location(
               3, "CODE_FILE=e.c", "CODE_LINE=1", "empty", "   ") == 0);
    assert(captured_n == 0);
    assert(sd_journal_print_with_location(
               8, "CODE_FILE=e.c", "CODE_LINE=1", "bad", "x") < 0);
    assert(sd_journal_send(NULL) < 0);
    clear_capture();
    return 0;
}
