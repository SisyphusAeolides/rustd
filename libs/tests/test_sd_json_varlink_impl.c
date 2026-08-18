/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../compat/sd_json_varlink_abi.h"

static int write_full(int fd, const void *data, size_t length) {
    const char *p = data;
    while (length > 0U) {
        ssize_t n = write(fd, p, length);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static char *read_frame(int fd) {
    char *buffer = NULL;
    size_t used = 0U;
    size_t capacity = 0U;
    for (;;) {
        char byte;
        ssize_t n = read(fd, &byte, 1U);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            free(buffer);
            return NULL;
        }
        if (byte == '\0') {
            if (used + 1U > capacity) {
                char *next = realloc(buffer, used + 1U);
                if (!next) {
                    free(buffer);
                    return NULL;
                }
                buffer = next;
            }
            buffer[used] = '\0';
            return buffer;
        }
        if (used + 1U >= capacity) {
            size_t next_capacity = capacity ? capacity * 2U : 256U;
            char *next = realloc(buffer, next_capacity);
            if (!next) {
                free(buffer);
                return NULL;
            }
            buffer = next;
            capacity = next_capacity;
        }
        buffer[used++] = byte;
    }
}

static void serve_client(int listen_fd) {
    int client = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    assert(client >= 0);

    {
        char *request = read_frame(client);
        assert(request);
        assert(strstr(request, "\"method\":\"io.rustd.Test.Ping\"") != NULL);
        free(request);
        assert(write_full(client,
                          "{\"parameters\":{\"value\":\"pong\",\"n\":2}}\0",
                          sizeof("{\"parameters\":{\"value\":\"pong\",\"n\":2}}\0") - 1U) == 0);
    }
    {
        char *request = read_frame(client);
        assert(request);
        assert(strstr(request, "\"method\":\"io.rustd.Test.Builder\"") != NULL);
        assert(strstr(request, "\"name\":\"rustd\"") != NULL);
        assert(strstr(request, "\"count\":7") != NULL);
        free(request);
        assert(write_full(client,
                          "{\"parameters\":{\"seen\":\"builder\"}}\0",
                          sizeof("{\"parameters\":{\"seen\":\"builder\"}}\0") - 1U) == 0);
    }
    {
        char *request = read_frame(client);
        assert(request);
        assert(strstr(request, "\"method\":\"io.rustd.Test.Error\"") != NULL);
        free(request);
        assert(write_full(client,
                          "{\"error\":\"io.rustd.Test.Failed\",\"parameters\":{\"why\":\"expected\"}}\0",
                          sizeof("{\"error\":\"io.rustd.Test.Failed\",\"parameters\":{\"why\":\"expected\"}}\0") - 1U) == 0);
    }
    {
        char *request = read_frame(client);
        assert(request);
        assert(strstr(request, "\"method\":\"io.rustd.Test.Stream\"") != NULL);
        assert(strstr(request, "\"more\":true") != NULL);
        free(request);
        assert(write_full(client,
                          "{\"parameters\":{\"value\":\"a\"},\"continues\":true}\0"
                          "{\"parameters\":{\"value\":\"b\"}}\0",
                          sizeof("{\"parameters\":{\"value\":\"a\"},\"continues\":true}\0"
                                 "{\"parameters\":{\"value\":\"b\"}}\0") - 1U) == 0);
    }

    close(client);
    close(listen_fd);
    _exit(0);
}

int main(void) {
    char template[] = "/tmp/rustd-varlink-XXXXXX";
    char *directory = mkdtemp(template);
    char socket_path[512];
    struct sockaddr_un sa;
    int listen_fd;
    pid_t child;
    sd_varlink *link = NULL;
    sd_json_variant *parameters = NULL;
    const char *error_id = NULL;
    int status;
    int r;

    assert(directory);
    snprintf(socket_path, sizeof(socket_path), "%s/service.sock", directory);
    assert(strlen(socket_path) < sizeof(sa.sun_path));
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, socket_path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listen_fd >= 0);
    assert(bind(listen_fd, (struct sockaddr *)&sa,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(socket_path) + 1U)) == 0);
    assert(listen(listen_fd, 4) == 0);

    child = fork();
    assert(child >= 0);
    if (child == 0)
        serve_client(listen_fd);
    close(listen_fd);

    assert(sd_varlink_connect_address(&link, socket_path) == 0);
    assert(link);

    r = sd_varlink_call(link, "io.rustd.Test.Ping", NULL, &parameters, &error_id);
    assert(r > 0);
    assert(error_id == NULL);
    assert(parameters);
    assert(sd_json_variant_elements(parameters) == 4U);
    assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(parameters, "value")), "pong") == 0);
    assert(strcmp(sd_json_variant_string(sd_json_variant_by_index(parameters, 0U)), "value") == 0);
    assert(strcmp(sd_json_variant_string(sd_json_variant_by_index(parameters, 1U)), "pong") == 0);

    r = sd_varlink_callb(
        link, "io.rustd.Test.Builder", &parameters, &error_id,
        SD_JSON_BUILD_OBJECT(
            SD_JSON_BUILD_PAIR_STRING("name", "rustd"),
            SD_JSON_BUILD_PAIR_INTEGER("count", 7)));
    assert(r > 0);
    assert(error_id == NULL);
    assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(parameters, "seen")), "builder") == 0);

    r = sd_varlink_call(link, "io.rustd.Test.Error", NULL, &parameters, &error_id);
    assert(r == 0);
    assert(error_id && strcmp(error_id, "io.rustd.Test.Failed") == 0);
    assert(parameters);
    assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(parameters, "why")), "expected") == 0);

    r = sd_varlink_collect(link, "io.rustd.Test.Stream", NULL, &parameters, &error_id);
    assert(r > 0);
    assert(error_id == NULL);
    assert(parameters && sd_json_variant_elements(parameters) == 2U);
    assert(strcmp(sd_json_variant_string(
                      sd_json_variant_by_key(sd_json_variant_by_index(parameters, 0U), "value")),
                  "a") == 0);
    assert(strcmp(sd_json_variant_string(
                      sd_json_variant_by_key(sd_json_variant_by_index(parameters, 1U), "value")),
                  "b") == 0);

    assert(sd_varlink_unref(link) == NULL);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(unlink(socket_path) == 0);
    assert(rmdir(directory) == 0);
    return 0;
}
