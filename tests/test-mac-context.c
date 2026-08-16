/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE

#include "spawn.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static rustd_spawn_params spawn_params(const char *const *argv) {
    rustd_spawn_params params;
    memset(&params, 0, sizeof(params));
    params.path = argv[0];
    params.argv = argv;
    params.uid = (uid_t)-1;
    params.gid = (gid_t)-1;
    params.stdin_fd = -1;
    params.stdout_fd = -1;
    params.stderr_fd = -1;
    params.notify_fd = -1;
    params.cap_bounding_set = UINT64_MAX;
    params.idle_read_fd = -1;
    params.idle_write_fd = -1;
    params.wait_for_exec = 1;
    return params;
}

static void wait_success(pid_t pid) {
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
}

static int selinux_enabled(void) {
    return access("/sys/fs/selinux/enforce", F_OK) == 0;
}

static int apparmor_enabled(void) {
    int fd = open("/sys/module/apparmor/parameters/enabled", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    char value = '\0';
    ssize_t length;
    do {
        length = read(fd, &value, 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    return length == 1 && (value == 'Y' || value == 'y' || value == '1');
}

int main(void) {
    const char *argv[] = { "/bin/true", NULL };

    rustd_spawn_params ignored = spawn_params(argv);
    ignored.selinux_context = "rustd_invalid_context";
    ignored.selinux_context_ignore = 1;
    ignored.apparmor_profile = "rustd-invalid-profile";
    ignored.apparmor_profile_ignore = 1;

    pid_t pid = rustd_spawn(&ignored);
    assert(pid > 0);
    wait_success(pid);

    rustd_spawn_params strict = spawn_params(argv);
    strict.selinux_context = "rustd_invalid_context";
    strict.apparmor_profile = "rustd-invalid-profile";

    pid = rustd_spawn(&strict);
    if (selinux_enabled() || apparmor_enabled()) {
        assert(pid < 0);
    } else {
        assert(pid > 0);
        wait_success(pid);
    }

    puts("MAC execution context gate: PASS");
    return 0;
}
