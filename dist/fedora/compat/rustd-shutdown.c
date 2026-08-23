/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

static const char *program_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int invoke_rustctl(const char *verb) {
    if (access("/run/rustd/ctl.sock", F_OK) != 0 || access("/usr/bin/rustctl", X_OK) != 0)
        return -1;
    execl("/usr/bin/rustctl", "rustctl", verb, (char *)NULL);
    return -1;
}

static int transition(const char *verb, int command) {
    const char *dry_run = getenv("RUSTD_SHUTDOWN_DRY_RUN");
    if (dry_run && strcmp(dry_run, "0") != 0) {
        puts(verb);
        return 0;
    }
    (void)invoke_rustctl(verb);
    sync();
    if (reboot(command) < 0) {
        fprintf(stderr, "%s: reboot syscall failed: %s\n", verb, strerror(errno));
        return 1;
    }
    return 0;
}

static int shutdown_action(int argc, char **argv) {
    int index;
    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "-r") == 0 || strcmp(argv[index], "--reboot") == 0)
            return RB_AUTOBOOT;
        if (strcmp(argv[index], "-H") == 0 || strcmp(argv[index], "--halt") == 0)
            return RB_HALT_SYSTEM;
        if (strcmp(argv[index], "-P") == 0 || strcmp(argv[index], "--poweroff") == 0)
            return RB_POWER_OFF;
    }
    return RB_POWER_OFF;
}

int main(int argc, char **argv) {
    const char *name = program_name(argv[0]);
    int command;

    if (strcmp(name, "reboot") == 0)
        return transition("reboot", RB_AUTOBOOT);
    if (strcmp(name, "poweroff") == 0)
        return transition("poweroff", RB_POWER_OFF);
    if (strcmp(name, "halt") == 0)
        return transition("poweroff", RB_HALT_SYSTEM);
    if (strcmp(name, "shutdown") == 0) {
        command = shutdown_action(argc, argv);
        return transition(command == RB_AUTOBOOT ? "reboot" : "poweroff", command);
    }
    if (strcmp(name, "telinit") == 0) {
        if (argc != 2) {
            fputs("telinit: exactly one runlevel is required\n", stderr);
            return 64;
        }
        if (strcmp(argv[1], "0") == 0)
            return transition("poweroff", RB_POWER_OFF);
        if (strcmp(argv[1], "6") == 0)
            return transition("reboot", RB_AUTOBOOT);
        fprintf(stderr, "telinit: runlevel %s is not a machine transition\n", argv[1]);
        return 95;
    }
    if (strcmp(name, "runlevel") == 0) {
        puts("N N");
        return 0;
    }
    fprintf(stderr, "unsupported RustD shutdown compatibility name: %s\n", name);
    return 64;
}
