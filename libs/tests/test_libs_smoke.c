/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <rustd/service.h>
#include <rustd/journal.h>
#include <rustd/device.h>
#include <rustd/login.h>
#include <rustd/manager.h>

int main(void) {
    assert(rustd_service_abi_version() == 1U);
    assert(rustd_journal_abi_version() == 1U);
    assert(rustd_device_abi_version() == 1U);
    assert(rustd_login_abi_version() == 1U);
    assert(rustd_manager_abi_version() == 1U);

    assert(rustd_listen_fds(0) == 0);
    assert(rustd_notify_ready() == 0 || rustd_notify_ready() < 0);

    {
        rustd_device_ctx *ctx = rustd_device_ctx_new();
        rustd_device_enumerate *enumerate;
        assert(ctx);
        enumerate = rustd_device_enumerate_new(ctx);
        assert(enumerate);
        assert(rustd_device_enumerate_add_match_subsystem(enumerate, "net") == 0);
        assert(rustd_device_enumerate_scan_devices(enumerate) == 0);
        rustd_device_enumerate_unref(enumerate);
        rustd_device_ctx_unref(ctx);
    }

    {
        char directory[128];
        char attribute[160];
        rustd_device_ctx *ctx = rustd_device_ctx_new();
        rustd_device *device;
        int fd;

        assert(ctx);
        snprintf(directory, sizeof(directory), "/tmp/rustd-device-smoke-%ld", (long)getpid());
        assert(mkdir(directory, 0700) == 0);
        snprintf(attribute, sizeof(attribute), "%s/control", directory);
        fd = open(attribute, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        assert(fd >= 0);
        assert(write(fd, "prior", 5) == 5);
        assert(close(fd) == 0);

        device = rustd_device_new_from_syspath(ctx, directory);
        assert(device);
        assert(rustd_device_set_sysattr_value(device, "control", "after\n\r") == 0);
        assert(strcmp(rustd_device_get_sysattr_value(device, "control"), "after") == 0);
        assert(rustd_device_set_sysattr_value(device, "control", NULL) == 0);
        assert(strcmp(rustd_device_get_sysattr_value(device, "control"), "after") == 0);
        assert(rustd_device_set_sysattr_value(device, "../escape", "blocked") == -EINVAL);

        rustd_device_unref(device);
        rustd_device_ctx_unref(ctx);
        assert(unlink(attribute) == 0);
        assert(rmdir(directory) == 0);
    }

    {
        rustd_journal *journal = NULL;
        int opened = rustd_journal_open(&journal, "/tmp/rustd-journal-missing");
        if (opened == 0) {
            rustd_journal_unref(journal);
        }
    }

    puts("librustd smoke ok");
    return 0;
}
