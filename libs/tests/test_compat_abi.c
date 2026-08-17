/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libudev.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-device.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-login.h>

static void verify_function_types(void) {
    int (*login_new)(const char *, sd_login_monitor **) = sd_login_monitor_new;
    int (*device_open)(sd_device *, int) = sd_device_open;
    int (*device_action)(sd_device *, sd_device_action_t *) = sd_device_get_action;
    int (*device_name)(sd_device *, const char **) = sd_device_get_devname;
    int (*monitor_new)(sd_device_monitor **) = sd_device_monitor_new;
    sd_event *(*monitor_event)(sd_device_monitor *) = sd_device_monitor_get_event;
    void (*flush_matches)(sd_journal *) = sd_journal_flush_matches;
    int (*set_sysattr)(struct udev_device *, const char *, const char *) =
        udev_device_set_sysattr_value;

    assert(login_new);
    assert(device_open);
    assert(device_action);
    assert(device_name);
    assert(monitor_new);
    assert(monitor_event);
    assert(flush_matches);
    assert(set_sysattr);
}

static void verify_bus_error_semantics(void) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_error unknown = SD_BUS_ERROR_NULL;

    assert(sd_bus_error_get_errno(NULL) == 0);
    assert(sd_bus_error_get_errno(&error) == 0);
    assert(sd_bus_error_set_errno(NULL, EIO) == -EIO);

    assert(sd_bus_error_set_errno(&error, EINVAL) == -EINVAL);
    assert(sd_bus_error_has_name(&error, SD_BUS_ERROR_INVALID_ARGS) > 0);
    assert(sd_bus_error_get_errno(&error) == EINVAL);
    assert(error.message != NULL);
    assert(sd_bus_error_set_errno(&error, EIO) == -EINVAL);
    sd_bus_error_free(&error);
    assert(error.name == NULL);
    assert(error.message == NULL);
    assert(sd_bus_error_get_errno(&error) == 0);

    assert(sd_bus_error_set_errno(&unknown, EDQUOT) == -EDQUOT);
    assert(unknown.name != NULL);
    assert(strncmp(unknown.name, "System.Error.", strlen("System.Error.")) == 0);
    assert(sd_bus_error_get_errno(&unknown) == EDQUOT);
    sd_bus_error_free(&unknown);
}

int main(void) {
    struct udev *udev;

    verify_function_types();
    verify_bus_error_semantics();
    assert(sd_seat_can_multi_session(NULL) > 0);
    assert(sd_seat_can_multi_session("seat0") > 0);
    assert(sd_seat_can_multi_session("arbitrary-seat") > 0);
    udev = udev_new();
    assert(udev);

    {
        char directory[128];
        char attribute[160];
        struct udev_device *device;
        int fd;

        snprintf(directory, sizeof(directory), "/tmp/rustd-udev-compat-%ld", (long)getpid());
        assert(mkdir(directory, 0700) == 0);
        snprintf(attribute, sizeof(attribute), "%s/control", directory);
        fd = open(attribute, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        assert(fd >= 0);
        assert(close(fd) == 0);

        device = udev_device_new_from_syspath(udev, directory);
        assert(device);
        assert(udev_device_set_sysattr_value(device, "control", "compat\n") == 0);
        assert(strcmp(udev_device_get_sysattr_value(device, "control"), "compat") == 0);
        assert(udev_device_set_sysattr_value(device, NULL, "blocked") == -EINVAL);
        assert(udev_device_set_sysattr_value(device, "../escape", "blocked") == -EINVAL);
        assert(udev_device_unref(device) == NULL);

        assert(unlink(attribute) == 0);
        assert(rmdir(directory) == 0);
    }

    assert(udev_ref(udev) == udev);
    assert(udev_unref(udev) == NULL);
    assert(udev_unref(udev) == NULL);
    return 0;
}
