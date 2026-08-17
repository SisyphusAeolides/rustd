/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>
#include <stdint.h>

#include <libudev.h>
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

    assert(login_new);
    assert(device_open);
    assert(device_action);
    assert(device_name);
    assert(monitor_new);
    assert(monitor_event);
    assert(flush_matches);
}

int main(void) {
    struct udev *udev;

    verify_function_types();
    udev = udev_new();
    assert(udev);
    assert(udev_ref(udev) == udev);
    assert(udev_unref(udev) == NULL);
    assert(udev_unref(udev) == NULL);
    return 0;
}
