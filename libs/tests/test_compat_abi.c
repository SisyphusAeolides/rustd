/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libudev.h>
#include "../compat/sd_core_abi.h"

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
    struct udev_device *(*from_environment)(struct udev *) =
        udev_device_new_from_environment;
    struct udev_monitor *(*monitor_ref)(struct udev_monitor *) = udev_monitor_ref;

    assert(login_new);
    assert(device_open);
    assert(device_action);
    assert(device_name);
    assert(monitor_new);
    assert(monitor_event);
    assert(flush_matches);
    assert(set_sysattr);
    assert(from_environment);
    assert(monitor_ref);
}

static void verify_bus_error_semantics(void) {
    static const char invalid_args[] = "org.freedesktop.DBus.Error.InvalidArgs";
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_error unknown = SD_BUS_ERROR_NULL;

    assert(sd_bus_error_get_errno(NULL) == 0);
    assert(sd_bus_error_get_errno(&error) == 0);
    assert(sd_bus_error_set_errno(NULL, EIO) == -EIO);

    assert(sd_bus_error_set_errno(&error, EINVAL) == -EINVAL);
    assert(sd_bus_error_has_name(&error, invalid_args) > 0);
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

static void verify_deprecated_seat_semantics(void) {
    assert(sd_seat_can_multi_session("seat0") > 0);
    assert(sd_seat_can_multi_session("arbitrary-seat") > 0);
}

static void verify_id128_semantics(void) {
    sd_id128_t id;
    char text[33];
    assert(sd_id128_from_string("00112233-4455-6677-8899-aabbccddeeff", &id) == 0);
    assert(strcmp(sd_id128_to_string(id, text), "00112233445566778899aabbccddeeff") == 0);
    assert(sd_id128_from_string("not-an-id", &id) == -EINVAL);
    assert(sd_id128_get_boot(&id) == 0);
    assert(sd_id128_randomize(&id) == 0);
}

static void verify_socket_helpers(void) {
    int descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors) == 0);
    assert(sd_is_socket_unix(descriptors[0], SOCK_STREAM, 0, NULL, 0) == 1);
    assert(sd_is_socket_unix(descriptors[0], SOCK_DGRAM, 0, NULL, 0) == 0);
    assert(close(descriptors[0]) == 0);
    assert(close(descriptors[1]) == 0);
}

static int io_event(sd_event_source *source, int fd, uint32_t events, void *userdata) {
    char byte;
    assert(source && sd_event_source_get_event(source));
    assert(events & POLLIN);
    assert(read(fd, &byte, 1U) == 1 && byte == 'x');
    *(int *)userdata = 1;
    return sd_event_exit(sd_event_source_get_event(source), 0);
}

static int signal_event(sd_event_source *source, const struct signalfd_siginfo *info,
                        void *userdata) {
    assert(info->ssi_signo == SIGUSR1);
    *(int *)userdata = 1;
    return sd_event_exit(sd_event_source_get_event(source), 0);
}

static int child_event(sd_event_source *source, const siginfo_t *info, void *userdata) {
    assert(info->si_code == CLD_EXITED && info->si_status == 7);
    *(int *)userdata = 1;
    return sd_event_exit(sd_event_source_get_event(source), 0);
}

static int inotify_event(sd_event_source *source, const struct inotify_event *info,
                         void *userdata) {
    assert(info->mask & IN_CLOSE_WRITE);
    *(int *)userdata = 1;
    return sd_event_exit(sd_event_source_get_event(source), 0);
}

static void verify_event_semantics(void) {
    sd_event *event = NULL;
    sd_event_source *source = NULL;
    int descriptors[2];
    int called = 0;
    pid_t child;
    char directory[] = "/tmp/rustd-event-XXXXXX";
    char path[160];
    int fd;

    assert(pipe2(descriptors, O_CLOEXEC) == 0);
    assert(sd_event_default(&event) == 0);
    assert(sd_event_add_io(event, &source, descriptors[0], POLLIN, io_event, &called) == 0);
    assert(sd_event_source_set_priority(source, -10) == 0);
    assert(write(descriptors[1], "x", 1U) == 1);
    assert(sd_event_loop(event) == 0 && called == 1);
    source = sd_event_source_unref(source);
    event = sd_event_unref(event);
    close(descriptors[0]); close(descriptors[1]);

    called = 0;
    assert(sd_event_default(&event) == 0);
    assert(sd_event_add_signal(event, &source, SIGUSR1, signal_event, &called) == 0);
    assert(kill(getpid(), SIGUSR1) == 0);
    assert(sd_event_loop(event) == 0 && called == 1);
    source = sd_event_source_unref(source);
    event = sd_event_unref(event);

    called = 0;
    assert(sd_event_default(&event) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
        _exit(7);
    assert(sd_event_add_child(event, &source, child, WEXITED, child_event, &called) == 0);
    assert(sd_event_loop(event) == 0 && called == 1);
    assert(waitpid(child, NULL, 0) == child);
    source = sd_event_source_unref(source);
    event = sd_event_unref(event);

    called = 0;
    assert(mkdtemp(directory));
    snprintf(path, sizeof(path), "%s/file", directory);
    assert(sd_event_default(&event) == 0);
    assert(sd_event_add_inotify(event, &source, directory, IN_CLOSE_WRITE,
                                inotify_event, &called) == 0);
    fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, "x", 1U) == 1 && close(fd) == 0);
    assert(sd_event_loop(event) == 0 && called == 1);
    source = sd_event_source_unref(source);
    event = sd_event_unref(event);
    assert(unlink(path) == 0 && rmdir(directory) == 0);
}

int main(void) {
    struct udev *udev;

    verify_function_types();
    verify_bus_error_semantics();
    verify_deprecated_seat_semantics();
    verify_id128_semantics();
    verify_socket_helpers();
    verify_event_semantics();
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
        assert(udev_device_get_udev(device) == udev);
        assert(udev_device_set_sysattr_value(device, "control", "compat\n") == 0);
        assert(strcmp(udev_device_get_sysattr_value(device, "control"), "compat") == 0);
        assert(udev_device_set_sysattr_value(device, NULL, "blocked") == -EINVAL);
        assert(udev_device_set_sysattr_value(device, "../escape", "blocked") == -EINVAL);
        assert(udev_device_unref(device) == NULL);

        assert(unlink(attribute) == 0);
        assert(rmdir(directory) == 0);
    }

    assert(unsetenv("DEVPATH") == 0);
    errno = 0;
    assert(udev_device_new_from_environment(udev) == NULL);
    assert(errno == ENODEV);

    assert(udev_ref(udev) == udev);
    assert(udev_unref(udev) == NULL);
    assert(udev_unref(udev) == NULL);
    return 0;
}
