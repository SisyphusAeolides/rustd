/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <signal.h>
#include "../../include/rustd/device.h"
#include "../../include/rustd/journal.h"
#include "../../include/rustd/login.h"
#include "sd_bus_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef rustd_login_monitor sd_login_monitor;
typedef rustd_journal sd_journal;
typedef struct sd_device sd_device;
typedef struct sd_device_monitor sd_device_monitor;
typedef int64_t sd_device_action_t;
typedef struct sd_event_source sd_event_source;
typedef struct sd_id128 {
    uint8_t bytes[16];
} sd_id128_t;

int sd_id128_from_string(const char *text, sd_id128_t *ret);
int sd_id128_get_boot(sd_id128_t *ret);
int sd_id128_randomize(sd_id128_t *ret);
char *sd_id128_to_string(sd_id128_t id, char text[33]);
int sd_is_fifo(int fd, const char *path);
int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length);
int sd_event_default(sd_event **ret);
int sd_event_add_io(sd_event *event, sd_event_source **ret, int fd, uint32_t events,
                    void *callback, void *userdata);
int sd_event_add_signal(sd_event *event, sd_event_source **ret, int signal,
                        void *callback, void *userdata);
int sd_event_add_child(sd_event *event, sd_event_source **ret, pid_t pid, int options,
                       void *callback, void *userdata);
int sd_event_add_inotify(sd_event *event, sd_event_source **ret, const char *path,
                         uint32_t mask, void *callback, void *userdata);
int sd_event_exit(sd_event *event, int code);
int sd_event_loop(sd_event *event);
sd_event *sd_event_source_get_event(sd_event_source *source);
int sd_event_source_set_priority(sd_event_source *source, int64_t priority);
sd_event_source *sd_event_source_unref(sd_event_source *source);
sd_event *sd_event_unref(sd_event *event);

int sd_login_monitor_new(const char *category, sd_login_monitor **ret);
sd_login_monitor *sd_login_monitor_unref(sd_login_monitor *monitor);
int sd_login_monitor_flush(sd_login_monitor *monitor);
int sd_login_monitor_get_fd(sd_login_monitor *monitor);
int sd_login_monitor_get_events(sd_login_monitor *monitor);

int sd_device_open(sd_device *device, int flags);
int sd_device_get_action(sd_device *device, sd_device_action_t *ret);
int sd_device_get_devname(sd_device *device, const char **ret);
int sd_device_get_is_initialized(sd_device *device);
int sd_device_monitor_new(sd_device_monitor **ret);
sd_device_monitor *sd_device_monitor_unref(sd_device_monitor *monitor);
int sd_device_monitor_filter_add_match_subsystem_devtype(
    sd_device_monitor *monitor, const char *subsystem, const char *devtype);
sd_event *sd_device_monitor_get_event(sd_device_monitor *monitor);

void sd_journal_flush_matches(sd_journal *journal);
int sd_journal_add_match(sd_journal *journal, const void *data, size_t size);
int sd_journal_add_disjunction(sd_journal *journal);

int sd_seat_can_multi_session(const char *seat);

#ifdef __cplusplus
}
#endif
