/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
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
