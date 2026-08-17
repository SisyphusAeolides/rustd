/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned rustd_device_abi_version(void);

typedef struct rustd_device_ctx rustd_device_ctx;
typedef struct rustd_device rustd_device;
typedef struct rustd_device_enumerate rustd_device_enumerate;
typedef struct rustd_device_monitor rustd_device_monitor;
typedef struct rustd_device_list_entry rustd_device_list_entry;
typedef struct rustd_device_hwdb rustd_device_hwdb;
typedef struct rustd_device_queue rustd_device_queue;

rustd_device_ctx *rustd_device_ctx_new(void);
rustd_device_ctx *rustd_device_ctx_ref(rustd_device_ctx *ctx);
rustd_device_ctx *rustd_device_ctx_unref(rustd_device_ctx *ctx);

rustd_device *rustd_device_ref(rustd_device *device);
rustd_device *rustd_device_unref(rustd_device *device);
rustd_device *rustd_device_new_from_syspath(rustd_device_ctx *ctx, const char *syspath);
rustd_device *rustd_device_new_from_devnum(rustd_device_ctx *ctx, char type, dev_t devnum);
rustd_device *rustd_device_new_from_subsystem_sysname(
    rustd_device_ctx *ctx, const char *subsystem, const char *sysname);

const char *rustd_device_get_syspath(rustd_device *device);
const char *rustd_device_get_sysname(rustd_device *device);
const char *rustd_device_get_subsystem(rustd_device *device);
const char *rustd_device_get_devnode(rustd_device *device);
const char *rustd_device_get_devpath(rustd_device *device);
const char *rustd_device_get_devtype(rustd_device *device);
const char *rustd_device_get_driver(rustd_device *device);
const char *rustd_device_get_action(rustd_device *device);
const char *rustd_device_get_property_value(rustd_device *device, const char *key);
const char *rustd_device_get_sysattr_value(rustd_device *device, const char *key);
int rustd_device_set_sysattr_value(rustd_device *device, const char *key, const char *value);
dev_t rustd_device_get_devnum(rustd_device *device);
int rustd_device_get_is_initialized(rustd_device *device);
rustd_device *rustd_device_get_parent(rustd_device *device);
rustd_device *rustd_device_get_parent_with_subsystem_devtype(
    rustd_device *device, const char *subsystem, const char *devtype);

rustd_device_list_entry *rustd_device_get_properties_list_entry(rustd_device *device);
rustd_device_list_entry *rustd_device_get_devlinks_list_entry(rustd_device *device);
rustd_device_list_entry *rustd_device_list_entry_get_next(rustd_device_list_entry *entry);
const char *rustd_device_list_entry_get_name(rustd_device_list_entry *entry);
const char *rustd_device_list_entry_get_value(rustd_device_list_entry *entry);

rustd_device_enumerate *rustd_device_enumerate_new(rustd_device_ctx *ctx);
rustd_device_enumerate *rustd_device_enumerate_unref(rustd_device_enumerate *enumerate);
int rustd_device_enumerate_add_match_subsystem(
    rustd_device_enumerate *enumerate, const char *subsystem);
int rustd_device_enumerate_add_match_property(
    rustd_device_enumerate *enumerate, const char *property, const char *value);
int rustd_device_enumerate_add_match_sysname(
    rustd_device_enumerate *enumerate, const char *sysname);
int rustd_device_enumerate_scan_devices(rustd_device_enumerate *enumerate);
rustd_device_list_entry *rustd_device_enumerate_get_list_entry(
    rustd_device_enumerate *enumerate);

rustd_device_monitor *rustd_device_monitor_new_from_netlink(
    rustd_device_ctx *ctx, const char *name);
rustd_device_monitor *rustd_device_monitor_unref(rustd_device_monitor *monitor);
int rustd_device_monitor_filter_add_match_subsystem_devtype(
    rustd_device_monitor *monitor, const char *subsystem, const char *devtype);
int rustd_device_monitor_enable_receiving(rustd_device_monitor *monitor);
int rustd_device_monitor_get_fd(rustd_device_monitor *monitor);
rustd_device *rustd_device_monitor_receive_device(rustd_device_monitor *monitor);

rustd_device_hwdb *rustd_device_hwdb_new(void);
rustd_device_hwdb *rustd_device_hwdb_unref(rustd_device_hwdb *hwdb);
rustd_device_list_entry *rustd_device_hwdb_get_properties_list_entry(
    rustd_device_hwdb *hwdb, const char *modalias);

rustd_device_queue *rustd_device_queue_new(rustd_device_ctx *ctx);
rustd_device_queue *rustd_device_queue_unref(rustd_device_queue *queue);
int rustd_device_queue_get_udev_is_active(rustd_device_queue *queue);
int rustd_device_queue_get_queue_is_empty(rustd_device_queue *queue);

#ifdef __cplusplus
}
#endif
