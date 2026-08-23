/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* libudev.so.1 compatibility shim over librustd_device.so.1 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <rustd/device.h>

struct udev {
    unsigned refs;
    rustd_device_ctx *ctx;
};

struct udev_device {
    unsigned refs;
    struct udev *udev;
    rustd_device *dev;
    struct udev_device *cached_children;
    struct udev_device *next_cached;
};

struct udev_enumerate {
    struct udev *udev;
    rustd_device_enumerate *enumerate;
};

struct udev_monitor {
    unsigned refs;
    struct udev *udev;
    rustd_device_monitor *monitor;
};

/* Opaque alias of rustd_device_list_entry — never heap-wrapped. */
struct udev_list_entry;

struct udev *udev_new(void) {
    rustd_device_ctx *ctx = rustd_device_ctx_new();
    struct udev *udev;
    if (!ctx)
        return NULL;
    udev = calloc(1, sizeof(*udev));
    if (!udev) {
        rustd_device_ctx_unref(ctx);
        return NULL;
    }
    udev->refs = 1U;
    udev->ctx = ctx;
    return udev;
}

struct udev *udev_ref(struct udev *udev) {
    if (udev)
        udev->refs++;
    return udev;
}

struct udev *udev_unref(struct udev *udev) {
    if (!udev)
        return NULL;
    if (--udev->refs > 0U)
        return NULL;
    rustd_device_ctx_unref(udev->ctx);
    free(udev);
    return NULL;
}

struct udev_device *udev_device_ref(struct udev_device *device) {
    if (!device)
        return NULL;
    device->refs++;
    return device;
}

struct udev_device *udev_device_unref(struct udev_device *device) {
    struct udev_device *child;
    if (!device)
        return NULL;
    if (--device->refs > 0U)
        return NULL;
    child = device->cached_children;
    while (child) {
        struct udev_device *next = child->next_cached;
        child->next_cached = NULL;
        (void)udev_device_unref(child);
        child = next;
    }
    udev_unref(device->udev);
    rustd_device_unref(device->dev);
    free(device);
    return NULL;
}

static struct udev_device *wrap_device(struct udev *udev, rustd_device *dev) {
    struct udev_device *out;
    if (!dev)
        return NULL;
    out = calloc(1, sizeof(*out));
    if (!out) {
        rustd_device_unref(dev);
        return NULL;
    }
    out->refs = 1U;
    out->udev = udev_ref(udev);
    out->dev = dev;
    return out;
}

static struct udev_device *cache_borrowed_device(
    struct udev_device *owner, rustd_device *dev) {
    struct udev_device *cached;
    const char *syspath;

    if (!owner || !dev)
        return NULL;
    syspath = rustd_device_get_syspath(dev);
    for (cached = owner->cached_children; cached; cached = cached->next_cached) {
        const char *candidate = rustd_device_get_syspath(cached->dev);
        if (syspath && candidate && strcmp(syspath, candidate) == 0) {
            rustd_device_unref(dev);
            return cached;
        }
    }
    cached = wrap_device(owner->udev, dev);
    if (!cached)
        return NULL;
    cached->next_cached = owner->cached_children;
    owner->cached_children = cached;
    return cached;
}

struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath) {
    if (!udev || !syspath)
        return NULL;
    return wrap_device(udev, rustd_device_new_from_syspath(udev->ctx, syspath));
}

struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum) {
    if (!udev)
        return NULL;
    return wrap_device(udev, rustd_device_new_from_devnum(udev->ctx, type, devnum));
}

struct udev_device *udev_device_new_from_subsystem_sysname(
    struct udev *udev, const char *subsystem, const char *sysname) {
    if (!udev)
        return NULL;
    return wrap_device(udev,
        rustd_device_new_from_subsystem_sysname(udev->ctx, subsystem, sysname));
}

struct udev_device *udev_device_new_from_environment(struct udev *udev) {
    const char *devpath;
    char *syspath;
    struct udev_device *device;

    if (!udev)
        return NULL;
    devpath = getenv("DEVPATH");
    if (!devpath || devpath[0] != '/') {
        errno = ENODEV;
        return NULL;
    }
    if (asprintf(&syspath, "/sys%s", devpath) < 0)
        return NULL;
    device = udev_device_new_from_syspath(udev, syspath);
    free(syspath);
    return device;
}

struct udev *udev_device_get_udev(struct udev_device *device) {
    return device ? device->udev : NULL;
}

const char *udev_device_get_action(struct udev_device *device) {
    return device ? rustd_device_get_action(device->dev) : NULL;
}
const char *udev_device_get_devnode(struct udev_device *device) {
    return device ? rustd_device_get_devnode(device->dev) : NULL;
}
dev_t udev_device_get_devnum(struct udev_device *device) {
    return device ? rustd_device_get_devnum(device->dev) : (dev_t)0;
}
const char *udev_device_get_devpath(struct udev_device *device) {
    return device ? rustd_device_get_devpath(device->dev) : NULL;
}
const char *udev_device_get_devtype(struct udev_device *device) {
    return device ? rustd_device_get_devtype(device->dev) : NULL;
}
const char *udev_device_get_driver(struct udev_device *device) {
    return device ? rustd_device_get_driver(device->dev) : NULL;
}
int udev_device_get_is_initialized(struct udev_device *device) {
    return device ? rustd_device_get_is_initialized(device->dev) : 0;
}
struct udev_device *udev_device_get_parent(struct udev_device *device) {
    return device
        ? cache_borrowed_device(device, rustd_device_get_parent(device->dev))
        : NULL;
}
struct udev_device *udev_device_get_parent_with_subsystem_devtype(
    struct udev_device *device, const char *subsystem, const char *devtype) {
    if (!device)
        return NULL;
    return cache_borrowed_device(
        device, rustd_device_get_parent_with_subsystem_devtype(
                    device->dev, subsystem, devtype));
}

/* List entries are owned by the underlying rustd_device; cast opaquely. */
static struct udev_list_entry *wrap_list(rustd_device_list_entry *entry) {
    return (struct udev_list_entry *)entry;
}

struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *device) {
    return device ? wrap_list(rustd_device_get_properties_list_entry(device->dev)) : NULL;
}
struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *device) {
    return device ? wrap_list(rustd_device_get_devlinks_list_entry(device->dev)) : NULL;
}
const char *udev_device_get_property_value(struct udev_device *device, const char *key) {
    return device ? rustd_device_get_property_value(device->dev, key) : NULL;
}
const char *udev_device_get_subsystem(struct udev_device *device) {
    return device ? rustd_device_get_subsystem(device->dev) : NULL;
}
const char *udev_device_get_sysattr_value(struct udev_device *device, const char *key) {
    return device ? rustd_device_get_sysattr_value(device->dev, key) : NULL;
}
const char *udev_device_get_sysname(struct udev_device *device) {
    return device ? rustd_device_get_sysname(device->dev) : NULL;
}
const char *udev_device_get_syspath(struct udev_device *device) {
    return device ? rustd_device_get_syspath(device->dev) : NULL;
}
unsigned long long udev_device_get_seqnum(struct udev_device *device) {
    (void)device;
    return 0;
}
const char *udev_device_get_sysnum(struct udev_device *device) {
    const char *name = udev_device_get_sysname(device);
    if (!name)
        return NULL;
    while (*name && (*name < '0' || *name > '9'))
        name++;
    return *name ? name : NULL;
}
struct udev_list_entry *udev_device_get_sysattr_list_entry(struct udev_device *device) {
    (void)device;
    return NULL;
}
struct udev_list_entry *udev_device_get_tags_list_entry(struct udev_device *device) {
    (void)device;
    return NULL;
}
struct udev_list_entry *udev_device_get_current_tags_list_entry(struct udev_device *device) {
    (void)device;
    return NULL;
}
unsigned long long udev_device_get_usec_since_initialized(struct udev_device *device) {
    (void)device;
    return 0;
}
int udev_device_has_tag(struct udev_device *device, const char *tag) {
    (void)device;
    (void)tag;
    return 0;
}
int udev_device_set_sysattr_value(struct udev_device *device, const char *key, const char *value) {
    if (!device)
        return -EINVAL;
    return rustd_device_set_sysattr_value(device->dev, key, value);
}

struct udev_enumerate *udev_enumerate_new(struct udev *udev) {
    struct udev_enumerate *enumerate;
    if (!udev)
        return NULL;
    enumerate = calloc(1, sizeof(*enumerate));
    if (!enumerate)
        return NULL;
    enumerate->udev = udev_ref(udev);
    enumerate->enumerate = rustd_device_enumerate_new(udev->ctx);
    if (!enumerate->enumerate) {
        udev_unref(enumerate->udev);
        free(enumerate);
        return NULL;
    }
    return enumerate;
}

struct udev_enumerate *udev_enumerate_unref(struct udev_enumerate *enumerate) {
    if (!enumerate)
        return NULL;
    rustd_device_enumerate_unref(enumerate->enumerate);
    udev_unref(enumerate->udev);
    free(enumerate);
    return NULL;
}

int udev_enumerate_add_match_subsystem(struct udev_enumerate *enumerate, const char *subsystem) {
    return enumerate
        ? rustd_device_enumerate_add_match_subsystem(enumerate->enumerate, subsystem)
        : -EINVAL;
}
int udev_enumerate_add_match_property(
    struct udev_enumerate *enumerate, const char *property, const char *value) {
    return enumerate ? rustd_device_enumerate_add_match_property(
                           enumerate->enumerate, property, value)
                     : -EINVAL;
}
int udev_enumerate_add_match_sysname(struct udev_enumerate *enumerate, const char *sysname) {
    return enumerate
        ? rustd_device_enumerate_add_match_sysname(enumerate->enumerate, sysname)
        : -EINVAL;
}
int udev_enumerate_add_match_sysattr(
    struct udev_enumerate *enumerate, const char *sysattr, const char *value) {
    (void)enumerate;
    (void)sysattr;
    (void)value;
    return 0;
}
int udev_enumerate_add_match_tag(struct udev_enumerate *enumerate, const char *tag) {
    (void)enumerate;
    (void)tag;
    return 0;
}
int udev_enumerate_add_match_is_initialized(struct udev_enumerate *enumerate) {
    (void)enumerate;
    return 0;
}
int udev_enumerate_add_nomatch_subsystem(struct udev_enumerate *enumerate, const char *subsystem) {
    (void)enumerate;
    (void)subsystem;
    return 0;
}
int udev_enumerate_add_nomatch_sysattr(
    struct udev_enumerate *enumerate, const char *sysattr, const char *value) {
    (void)enumerate;
    (void)sysattr;
    (void)value;
    return 0;
}
int udev_enumerate_add_syspath(struct udev_enumerate *enumerate, const char *syspath) {
    (void)enumerate;
    (void)syspath;
    return 0;
}
int udev_enumerate_scan_devices(struct udev_enumerate *enumerate) {
    return enumerate ? rustd_device_enumerate_scan_devices(enumerate->enumerate) : -EINVAL;
}
int udev_enumerate_scan_subsystems(struct udev_enumerate *enumerate) {
    return udev_enumerate_scan_devices(enumerate);
}
struct udev_list_entry *udev_enumerate_get_list_entry(struct udev_enumerate *enumerate) {
    return enumerate
        ? wrap_list(rustd_device_enumerate_get_list_entry(enumerate->enumerate))
        : NULL;
}
struct udev *udev_enumerate_get_udev(struct udev_enumerate *enumerate) {
    return enumerate ? enumerate->udev : NULL;
}

struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *entry) {
    return wrap_list(
        rustd_device_list_entry_get_next((rustd_device_list_entry *)entry));
}
const char *udev_list_entry_get_name(struct udev_list_entry *entry) {
    return entry
        ? rustd_device_list_entry_get_name((rustd_device_list_entry *)entry)
        : NULL;
}
const char *udev_list_entry_get_value(struct udev_list_entry *entry) {
    return entry
        ? rustd_device_list_entry_get_value((rustd_device_list_entry *)entry)
        : NULL;
}

struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev, const char *name) {
    struct udev_monitor *monitor;
    if (!udev)
        return NULL;
    monitor = calloc(1, sizeof(*monitor));
    if (!monitor)
        return NULL;
    monitor->refs = 1U;
    monitor->udev = udev_ref(udev);
    monitor->monitor = rustd_device_monitor_new_from_netlink(udev->ctx, name ? name : "udev");
    if (!monitor->monitor) {
        udev_unref(monitor->udev);
        free(monitor);
        return NULL;
    }
    return monitor;
}
struct udev_monitor *udev_monitor_unref(struct udev_monitor *monitor) {
    if (!monitor)
        return NULL;
    if (--monitor->refs > 0U)
        return NULL;
    rustd_device_monitor_unref(monitor->monitor);
    udev_unref(monitor->udev);
    free(monitor);
    return NULL;
}
struct udev_monitor *udev_monitor_ref(struct udev_monitor *monitor) {
    if (monitor)
        monitor->refs++;
    return monitor;
}
int udev_monitor_filter_add_match_subsystem_devtype(
    struct udev_monitor *monitor, const char *subsystem, const char *devtype) {
    return monitor ? rustd_device_monitor_filter_add_match_subsystem_devtype(
                         monitor->monitor, subsystem, devtype)
                   : -EINVAL;
}
int udev_monitor_enable_receiving(struct udev_monitor *monitor) {
    return monitor ? rustd_device_monitor_enable_receiving(monitor->monitor) : -EINVAL;
}
int udev_monitor_get_fd(struct udev_monitor *monitor) {
    return monitor ? rustd_device_monitor_get_fd(monitor->monitor) : -EINVAL;
}
struct udev_device *udev_monitor_receive_device(struct udev_monitor *monitor) {
    return monitor ? wrap_device(monitor->udev,
                                 rustd_device_monitor_receive_device(monitor->monitor)) : NULL;
}
int udev_monitor_set_receive_buffer_size(struct udev_monitor *monitor, int size) {
    (void)monitor;
    (void)size;
    return 0;
}

struct udev *udev_monitor_get_udev(struct udev_monitor *monitor) {
    return monitor ? monitor->udev : NULL;
}

struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *list, const char *name) {
    while (list) {
        const char *candidate = udev_list_entry_get_name(list);
        if (candidate && name && strcmp(candidate, name) == 0)
            return list;
        list = udev_list_entry_get_next(list);
    }
    return NULL;
}

int udev_enumerate_add_match_parent(struct udev_enumerate *enumerate, struct udev_device *device) {
    (void)enumerate;
    (void)device;
    return 0;
}

struct udev_hwdb {
    rustd_device_hwdb *hwdb;
};

struct udev_hwdb *udev_hwdb_new(void) {
    struct udev_hwdb *hwdb = calloc(1, sizeof(*hwdb));
    if (!hwdb)
        return NULL;
    hwdb->hwdb = rustd_device_hwdb_new();
    if (!hwdb->hwdb) {
        free(hwdb);
        return NULL;
    }
    return hwdb;
}

struct udev_hwdb *udev_hwdb_unref(struct udev_hwdb *hwdb) {
    if (!hwdb)
        return NULL;
    rustd_device_hwdb_unref(hwdb->hwdb);
    free(hwdb);
    return NULL;
}

struct udev_list_entry *udev_hwdb_get_properties_list_entry(
    struct udev_hwdb *hwdb, const char *modalias) {
    return hwdb ? wrap_list(rustd_device_hwdb_get_properties_list_entry(hwdb->hwdb, modalias))
                : NULL;
}

struct udev_queue {
    rustd_device_queue *queue;
};

struct udev_queue *udev_queue_new(struct udev *udev) {
    struct udev_queue *queue;
    if (!udev)
        return NULL;
    queue = calloc(1, sizeof(*queue));
    if (!queue)
        return NULL;
    queue->queue = rustd_device_queue_new(udev->ctx);
    if (!queue->queue) {
        free(queue);
        return NULL;
    }
    return queue;
}

struct udev_queue *udev_queue_unref(struct udev_queue *queue) {
    if (!queue)
        return NULL;
    rustd_device_queue_unref(queue->queue);
    free(queue);
    return NULL;
}

int udev_queue_get_udev_is_active(struct udev_queue *queue) {
    return queue ? rustd_device_queue_get_udev_is_active(queue->queue) : 0;
}

int udev_queue_get_queue_is_empty(struct udev_queue *queue) {
    return queue ? rustd_device_queue_get_queue_is_empty(queue->queue) : 1;
}
