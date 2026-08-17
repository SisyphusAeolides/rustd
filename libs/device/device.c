/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <rustd/device.h>

unsigned rustd_device_abi_version(void) {
    return 1U;
}

struct rustd_device_list_entry {
    char *name;
    char *value;
    struct rustd_device_list_entry *next;
};

struct rustd_device_ctx {
    unsigned refs;
};

struct rustd_device {
    unsigned refs;
    rustd_device_ctx *ctx;
    char *syspath;
    char *sysname;
    char *subsystem;
    char *devnode;
    char *devpath;
    char *devtype;
    char *driver;
    char *action;
    char *sysnum;
    dev_t devnum;
    int initialized;
    rustd_device_list_entry *properties;
    rustd_device_list_entry *devlinks;
    rustd_device *parent;
};

struct rustd_device_enumerate {
    rustd_device_ctx *ctx;
    char *match_subsystem;
    char *match_property;
    char *match_property_value;
    char *match_sysname;
    rustd_device_list_entry *results;
};

struct rustd_device_monitor {
    rustd_device_ctx *ctx;
    int fd;
    char *match_subsystem;
    char *match_devtype;
};

struct rustd_device_hwdb {
    rustd_device_list_entry *entries;
};

struct rustd_device_queue {
    rustd_device_ctx *ctx;
};

static void free_list(rustd_device_list_entry *entry) {
    while (entry) {
        rustd_device_list_entry *next = entry->next;
        free(entry->name);
        free(entry->value);
        free(entry);
        entry = next;
    }
}

static rustd_device_list_entry *list_prepend(
    rustd_device_list_entry *head, const char *name, const char *value) {
    rustd_device_list_entry *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return head;
    entry->name = name ? strdup(name) : NULL;
    entry->value = value ? strdup(value) : NULL;
    entry->next = head;
    return entry;
}

rustd_device_ctx *rustd_device_ctx_new(void) {
    rustd_device_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->refs = 1;
    return ctx;
}

rustd_device_ctx *rustd_device_ctx_ref(rustd_device_ctx *ctx) {
    if (ctx)
        ctx->refs++;
    return ctx;
}

rustd_device_ctx *rustd_device_ctx_unref(rustd_device_ctx *ctx) {
    if (!ctx || --ctx->refs)
        return ctx;
    free(ctx);
    return NULL;
}

rustd_device *rustd_device_ref(rustd_device *device) {
    if (device)
        device->refs++;
    return device;
}

rustd_device *rustd_device_unref(rustd_device *device) {
    if (!device || --device->refs)
        return device;
    rustd_device_ctx_unref(device->ctx);
    rustd_device_unref(device->parent);
    free(device->syspath);
    free(device->sysname);
    free(device->subsystem);
    free(device->devnode);
    free(device->devpath);
    free(device->devtype);
    free(device->driver);
    free(device->action);
    free(device->sysnum);
    free_list(device->properties);
    free_list(device->devlinks);
    free(device);
    return NULL;
}

static char *read_sysfs_value(const char *syspath, const char *name) {
    char path[512];
    char buffer[1024];
    FILE *stream;
    size_t length;

    snprintf(path, sizeof(path), "%s/%s", syspath, name);
    stream = fopen(path, "r");
    if (!stream)
        return NULL;
    if (!fgets(buffer, sizeof(buffer), stream)) {
        fclose(stream);
        return NULL;
    }
    fclose(stream);
    length = strlen(buffer);
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r'))
        buffer[--length] = '\0';
    return strdup(buffer);
}

static void load_uevent_properties(rustd_device *device) {
    char path[512];
    FILE *stream;
    char line[1024];

    snprintf(path, sizeof(path), "%s/uevent", device->syspath);
    stream = fopen(path, "r");
    if (!stream)
        return;
    while (fgets(line, sizeof(line), stream)) {
        char *eq = strchr(line, '=');
        size_t length = strlen(line);
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (!eq)
            continue;
        *eq = '\0';
        device->properties = list_prepend(device->properties, line, eq + 1);
        if (strcmp(line, "DEVNAME") == 0) {
            free(device->devnode);
            if (eq[1] == '/')
                device->devnode = strdup(eq + 1);
            else {
                char node[512];
                snprintf(node, sizeof(node), "/dev/%s", eq + 1);
                device->devnode = strdup(node);
            }
        } else if (strcmp(line, "DEVTYPE") == 0) {
            free(device->devtype);
            device->devtype = strdup(eq + 1);
        } else if (strcmp(line, "MAJOR") == 0 || strcmp(line, "MINOR") == 0) {
            /* filled below from DEVTYPE path when present */
        }
    }
    fclose(stream);
}

static void load_persist_properties(rustd_device *device) {
    char path[512];
    FILE *stream;
    char line[1024];
    const char *devpath = device->devpath ? device->devpath : "";

    snprintf(path, sizeof(path), "/run/udev/data/+%s:%s",
             device->subsystem ? device->subsystem : "",
             device->sysname ? device->sysname : "");
    stream = fopen(path, "r");
    if (!stream) {
        snprintf(path, sizeof(path), "/run/udev/data/c%u:%u",
                 major(device->devnum), minor(device->devnum));
        stream = fopen(path, "r");
    }
    if (!stream && *devpath) {
        snprintf(path, sizeof(path), "/run/udev/data/%s", devpath + (*devpath == '/'));
        stream = fopen(path, "r");
    }
    if (!stream)
        return;
    while (fgets(line, sizeof(line), stream)) {
        size_t length = strlen(line);
        char *eq;
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if ((line[0] == 'E' || line[0] == 'S' || line[0] == 'I') && line[1] == ':') {
            eq = strchr(line + 2, '=');
            if (!eq)
                continue;
            *eq = '\0';
            if (line[0] == 'E')
                device->properties = list_prepend(device->properties, line + 2, eq + 1);
            else if (line[0] == 'S')
                device->devlinks = list_prepend(device->devlinks, eq + 1, NULL);
        }
        (void)devpath;
    }
    fclose(stream);
}

static rustd_device *device_from_syspath(rustd_device_ctx *ctx, const char *syspath) {
    rustd_device *device;
    char resolved[PATH_MAX];
    const char *canonical = syspath;
    char *slash;

    if (!ctx || !syspath)
        return NULL;
    if (realpath(syspath, resolved))
        canonical = resolved;
    device = calloc(1, sizeof(*device));
    if (!device)
        return NULL;
    device->refs = 1;
    device->ctx = rustd_device_ctx_ref(ctx);
    device->syspath = strdup(canonical);
    device->initialized = 1;
    if (!device->syspath) {
        rustd_device_unref(device);
        return NULL;
    }
    slash = strrchr(device->syspath, '/');
    device->sysname = strdup(slash ? slash + 1 : device->syspath);
    if (strncmp(device->syspath, "/sys", 4) == 0)
        device->devpath = strdup(device->syspath + 4);
    device->subsystem = read_sysfs_value(device->syspath, "subsystem");
    if (!device->subsystem) {
        char link[PATH_MAX];
        char target[PATH_MAX];
        ssize_t n;
        snprintf(link, sizeof(link), "%s/subsystem", device->syspath);
        n = readlink(link, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            slash = strrchr(target, '/');
            device->subsystem = strdup(slash ? slash + 1 : target);
        }
    }
    device->driver = read_sysfs_value(device->syspath, "driver");
    if (!device->driver) {
        char link[PATH_MAX];
        char target[PATH_MAX];
        ssize_t n;
        snprintf(link, sizeof(link), "%s/driver", device->syspath);
        n = readlink(link, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            slash = strrchr(target, '/');
            device->driver = strdup(slash ? slash + 1 : target);
        }
    }
    {
        char *major_text = read_sysfs_value(device->syspath, "dev");
        if (major_text) {
            unsigned major_n = 0, minor_n = 0;
            if (sscanf(major_text, "%u:%u", &major_n, &minor_n) == 2)
                device->devnum = makedev(major_n, minor_n);
            free(major_text);
        }
    }
    load_uevent_properties(device);
    load_persist_properties(device);
    return device;
}

rustd_device *rustd_device_new_from_syspath(rustd_device_ctx *ctx, const char *syspath) {
    return device_from_syspath(ctx, syspath);
}

rustd_device *rustd_device_new_from_devnum(rustd_device_ctx *ctx, char type, dev_t devnum) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/dev/%s/%u:%u",
             type == 'b' ? "block" : "char", major(devnum), minor(devnum));
    return device_from_syspath(ctx, path);
}

rustd_device *rustd_device_new_from_subsystem_sysname(
    rustd_device_ctx *ctx, const char *subsystem, const char *sysname) {
    char path[512];
    if (!subsystem || !sysname)
        return NULL;
    snprintf(path, sizeof(path), "/sys/class/%s/%s", subsystem, sysname);
    if (access(path, F_OK) == 0)
        return device_from_syspath(ctx, path);
    snprintf(path, sizeof(path), "/sys/bus/%s/devices/%s", subsystem, sysname);
    return device_from_syspath(ctx, path);
}

const char *rustd_device_get_syspath(rustd_device *device) {
    return device ? device->syspath : NULL;
}
const char *rustd_device_get_sysname(rustd_device *device) {
    return device ? device->sysname : NULL;
}
const char *rustd_device_get_subsystem(rustd_device *device) {
    return device ? device->subsystem : NULL;
}
const char *rustd_device_get_devnode(rustd_device *device) {
    return device ? device->devnode : NULL;
}
const char *rustd_device_get_devpath(rustd_device *device) {
    return device ? device->devpath : NULL;
}
const char *rustd_device_get_devtype(rustd_device *device) {
    return device ? device->devtype : NULL;
}
const char *rustd_device_get_driver(rustd_device *device) {
    return device ? device->driver : NULL;
}
const char *rustd_device_get_action(rustd_device *device) {
    return device ? device->action : NULL;
}
dev_t rustd_device_get_devnum(rustd_device *device) {
    return device ? device->devnum : 0;
}
int rustd_device_get_is_initialized(rustd_device *device) {
    return device ? device->initialized : 0;
}

const char *rustd_device_get_property_value(rustd_device *device, const char *key) {
    rustd_device_list_entry *entry;
    if (!device || !key)
        return NULL;
    for (entry = device->properties; entry; entry = entry->next) {
        if (entry->name && strcmp(entry->name, key) == 0)
            return entry->value;
    }
    return NULL;
}

const char *rustd_device_get_sysattr_value(rustd_device *device, const char *key) {
    static __thread char buffer[1024];
    char *value;
    if (!device || !key)
        return NULL;
    value = read_sysfs_value(device->syspath, key);
    if (!value)
        return NULL;
    snprintf(buffer, sizeof(buffer), "%s", value);
    free(value);
    return buffer;
}

rustd_device *rustd_device_get_parent(rustd_device *device) {
    char parent_path[PATH_MAX];
    char *slash;
    if (!device || !device->syspath)
        return NULL;
    if (device->parent)
        return rustd_device_ref(device->parent);
    snprintf(parent_path, sizeof(parent_path), "%s", device->syspath);
    slash = strrchr(parent_path, '/');
    if (!slash || slash == parent_path)
        return NULL;
    *slash = '\0';
    if (strcmp(parent_path, "/sys") == 0 || strcmp(parent_path, "/sys/devices") == 0)
        return NULL;
    device->parent = device_from_syspath(device->ctx, parent_path);
    return rustd_device_ref(device->parent);
}

rustd_device *rustd_device_get_parent_with_subsystem_devtype(
    rustd_device *device, const char *subsystem, const char *devtype) {
    rustd_device *current = rustd_device_get_parent(device);
    while (current) {
        const char *current_subsystem = rustd_device_get_subsystem(current);
        const char *current_devtype = rustd_device_get_devtype(current);
        if ((!subsystem || (current_subsystem && strcmp(current_subsystem, subsystem) == 0)) &&
            (!devtype || (current_devtype && strcmp(current_devtype, devtype) == 0)))
            return current;
        {
            rustd_device *next = rustd_device_get_parent(current);
            rustd_device_unref(current);
            current = next;
        }
    }
    return NULL;
}

rustd_device_list_entry *rustd_device_get_properties_list_entry(rustd_device *device) {
    return device ? device->properties : NULL;
}
rustd_device_list_entry *rustd_device_get_devlinks_list_entry(rustd_device *device) {
    return device ? device->devlinks : NULL;
}
rustd_device_list_entry *rustd_device_list_entry_get_next(rustd_device_list_entry *entry) {
    return entry ? entry->next : NULL;
}
const char *rustd_device_list_entry_get_name(rustd_device_list_entry *entry) {
    return entry ? entry->name : NULL;
}
const char *rustd_device_list_entry_get_value(rustd_device_list_entry *entry) {
    return entry ? entry->value : NULL;
}

rustd_device_enumerate *rustd_device_enumerate_new(rustd_device_ctx *ctx) {
    rustd_device_enumerate *enumerate;
    if (!ctx)
        return NULL;
    enumerate = calloc(1, sizeof(*enumerate));
    if (!enumerate)
        return NULL;
    enumerate->ctx = rustd_device_ctx_ref(ctx);
    return enumerate;
}

rustd_device_enumerate *rustd_device_enumerate_unref(rustd_device_enumerate *enumerate) {
    if (!enumerate)
        return NULL;
    rustd_device_ctx_unref(enumerate->ctx);
    free(enumerate->match_subsystem);
    free(enumerate->match_property);
    free(enumerate->match_property_value);
    free(enumerate->match_sysname);
    free_list(enumerate->results);
    free(enumerate);
    return NULL;
}

int rustd_device_enumerate_add_match_subsystem(
    rustd_device_enumerate *enumerate, const char *subsystem) {
    if (!enumerate || !subsystem)
        return -EINVAL;
    free(enumerate->match_subsystem);
    enumerate->match_subsystem = strdup(subsystem);
    return enumerate->match_subsystem ? 0 : -ENOMEM;
}

int rustd_device_enumerate_add_match_property(
    rustd_device_enumerate *enumerate, const char *property, const char *value) {
    if (!enumerate || !property)
        return -EINVAL;
    free(enumerate->match_property);
    free(enumerate->match_property_value);
    enumerate->match_property = strdup(property);
    enumerate->match_property_value = value ? strdup(value) : NULL;
    return 0;
}

int rustd_device_enumerate_add_match_sysname(
    rustd_device_enumerate *enumerate, const char *sysname) {
    if (!enumerate || !sysname)
        return -EINVAL;
    free(enumerate->match_sysname);
    enumerate->match_sysname = strdup(sysname);
    return enumerate->match_sysname ? 0 : -ENOMEM;
}

static int append_syspath_result(rustd_device_enumerate *enumerate, const char *syspath) {
    rustd_device *device = device_from_syspath(enumerate->ctx, syspath);
    if (!device)
        return 0;
    if (enumerate->match_subsystem &&
        (!device->subsystem || strcmp(device->subsystem, enumerate->match_subsystem) != 0)) {
        rustd_device_unref(device);
        return 0;
    }
    if (enumerate->match_sysname &&
        (!device->sysname || strcmp(device->sysname, enumerate->match_sysname) != 0)) {
        rustd_device_unref(device);
        return 0;
    }
    if (enumerate->match_property) {
        const char *value = rustd_device_get_property_value(device, enumerate->match_property);
        if (!value ||
            (enumerate->match_property_value &&
             strcmp(value, enumerate->match_property_value) != 0)) {
            rustd_device_unref(device);
            return 0;
        }
    }
    enumerate->results = list_prepend(enumerate->results, device->syspath, NULL);
    rustd_device_unref(device);
    return 0;
}

static void scan_dir(rustd_device_enumerate *enumerate, const char *root) {
    DIR *dir = opendir(root);
    struct dirent *entry;
    if (!dir)
        return;
    while ((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        struct stat st;
        if (entry->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", root, entry->d_name);
        if (lstat(path, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (access(path, F_OK) == 0)
                append_syspath_result(enumerate, path);
        }
    }
    closedir(dir);
}

int rustd_device_enumerate_scan_devices(rustd_device_enumerate *enumerate) {
    char path[512];
    if (!enumerate)
        return -EINVAL;
    free_list(enumerate->results);
    enumerate->results = NULL;
    if (enumerate->match_subsystem) {
        snprintf(path, sizeof(path), "/sys/class/%s", enumerate->match_subsystem);
        scan_dir(enumerate, path);
        snprintf(path, sizeof(path), "/sys/bus/%s/devices", enumerate->match_subsystem);
        scan_dir(enumerate, path);
    } else {
        scan_dir(enumerate, "/sys/class/net");
        scan_dir(enumerate, "/sys/class/block");
        scan_dir(enumerate, "/sys/class/input");
        scan_dir(enumerate, "/sys/class/drm");
        scan_dir(enumerate, "/sys/class/tty");
    }
    return 0;
}

rustd_device_list_entry *rustd_device_enumerate_get_list_entry(
    rustd_device_enumerate *enumerate) {
    return enumerate ? enumerate->results : NULL;
}

rustd_device_monitor *rustd_device_monitor_new_from_netlink(
    rustd_device_ctx *ctx, const char *name) {
    rustd_device_monitor *monitor;
    struct sockaddr_nl address;
    int fd;
    (void)name;
    if (!ctx)
        return NULL;
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    if (fd < 0)
        return NULL;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = 1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return NULL;
    }
    monitor = calloc(1, sizeof(*monitor));
    if (!monitor) {
        close(fd);
        return NULL;
    }
    monitor->ctx = rustd_device_ctx_ref(ctx);
    monitor->fd = fd;
    return monitor;
}

rustd_device_monitor *rustd_device_monitor_unref(rustd_device_monitor *monitor) {
    if (!monitor)
        return NULL;
    if (monitor->fd >= 0)
        close(monitor->fd);
    rustd_device_ctx_unref(monitor->ctx);
    free(monitor->match_subsystem);
    free(monitor->match_devtype);
    free(monitor);
    return NULL;
}

int rustd_device_monitor_filter_add_match_subsystem_devtype(
    rustd_device_monitor *monitor, const char *subsystem, const char *devtype) {
    if (!monitor)
        return -EINVAL;
    free(monitor->match_subsystem);
    free(monitor->match_devtype);
    monitor->match_subsystem = subsystem ? strdup(subsystem) : NULL;
    monitor->match_devtype = devtype ? strdup(devtype) : NULL;
    return 0;
}

int rustd_device_monitor_enable_receiving(rustd_device_monitor *monitor) {
    return monitor && monitor->fd >= 0 ? 0 : -EINVAL;
}

int rustd_device_monitor_get_fd(rustd_device_monitor *monitor) {
    return monitor ? monitor->fd : -EINVAL;
}

rustd_device *rustd_device_monitor_receive_device(rustd_device_monitor *monitor) {
    char buffer[8192];
    ssize_t n;
    char *syspath = NULL;
    char *action = NULL;
    char *subsystem = NULL;
    char *devtype = NULL;
    char *cursor;

    if (!monitor || monitor->fd < 0)
        return NULL;
    n = recv(monitor->fd, buffer, sizeof(buffer) - 1, 0);
    if (n <= 0)
        return NULL;
    buffer[n] = '\0';
    cursor = buffer;
    while (cursor < buffer + n) {
        if (strncmp(cursor, "DEVPATH=", 8) == 0)
            syspath = cursor + 8;
        else if (strncmp(cursor, "ACTION=", 7) == 0)
            action = cursor + 7;
        else if (strncmp(cursor, "SUBSYSTEM=", 10) == 0)
            subsystem = cursor + 10;
        else if (strncmp(cursor, "DEVTYPE=", 8) == 0)
            devtype = cursor + 8;
        cursor += strlen(cursor) + 1;
    }
    if (monitor->match_subsystem && subsystem &&
        strcmp(subsystem, monitor->match_subsystem) != 0)
        return NULL;
    if (monitor->match_devtype &&
        (!devtype || strcmp(devtype, monitor->match_devtype) != 0))
        return NULL;
    if (!syspath)
        return NULL;
    {
        char full[PATH_MAX];
        rustd_device *device;
        snprintf(full, sizeof(full), "/sys%s", syspath);
        device = device_from_syspath(monitor->ctx, full);
        if (device && action) {
            free(device->action);
            device->action = strdup(action);
        }
        return device;
    }
}

rustd_device_hwdb *rustd_device_hwdb_new(void) {
    return calloc(1, sizeof(rustd_device_hwdb));
}

rustd_device_hwdb *rustd_device_hwdb_unref(rustd_device_hwdb *hwdb) {
    if (!hwdb)
        return NULL;
    free_list(hwdb->entries);
    free(hwdb);
    return NULL;
}

rustd_device_list_entry *rustd_device_hwdb_get_properties_list_entry(
    rustd_device_hwdb *hwdb, const char *modalias) {
    FILE *stream;
    char line[1024];
    if (!hwdb)
        return NULL;
    free_list(hwdb->entries);
    hwdb->entries = NULL;
    stream = fopen("/etc/udev/hwdb.bin", "r");
    if (!stream)
        stream = fopen("/usr/lib/udev/hwdb.bin", "r");
    if (!stream) {
        /* Text fallback used by some images for a tiny property set. */
        stream = fopen("/etc/udev/hwdb.d/rustd-fallback.hwdb", "r");
    }
    if (!stream)
        return NULL;
    (void)modalias;
    while (fgets(line, sizeof(line), stream)) {
        char *eq;
        size_t length = strlen(line);
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (line[0] == '#' || line[0] == '\0' || line[0] != ' ')
            continue;
        eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        hwdb->entries = list_prepend(hwdb->entries, line + 1, eq + 1);
    }
    fclose(stream);
    return hwdb->entries;
}

rustd_device_queue *rustd_device_queue_new(rustd_device_ctx *ctx) {
    rustd_device_queue *queue;
    if (!ctx)
        return NULL;
    queue = calloc(1, sizeof(*queue));
    if (!queue)
        return NULL;
    queue->ctx = rustd_device_ctx_ref(ctx);
    return queue;
}

rustd_device_queue *rustd_device_queue_unref(rustd_device_queue *queue) {
    if (!queue)
        return NULL;
    rustd_device_ctx_unref(queue->ctx);
    free(queue);
    return NULL;
}

int rustd_device_queue_get_udev_is_active(rustd_device_queue *queue) {
    (void)queue;
    return access("/run/udev/control", F_OK) == 0 ? 1 : 0;
}

int rustd_device_queue_get_queue_is_empty(rustd_device_queue *queue) {
    (void)queue;
    return access("/run/udev/queue", F_OK) != 0 ? 1 : 0;
}
