/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * capability.c — Linux capability helpers for service sandboxing.
 *
 * Upstream reference: src/shared/capability-util.c (v261)
 */

#include "capability.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

/* ── kernel capability range ─────────────────────────────────────────────── */

static int capability_last_cap(void) {
#ifdef CAP_LAST_CAP
    int fallback = CAP_LAST_CAP;
#else
    int fallback = 40;
#endif
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return fallback;

    char buffer[32];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    int saved = errno;
    close(fd);
    if (n <= 0) {
        errno = saved;
        return fallback;
    }

    buffer[n] = '\0';
    char *end = NULL;
    errno = 0;
    long parsed = strtol(buffer, &end, 10);
    if (errno != 0 || end == buffer || parsed < 0)
        return fallback;
    if (parsed > 63)
        return 63;
    return (int)parsed;
}

static int capability_mask_validate(uint64_t mask, int last_cap) {
    if (last_cap < 63) {
        uint64_t unsupported = mask & (UINT64_MAX << (last_cap + 1));
        if (unsupported != 0)
            return -EINVAL;
    }
    return 0;
}

static uint64_t capability_join(uint32_t low, uint32_t high) {
    return (uint64_t)low | ((uint64_t)high << 32);
}

static void capability_split(uint64_t value, uint32_t *low, uint32_t *high) {
    *low = (uint32_t)(value & UINT32_MAX);
    *high = (uint32_t)(value >> 32);
}

static int capability_get_sets(uint64_t *permitted,
                               uint64_t *inheritable,
                               uint64_t *effective) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    memset(data, 0, sizeof(data));

    if (syscall(SYS_capget, &header, data) < 0)
        return -errno;

    *effective = capability_join(data[0].effective, data[1].effective);
    *permitted = capability_join(data[0].permitted, data[1].permitted);
    *inheritable = capability_join(data[0].inheritable, data[1].inheritable);
    return 0;
}

static int capability_set_sets(uint64_t permitted,
                               uint64_t inheritable,
                               uint64_t effective) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    memset(data, 0, sizeof(data));

    capability_split(effective, &data[0].effective, &data[1].effective);
    capability_split(permitted, &data[0].permitted, &data[1].permitted);
    capability_split(inheritable, &data[0].inheritable, &data[1].inheritable);

    if (syscall(SYS_capset, &header, data) < 0)
        return -errno;
    return 0;
}

/* ── rustd_capability_name_to_num ───────────────────────────────────────────── */

typedef struct {
    const char *name;
    int num;
} cap_entry;

static const cap_entry cap_table[] = {
    { "chown",              0  },
    { "dac_override",       1  },
    { "dac_read_search",    2  },
    { "fowner",             3  },
    { "fsetid",             4  },
    { "kill",               5  },
    { "setgid",             6  },
    { "setuid",             7  },
    { "setpcap",            8  },
    { "linux_immutable",    9  },
    { "net_bind_service",   10 },
    { "net_broadcast",      11 },
    { "net_admin",          12 },
    { "net_raw",            13 },
    { "ipc_lock",           14 },
    { "ipc_owner",          15 },
    { "sys_module",         16 },
    { "sys_rawio",          17 },
    { "sys_chroot",         18 },
    { "sys_ptrace",         19 },
    { "sys_pacct",          20 },
    { "sys_admin",          21 },
    { "sys_boot",           22 },
    { "sys_nice",           23 },
    { "sys_resource",       24 },
    { "sys_time",           25 },
    { "sys_tty_config",     26 },
    { "mknod",              27 },
    { "lease",              28 },
    { "audit_write",        29 },
    { "audit_control",      30 },
    { "setfcap",            31 },
    { "mac_override",       32 },
    { "mac_admin",          33 },
    { "syslog",             34 },
    { "wake_alarm",         35 },
    { "block_suspend",      36 },
    { "audit_read",         37 },
    { "perfmon",            38 },
    { "bpf",                39 },
    { "checkpoint_restore", 40 },
    { NULL,                   -1 },
};

int rustd_capability_name_to_num(const char *name) {
    if (!name)
        return -1;

    char lower[64];
    size_t i;
    for (i = 0; i < sizeof(lower) - 1 && name[i]; i++)
        lower[i] = (char)tolower((unsigned char)name[i]);
    lower[i] = '\0';

    const char *key = lower;
    if (strncmp(key, "cap_", 4) == 0)
        key += 4;

    for (int j = 0; cap_table[j].name != NULL; j++) {
        if (strcmp(cap_table[j].name, key) == 0)
            return cap_table[j].num;
    }
    return -1;
}

/* ── rustd_capability_bounding_set_drop ─────────────────────────────────────── */

int rustd_capability_bounding_set_drop(uint64_t keep_mask) {
    if (keep_mask == UINT64_MAX)
        return 0;

    int last_cap = capability_last_cap();
    int r = capability_mask_validate(keep_mask, last_cap);
    if (r < 0)
        return r;

    for (int cap = 0; cap <= last_cap; cap++) {
        if ((keep_mask & (UINT64_C(1) << cap)) != 0)
            continue;
        if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) < 0) {
            int saved = errno;
            if (saved == EINVAL)
                continue;
            return -saved;
        }
    }
    return 0;
}

/* ── ambient capability preparation and application ─────────────────────── */

int rustd_capability_ambient_prepare(uint64_t ambient_mask) {
    int last_cap = capability_last_cap();
    int r = capability_mask_validate(ambient_mask, last_cap);
    if (r < 0 || ambient_mask == 0)
        return r;

    uint64_t permitted = 0;
    uint64_t inheritable = 0;
    uint64_t effective = 0;
    r = capability_get_sets(&permitted, &inheritable, &effective);
    if (r < 0)
        return r;
    if ((permitted & ambient_mask) != ambient_mask)
        return -EPERM;

    inheritable |= ambient_mask;
    effective |= ambient_mask;
    return capability_set_sets(permitted, inheritable, effective);
}

int rustd_capability_ambient_apply(uint64_t ambient_mask) {
    int last_cap = capability_last_cap();
    int r = capability_mask_validate(ambient_mask, last_cap);
    if (r < 0)
        return r;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        int saved = errno;
        if (ambient_mask == 0 && (saved == EINVAL || saved == ENOSYS))
            return 0;
        return -saved;
    }

    for (int cap = 0; cap <= last_cap; cap++) {
        if ((ambient_mask & (UINT64_C(1) << cap)) == 0)
            continue;
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
                  (unsigned long)cap, 0, 0) < 0)
            return -errno;
    }
    return 0;
}
