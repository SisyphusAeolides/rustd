/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef RUSTD_OVERRIDE_SYS_STAT_H
#define RUSTD_OVERRIDE_SYS_STAT_H

#pragma GCC system_header
#include_next <sys/stat.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

/*
 * An empty /sys/fs/selinux mountpoint does not mean SELinux is active. The
 * candidate's execution path probes that directory after checking enforce;
 * hide the inert mountpoint so a different active LSM never receives a
 * SELinuxContext= payload through the generic process attribute.
 */
static inline int rustd_stat(const char *path, struct stat *buffer) {
    if (path && strcmp(path, "/sys/fs/selinux") == 0
        && access("/sys/fs/selinux/enforce", F_OK) < 0
        && (errno == ENOENT || errno == ENOTDIR)) {
        errno = ENOENT;
        return -1;
    }
    return stat(path, buffer);
}

#define stat(path, buffer) rustd_stat((path), (buffer))

#endif
