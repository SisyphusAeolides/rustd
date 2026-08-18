/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * cgroup.c — cgroup v2 fd operations and delegation helpers.
 *
 * Wraps the Linux cgroup2 file-descriptor ABI so that unsafe Rust is
 * confined to src/native.rs. These helpers implement the native cgroup v2
 * file-descriptor operations used by the Rust manager.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * rustd_cgroup_fd_open:  open a cgroup directory fd by absolute path.
 * Returns an fd on success, -errno on failure.
 */
int rustd_cgroup_fd_open(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -errno;
    return fd;
}

/*
 * rustd_cgroup_write:  write a NUL-terminated value to a cgroup control file.
 * Returns 0 on success, -errno on failure.
 */
int rustd_cgroup_write(int cgroup_fd, const char *filename, const char *value) {
    int fd = openat(cgroup_fd, filename,
                    O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -errno;

    size_t len = strlen(value);
    ssize_t n = write(fd, value, len);
    int err = (n < 0) ? -errno : 0;
    close(fd);
    return err;
}
