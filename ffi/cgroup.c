/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * cgroup.c — cgroup v2 fd operations and delegation helpers.
 *
 * Wraps the Linux cgroup2 file-descriptor ABI so that unsafe Rust is
 * confined to src/native.rs. The implementation uses bounded path and
 * descriptor operations for production cgroup v2 management.
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
 * Returns fd >= 0, or negative errno.
 */
int rustd_cgroup_fd_open(const char *path)
{
    if (!path || path[0] != '/')
        return -EINVAL;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

/*
 * rustd_cgroup_write: write a string value to a controller file relative
 * to an open cgroup directory fd.  Uses openat so there is no TOCTOU on
 * the cgroup directory path.  Rejects '/' in the filename.
 */
int rustd_cgroup_write(int cgfd, const char *file, const char *value)
{
    if (cgfd < 0 || !file || !*file || !value || strchr(file, '/'))
        return -EINVAL;

    int fd = openat(cgfd, file, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -errno;

    size_t len = strlen(value);
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, value + off, len - off);
        if (n < 0) {
            int saved = errno;
            close(fd);
            return -saved;
        }
        off += (size_t)n;
    }
    if (close(fd) < 0)
        return -errno;
    return 0;
}

/* Read a small controller value into buf. Returns byte count or -errno. */
ssize_t rustd_cgroup_read(int cgfd, const char *file, char *buf, size_t cap)
{
    if (cgfd < 0 || !file || !*file || !buf || cap == 0 || strchr(file, '/'))
        return -EINVAL;

    int fd = openat(cgfd, file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -errno;
    ssize_t n = read(fd, buf, cap - 1);
    if (n < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }
    buf[n] = '\0';
    close(fd);
    return n;
}

/*
 * Move a PID into the cgroup by writing decimal pid to cgroup.procs.
 */
int rustd_cgroup_attach_pid(int cgfd, int pid)
{
    if (pid <= 0)
        return -EINVAL;
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", pid);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        return -EOVERFLOW;
    return rustd_cgroup_write(cgfd, "cgroup.procs", buf);
}
