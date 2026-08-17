/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stddef.h>

#include <rustd/service.h>

unsigned rustd_service_abi_version(void) {
    return 1U;
}

int rustd_notify_status(const char *status) {
    char buffer[512];
    int length;

    if (!status)
        return -EINVAL;
    length = snprintf(buffer, sizeof(buffer), "STATUS=%s\n", status);
    if (length < 0 || (size_t)length >= sizeof(buffer))
        return -ENAMETOOLONG;
    return rustd_notify_send(0, buffer, NULL, 0);
}
