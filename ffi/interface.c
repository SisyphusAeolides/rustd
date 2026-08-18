/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * interface.c — small native validation helpers shared by control protocols.
 *
 * These helpers keep D-Bus/Varlink identifier validation out of ad-hoc call
 * sites and provide a stable native ABI version for the Rust FFI boundary.
 */

#include <stddef.h>

unsigned rustd_interface_abi_version(void) {
    return 1U;
}

int rustd_interface_valid_object_path(const char *path) {
    const unsigned char *cursor;

    if (!path || path[0] != '/')
        return 0;
    if (path[1] == '\0')
        return 1;
    if (path[1] == '/')
        return 0;

    cursor = (const unsigned char *)path + 1;
    while (*cursor) {
        if (*cursor == '/') {
            if (cursor[1] == '\0' || cursor[1] == '/')
                return 0;
        } else if (!((*cursor >= 'A' && *cursor <= 'Z') ||
                     (*cursor >= 'a' && *cursor <= 'z') ||
                     (*cursor >= '0' && *cursor <= '9') ||
                     *cursor == '_')) {
            return 0;
        }
        cursor++;
    }
    return 1;
}

int rustd_interface_valid_member_name(const char *name) {
    const unsigned char *cursor;

    if (!name || !*name)
        return 0;
    cursor = (const unsigned char *)name;
    if (!((*cursor >= 'A' && *cursor <= 'Z') ||
          (*cursor >= 'a' && *cursor <= 'z') || *cursor == '_'))
        return 0;
    cursor++;
    while (*cursor) {
        if (!((*cursor >= 'A' && *cursor <= 'Z') ||
              (*cursor >= 'a' && *cursor <= 'z') ||
              (*cursor >= '0' && *cursor <= '9') ||
              *cursor == '_'))
            return 0;
        cursor++;
    }
    return 1;
}
