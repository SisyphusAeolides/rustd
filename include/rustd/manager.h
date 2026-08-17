/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned rustd_manager_abi_version(void);

typedef struct rustd_manager rustd_manager;

/* Connect to RUSTD_CONTROL_SOCKET or /run/rustd/ctl.sock. */
int rustd_manager_connect(rustd_manager **ret);
void rustd_manager_unref(rustd_manager *manager);

/* Returns a newly allocated newline-separated unit list on success. */
int rustd_manager_list_units(rustd_manager *manager, char **out);
int rustd_manager_start_unit(rustd_manager *manager, const char *unit);
int rustd_manager_stop_unit(rustd_manager *manager, const char *unit);
int rustd_manager_restart_unit(rustd_manager *manager, const char *unit);
int rustd_manager_reload_unit(rustd_manager *manager, const char *unit);
int rustd_manager_daemon_reload(rustd_manager *manager);
int rustd_manager_is_active(rustd_manager *manager, const char *unit, int *active);

#ifdef __cplusplus
}
#endif
