/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned rustd_login_abi_version(void);

typedef struct rustd_login_monitor rustd_login_monitor;

int rustd_get_sessions(char ***sessions);
int rustd_uid_get_sessions(uid_t uid, int require_active, char ***sessions);
int rustd_uid_get_seats(uid_t uid, int require_active, char ***seats);
int rustd_uid_get_state(uid_t uid, char **state);
int rustd_uid_is_on_seat(uid_t uid, int require_active, const char *seat);

int rustd_session_get_uid(const char *session, uid_t *uid);
int rustd_session_get_seat(const char *session, char **seat);
int rustd_session_get_state(const char *session, char **state);
int rustd_session_get_type(const char *session, char **type);
int rustd_session_get_class(const char *session, char **class);
int rustd_session_get_display(const char *session, char **display);
int rustd_session_get_tty(const char *session, char **tty);
int rustd_session_get_service(const char *session, char **service);
int rustd_session_get_username(const char *session, char **user);
int rustd_session_get_leader(const char *session, pid_t *leader);
int rustd_session_get_remote_host(const char *session, char **host);
int rustd_session_get_remote_user(const char *session, char **user);
int rustd_session_get_start_time(const char *session, uint64_t *usec);
int rustd_session_is_remote(const char *session);

int rustd_pid_get_session(pid_t pid, char **session);
int rustd_pid_get_owner_uid(pid_t pid, uid_t *uid);
int rustd_pid_get_unit(pid_t pid, char **unit);
int rustd_pid_get_user_unit(pid_t pid, char **unit);
int rustd_pid_get_slice(pid_t pid, char **slice);
int rustd_pid_get_user_slice(pid_t pid, char **slice);
int rustd_pid_get_cgroup(pid_t pid, char **cgroup);
int rustd_pid_get_machine_name(pid_t pid, char **machine);

rustd_login_monitor *rustd_login_monitor_new(const char *category);
rustd_login_monitor *rustd_login_monitor_unref(rustd_login_monitor *monitor);
int rustd_login_monitor_flush(rustd_login_monitor *monitor);
int rustd_login_monitor_get_fd(rustd_login_monitor *monitor);
int rustd_login_monitor_get_events(rustd_login_monitor *monitor);
int rustd_login_monitor_get_timeout(rustd_login_monitor *monitor, uint64_t *timeout_usec);

#ifdef __cplusplus
}
#endif
