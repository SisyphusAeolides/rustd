/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Minimal pam_systemd-compatible session registration module.  It deliberately
 * uses libdbus rather than libsystemd: RustD replaces systemd and owns login1.
 */
#include <dbus/dbus.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SESSION_KEY "rustd-logind-session"
/* RustD owns the native bus/path while preserving the login1 wire interface. */
#define LOGIN1_INTERFACE "org.freedesktop.login1.Manager"

static void free_session(pam_handle_t *pamh, void *data, int status) {
    (void)pamh; (void)status;
    free(data);
}

static DBusConnection *system_bus(void) {
    DBusError error;
    dbus_error_init(&error);
    DBusConnection *bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    dbus_error_free(&error);
    return bus;
}

static int call_terminate(const char *id) {
    DBusConnection *bus = system_bus();
    if (!bus) return PAM_SESSION_ERR;
    DBusMessage *message = dbus_message_new_method_call(
        "io.rustd.Login1", "/io/rustd/Login1",
        LOGIN1_INTERFACE, "TerminateSession");
    if (!message) return PAM_BUF_ERR;
    if (!dbus_message_append_args(message, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID)) {
        dbus_message_unref(message);
        return PAM_BUF_ERR;
    }
    DBusError error;
    dbus_error_init(&error);
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, message, 5000, &error);
    dbus_message_unref(message);
    dbus_connection_unref(bus);
    if (!reply) {
        dbus_error_free(&error);
        return PAM_SESSION_ERR;
    }
    dbus_message_unref(reply);
    return PAM_SUCCESS;
}

static int create_session(pam_handle_t *pamh, const char *user, const struct passwd *pwd, char **out) {
    (void)user;
    const char *service = NULL, *tty = "";
    (void)pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    (void)pam_get_item(pamh, PAM_TTY, (const void **)&tty);
    if (!service) service = "login";
    if (!tty) tty = "";
    DBusConnection *bus = system_bus();
    if (!bus) return PAM_SESSION_ERR;
    DBusMessage *message = dbus_message_new_method_call(
        "io.rustd.Login1", "/io/rustd/Login1",
        LOGIN1_INTERFACE, "CreateSession");
    if (!message) return PAM_BUF_ERR;
    dbus_uint32_t uid = pwd->pw_uid, pid = getpid(), vtnr = 0;
    dbus_bool_t remote = FALSE;
    const char *type = "unspecified", *class = "user", *desktop = "KDE", *seat = "seat0";
    const char *display = "", *remote_user = "", *remote_host = "";
    DBusMessageIter iter, array;
    dbus_message_iter_init_append(message, &iter);
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &uid) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &pid) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &service) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &type) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &class) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &desktop) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &seat) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &vtnr) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &tty) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &display) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &remote) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &remote_user) ||
        !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &remote_host) ||
        /* login1's CreateSession properties are an array of (string, variant)
         * structs, not a dictionary.  Keep this byte-for-byte compatible with
         * pam_systemd and the org.freedesktop.login1 contract. */
        !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(sv)", &array) ||
        !dbus_message_iter_close_container(&iter, &array)) {
        dbus_message_unref(message);
        dbus_connection_unref(bus);
        return PAM_BUF_ERR;
    }
    DBusError error;
    dbus_error_init(&error);
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(bus, message, 5000, &error);
    dbus_message_unref(message);
    dbus_connection_unref(bus);
    if (!reply) {
        dbus_error_free(&error);
        return PAM_SESSION_ERR;
    }
    const char *id = NULL;
    int ok = dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &id, DBUS_TYPE_INVALID);
    if (ok && id) {
        size_t length = strlen(id) + 1;
        *out = malloc(length);
        if (*out) memcpy(*out, id, length);
    }
    dbus_message_unref(reply);
    dbus_error_free(&error);
    return *out ? PAM_SUCCESS : PAM_SESSION_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) return PAM_USER_UNKNOWN;
    struct passwd *pwd = getpwnam(user);
    if (!pwd) return PAM_USER_UNKNOWN;
    char *session = NULL;
    int status = create_session(pamh, user, pwd, &session);
    if (status != PAM_SUCCESS) return status;
    status = pam_set_data(pamh, SESSION_KEY, session, free_session);
    if (status != PAM_SUCCESS) free(session);
    return status;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const void *data = NULL;
    if (pam_get_data(pamh, SESSION_KEY, &data) != PAM_SUCCESS || !data) return PAM_SUCCESS;
    return call_terminate(data);
}
