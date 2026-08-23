/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "sd_bus_abi.h"
#include "sd_core_abi.h"

static int async_called;
static int async_saw_dbus;
static int raw_filter_called;
static int match_called;

static int match_callback(sd_bus_message *message, void *userdata, sd_bus_error *error) {
    sd_bus *bus = userdata;
    (void)error;
    assert(message != NULL);
    assert(sd_bus_get_current_message(bus) == message);
    match_called++;
    return 1;
}

static int raw_filter(sd_bus_message *message, void *userdata, sd_bus_error *error) {
    int *marker = userdata;
    (void)message;
    (void)error;
    ++*marker;
    raw_filter_called = 1;
    return 1;
}

static int list_names_callback(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
    const char *name = NULL;
    int *marker = userdata;
    (void)ret_error;
    assert(reply != NULL);

    {
        sd_bus_creds *creds = NULL;
        pid_t pid = 0;
        uid_t uid = (uid_t)-1;
        gid_t gid = (gid_t)-1;
        const gid_t *groups = NULL;
        uint64_t mask = SD_BUS_CREDS_PID | SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID |
                        SD_BUS_CREDS_GID | SD_BUS_CREDS_EGID |
                        SD_BUS_CREDS_SUPPLEMENTARY_GIDS;
        assert(sd_bus_query_sender_creds(reply, mask, &creds) == 0);
        assert(creds != NULL);
        assert(sd_bus_creds_ref(creds) == creds);
        assert(sd_bus_creds_unref(creds) == NULL);
        assert(sd_bus_creds_get_pid(creds, &pid) == 0 && pid > 0);
        assert(sd_bus_creds_get_uid(creds, &uid) == 0 && uid != (uid_t)-1);
        assert(sd_bus_creds_get_gid(creds, &gid) == 0 && gid != (gid_t)-1);
        assert(sd_bus_creds_get_supplementary_gids(creds, &groups) >= 0);
        sd_bus_creds_unref(creds);
    }
    assert(marker != NULL);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s") > 0);
    while (sd_bus_message_read(reply, "s", &name) > 0) {
        assert(name != NULL);
        if (strcmp(name, "org.freedesktop.DBus") == 0)
            async_saw_dbus = 1;
    }
    assert(sd_bus_message_exit_container(reply) > 0);
    *marker = 1;
    async_called = 1;
    return 1;
}

static void test_matches_and_emission(void) {
    sd_bus *bus = NULL;
    sd_bus_slot *slot = NULL;
    sd_bus_message *signal = NULL;
    char *interfaces[] = {"org.example.Test", NULL};
    char *properties[] = {"Value", NULL};
    int r;

    match_called = 0;
    assert(sd_bus_open_user(&bus) == 0);
    assert(sd_bus_request_name(bus, "org.example.RustDTest", 0U) > 0);
    assert(sd_bus_add_object_manager(bus, NULL, "/org/example") == 0);
    assert(sd_bus_add_match(bus, &slot,
                            "type='signal',interface='org.example.Test',member='Changed'",
                            match_callback, bus) == 0);
    assert(sd_bus_message_new_signal(bus, &signal, "/org/example/Test",
                                     "org.example.Test", "Changed") == 0);
    assert(sd_bus_send(bus, signal, NULL) > 0);
    assert(sd_bus_flush(bus) == 0);
    for (int i = 0; i < 200 && match_called == 0; ++i) {
        r = sd_bus_process(bus, NULL);
        assert(r >= 0);
        if (match_called == 0)
            usleep(5000);
    }
    assert(match_called == 1);
    assert(sd_bus_emit_properties_changed_strv(bus, "/org/example/Test",
                                               "org.example.Test", properties) > 0);
    assert(sd_bus_emit_interfaces_added_strv(bus, "/org/example/Test", interfaces) > 0);
    assert(sd_bus_emit_interfaces_removed_strv(bus, "/org/example/Test", interfaces) > 0);
    assert(sd_bus_release_name(bus, "org.example.RustDTest") > 0);
    sd_bus_message_unref(signal);
    sd_bus_slot_unref(slot);
    sd_bus_unref(bus);
}

static void test_local_message_codec(void) {
    sd_bus *bus = NULL;
    sd_bus_message *m = NULL;
    const char *text = NULL;
    uint32_t number = 0;
    int b = 0;
    int r;

    assert(sd_bus_new(&bus) == 0);
    assert(bus != NULL);
    assert(sd_bus_message_new_method_call(
               bus, &m, "org.example.Test", "/org/example/Test",
               "org.example.Test", "Echo") == 0);
    assert(m != NULL);

    assert(sd_bus_message_append(m, "sub", "hello", (uint32_t)42, 1) == 0);
    assert(sd_bus_message_read(m, "sub", &text, &number, &b) == 3);
    assert(text && strcmp(text, "hello") == 0);
    assert(number == 42U);
    assert(b != 0);
    assert(sd_bus_message_at_end(m, 1) > 0);

    sd_bus_message_unref(m);
    m = NULL;

    assert(sd_bus_message_new_method_call(
               bus, &m, "org.example.Test", "/org/example/Test",
               "org.example.Test", "Containers") == 0);
    assert(sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "s") == 0);
    assert(sd_bus_message_append(m, "s", "one") == 0);
    assert(sd_bus_message_append(m, "s", "two") == 0);
    assert(sd_bus_message_close_container(m) == 0);

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "s");
    assert(r > 0);
    assert(sd_bus_message_read(m, "s", &text) == 1);
    assert(text && strcmp(text, "one") == 0);
    assert(sd_bus_message_read(m, "s", &text) == 1);
    assert(text && strcmp(text, "two") == 0);
    assert(sd_bus_message_at_end(m, 0) > 0);
    assert(sd_bus_message_exit_container(m) > 0);
    assert(sd_bus_message_at_end(m, 1) > 0);

    sd_bus_message_unref(m);
    m = NULL;

    assert(sd_bus_message_new_method_call(
               bus, &m, "org.example.Test", "/org/example/Test",
               "org.example.Test", "Struct") == 0);
    assert(sd_bus_message_open_container(m, SD_BUS_TYPE_STRUCT, "ss") == 0);
    assert(sd_bus_message_append(m, "ss", "left", "right") == 0);
    assert(sd_bus_message_close_container(m) == 0);

    sd_bus_message_unref(m);
    sd_bus_unref(bus);
}

static void test_extended_message_codec(void) {
    sd_bus *bus = NULL;
    sd_bus_message *source = NULL;
    sd_bus_message *copy = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    const uint32_t values[] = {3U, 5U, 8U};
    const void *read_values = NULL;
    const char *text = NULL;
    char *space = NULL;
    size_t size = 0U;
    uint64_t cookie = 0U;
    char type = 0;
    const char *contents = NULL;

    assert(sd_bus_service_name_is_valid("org.example.Test"));
    assert(!sd_bus_service_name_is_valid("not valid"));
    assert(sd_bus_interface_name_is_valid("org.example.Test"));
    assert(sd_bus_member_name_is_valid("Changed"));
    assert(sd_bus_object_path_is_valid("/org/example/Test"));
    assert(sd_bus_error_set(&error, "org.example.Error", "failure") < 0);
    assert(sd_bus_error_is_set(&error));
    sd_bus_error_free(&error);

    assert(sd_bus_new(&bus) == 0);
    assert(sd_bus_message_new_method_call(bus, &source, "org.example.Test",
                                          "/org/example/Test",
                                          "org.example.Test", "Changed") == 0);
    assert(sd_bus_message_is_empty(source) > 0);
    assert(sd_bus_message_append_string_space(source, 5U, &space) == 0);
    memcpy(space, "hello", 5U);
    assert(sd_bus_message_append_array(source, SD_BUS_TYPE_UINT32,
                                       values, sizeof(values)) == 0);
    assert(sd_bus_message_get_expect_reply(source) > 0);
    assert(sd_bus_message_set_expect_reply(source, 0) == 0);
    assert(sd_bus_message_get_expect_reply(source) == 0);
    assert(sd_bus_message_seal(source, 41U, 1000U) == 0);
    assert(sd_bus_message_get_cookie(source, &cookie) == 0 && cookie == 41U);
    assert(sd_bus_message_append(source, "s", "forbidden") == -EPERM);
    assert(sd_bus_message_peek_type(source, &type, &contents) > 0 && type == SD_BUS_TYPE_STRING);
    assert(contents == NULL);
    assert(sd_bus_message_read(source, "s", &text) == 1 && strcmp(text, "hello") == 0);
    assert(sd_bus_message_peek_type(source, &type, &contents) > 0 &&
           type == SD_BUS_TYPE_ARRAY && contents && strcmp(contents, "u") == 0);
    assert(sd_bus_message_read_array(source, SD_BUS_TYPE_UINT32, &read_values, &size) > 0);
    assert(size == sizeof(values) && memcmp(read_values, values, size) == 0);

    assert(sd_bus_message_rewind(source, 1) > 0);
    assert(sd_bus_message_new_method_call(bus, &copy, "org.example.Test",
                                          "/org/example/Test",
                                          "org.example.Test", "Copied") == 0);
    assert(sd_bus_message_copy(copy, source, 1) == 2);
    assert(sd_bus_message_read(copy, "s", &text) == 1 && strcmp(text, "hello") == 0);
    assert(sd_bus_message_read_array(copy, SD_BUS_TYPE_UINT32, &read_values, &size) > 0);
    assert(size == sizeof(values) && memcmp(read_values, values, size) == 0);

    sd_bus_message_unref(copy);
    sd_bus_message_unref(source);
    sd_bus_unref(bus);
}

static void test_real_session_bus(void) {
    sd_bus *bus = NULL;
    sd_bus_message *reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    const char *unique = NULL;
    int r;

    r = sd_bus_open_user(&bus);
    assert(r == 0);
    assert(bus != NULL);
    assert(sd_bus_get_fd(bus) >= 0);
    assert(sd_bus_get_events(bus) > 0);
    assert(sd_bus_get_unique_name(bus, &unique) == 0);
    assert(unique && unique[0] == ':');

    assert(sd_bus_call_method_async(
               bus, NULL, "org.freedesktop.DBus", "/org/freedesktop/DBus",
               "org.freedesktop.DBus", "ListNames", NULL, NULL, "") > 0);

    r = sd_bus_call_method(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "ListNames",
        &error,
        &reply,
        NULL);
    if (r < 0) {
        fprintf(stderr, "ListNames failed: %s: %s (%d)\n",
                error.name ? error.name : "(none)",
                error.message ? error.message : "(none)", r);
    }
    assert(r >= 0);
    assert(reply != NULL);

    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "s") > 0);
    {
        const char *name = NULL;
        int found_dbus = 0;
        while (sd_bus_message_read(reply, "s", &name) > 0) {
            assert(name != NULL);
            if (strcmp(name, "org.freedesktop.DBus") == 0)
                found_dbus = 1;
        }
        assert(found_dbus);
    }
    assert(sd_bus_message_exit_container(reply) > 0);
    sd_bus_message_unref(reply);
    reply = NULL;

    /* Remote D-Bus errors must become errno-style failures with sd_bus_error. */
    r = sd_bus_call_method(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "DefinitelyNotAMethod",
        &error,
        &reply,
        NULL);
    assert(r < 0);
    assert(error.name != NULL);
    assert(sd_bus_error_get_errno(&error) > 0);
    sd_bus_error_free(&error);
    if (reply) {
        sd_bus_message_unref(reply);
        reply = NULL;
    }

    sd_bus_unref(bus);
}

static void test_async_session_bus(void) {
    sd_bus *bus = NULL;
    sd_bus_slot *slot = NULL;
    sd_bus_message *call = NULL;
    int callback_marker = 0;
    int r;
    uint64_t timeout = UINT64_MAX;

    async_called = 0;
    async_saw_dbus = 0;
    assert(sd_bus_open_user(&bus) == 0);
    assert(sd_bus_message_new_method_call(
               bus, &call,
               "org.freedesktop.DBus",
               "/org/freedesktop/DBus",
               "org.freedesktop.DBus",
               "ListNames") == 0);
    assert(sd_bus_call_async(bus, &slot, call, list_names_callback,
                             &callback_marker, 5U * 1000U * 1000U) == 0);
    assert(sd_bus_get_timeout(bus, &timeout) == 0 && timeout != UINT64_MAX);
    assert(slot != NULL);
    assert(sd_bus_slot_ref(slot) == slot);
    assert(sd_bus_slot_unref(slot) == NULL);

    for (int i = 0; i < 500 && !async_called; ++i) {
        r = sd_bus_process(bus, NULL);
        assert(r >= 0);
        if (!async_called)
            usleep(10000);
    }
    assert(async_called);
    assert(callback_marker == 1);
    assert(async_saw_dbus);

    sd_bus_slot_unref(slot);
    sd_bus_message_unref(call);
    sd_bus_unref(bus);
}

static void test_default_user_lifecycle(void) {
    sd_bus *bus = NULL;
    assert(sd_bus_default_user(&bus) == 0);
    assert(bus != NULL);
    assert(sd_bus_wait(bus, 0) >= 0);
    assert(sd_bus_flush_close_unref(bus) == NULL);
}

static void test_configured_address_client(void) {
    sd_bus *bus = NULL;
    const char *address = getenv("DBUS_SESSION_BUS_ADDRESS");
    const char *unique = NULL;
    assert(address && *address);
    assert(sd_bus_new(&bus) == 0);
    assert(sd_bus_set_address(bus, address) == 0);
    assert(sd_bus_set_bus_client(bus, 1) == 0);
    assert(sd_bus_start(bus) == 0);
    assert(sd_bus_get_unique_name(bus, &unique) == 0);
    assert(unique && unique[0] == ':');
    sd_bus_unref(bus);
}

static void transfer_exact(int fd, void *buffer, size_t size, int writing) {
    unsigned char *cursor = buffer;
    while (size > 0U) {
        ssize_t n = writing ? write(fd, cursor, size) : read(fd, cursor, size);
        assert(n > 0);
        cursor += (size_t)n;
        size -= (size_t)n;
    }
}

static void raw_peer_reply(int fd) {
    static const unsigned char auth_request[] =
        "\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    static const char auth_reply[] =
        "DATA\r\nOK 0123456789abcdef0123456789abcdef\r\nAGREE_UNIX_FD\r\n";
    unsigned char received_auth[sizeof(auth_request) - 1U];
    unsigned char header[16];
    DBusMessage *reply;
    DBusMessage *signal;
    unsigned char *wire;
    char *reply_wire = NULL;
    unsigned char control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = header, .iov_len = sizeof(header)};
    struct msghdr received = {0};
    struct cmsghdr *cmsg;
    uint32_t call_serial;
    int needed;
    int reply_size = 0;

    transfer_exact(fd, received_auth, sizeof(received_auth), 0);
    assert(memcmp(received_auth, auth_request, sizeof(received_auth)) == 0);
    transfer_exact(fd, (void *)auth_reply, sizeof(auth_reply) - 1U, 1);

    received.msg_iov = &iov;
    received.msg_iovlen = 1;
    received.msg_control = control;
    received.msg_controllen = sizeof(control);
    assert(recvmsg(fd, &received, MSG_WAITALL) == (ssize_t)sizeof(header));
    cmsg = CMSG_FIRSTHDR(&received);
    assert(cmsg != NULL);
    assert(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS);
    assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
    close(*(int *)CMSG_DATA(cmsg));
    needed = dbus_message_demarshal_bytes_needed((const char *)header, sizeof(header));
    assert(needed >= (int)sizeof(header));
    wire = malloc((size_t)needed);
    assert(wire != NULL);
    memcpy(wire, header, sizeof(header));
    transfer_exact(fd, wire + sizeof(header), (size_t)needed - sizeof(header), 0);
    if (header[0] == 'l')
        call_serial = (uint32_t)header[8] | ((uint32_t)header[9] << 8) |
                      ((uint32_t)header[10] << 16) | ((uint32_t)header[11] << 24);
    else
        call_serial = ((uint32_t)header[8] << 24) | ((uint32_t)header[9] << 16) |
                      ((uint32_t)header[10] << 8) | (uint32_t)header[11];
    free(wire);
    assert(call_serial != 0U);
    reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    assert(reply != NULL);
    assert(dbus_message_set_reply_serial(reply, call_serial));
    dbus_message_set_serial(reply, 77U);
    assert(dbus_message_marshal(reply, &reply_wire, &reply_size));
    transfer_exact(fd, reply_wire, (size_t)reply_size, 1);
    dbus_free(reply_wire);
    dbus_message_unref(reply);

    signal = dbus_message_new_signal(
        "/org/example/Peer", "org.example.Peer", "Changed");
    assert(signal != NULL);
    reply_wire = NULL;
    reply_size = 0;
    dbus_message_set_serial(signal, 78U);
    assert(dbus_message_marshal(signal, &reply_wire, &reply_size));
    transfer_exact(fd, reply_wire, (size_t)reply_size, 1);
    dbus_free(reply_wire);
    dbus_message_unref(signal);
}

static void test_raw_peer_call(void) {
    int pair[2];
    pid_t child;
    sd_bus *bus = NULL;
    sd_bus_message *call = NULL;
    int probe[2];

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    assert(pipe2(probe, O_CLOEXEC) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(pair[0]);
        close(probe[0]);
        close(probe[1]);
        raw_peer_reply(pair[1]);
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    close(probe[1]);
    assert(sd_bus_new(&bus) == 0);
    assert(sd_bus_set_fd(bus, pair[0], pair[0]) == 0);
    assert(sd_bus_add_filter(bus, NULL, raw_filter, &raw_filter_called) == 0);
    assert(sd_bus_start(bus) == 0);
    assert(sd_bus_message_new_method_call(
               bus, &call, NULL, "/org/example/Peer", "org.example.Peer", "Probe") == 0);
    assert(sd_bus_message_append(call, "h", probe[0]) == 0);
    close(probe[0]);
    assert(sd_bus_call(bus, call, 5U * 1000U * 1000U, NULL, NULL) > 0);
    assert(sd_bus_wait(bus, 5U * 1000U * 1000U) > 0);
    assert(sd_bus_process(bus, NULL) > 0);
    assert(raw_filter_called > 0);
    sd_bus_message_unref(call);
    sd_bus_unref(bus);
    assert(waitpid(child, NULL, 0) == child);
}

static int raw_server_reply(sd_bus_message *call, void *userdata, sd_bus_error *error) {
    sd_bus *bus = userdata;
    sd_bus_message *reply = NULL;
    (void)error;
    assert(sd_bus_message_new_method_return(call, &reply) == 0);
    assert(sd_bus_message_append(reply, "s", "server-ready") == 0);
    assert(sd_bus_send(bus, reply, NULL) > 0);
    sd_bus_message_unref(reply);
    return 1;
}

static int object_property_get(sd_bus *bus, const char *path, const char *interface,
                               const char *property, sd_bus_message *reply,
                               void *userdata, sd_bus_error *error) {
    const char *value = userdata;
    (void)bus;
    (void)path;
    (void)interface;
    (void)property;
    (void)error;
    return sd_bus_message_append(reply, "s", value);
}

static const sd_bus_vtable object_vtable[] = {
    {.type = _SD_BUS_VTABLE_START,
     .x.start = {.element_size = sizeof(sd_bus_vtable),
                 .features = 0U,
                 .vtable_format_reference = &sd_bus_object_vtable_format}},
    {.type = _SD_BUS_VTABLE_PROPERTY,
     .x.property = {.member = "Value", .signature = "s",
                    .get = object_property_get, .set = NULL, .offset = 0U}},
    {.type = _SD_BUS_VTABLE_END},
};

static void test_raw_server_transport(void) {
    int pair[2];
    pid_t child;
    sd_bus *client = NULL;
    sd_bus_message *call = NULL;
    sd_bus_message *reply = NULL;
    const char *text = NULL;

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        sd_bus *server = NULL;
        sd_id128_t id = {{0}};
        int handled = 0;
        id.bytes[15] = 1U;
        close(pair[0]);
        assert(sd_bus_new(&server) == 0);
        assert(sd_bus_set_fd(server, pair[1], pair[1]) == 0);
        assert(sd_bus_set_server(server, 1, id) == 0);
        assert(sd_bus_set_trusted(server, 0) == 0);
        assert(sd_bus_add_filter(server, NULL, raw_server_reply, server) == 0);
        assert(sd_bus_start(server) == 0);
        for (int i = 0; i < 500 && !handled; ++i) {
            int r = sd_bus_process(server, NULL);
            assert(r >= 0);
            handled = r > 0;
            if (!handled)
                usleep(1000);
        }
        sd_bus_unref(server);
        _exit(handled ? 0 : 1);
    }
    close(pair[1]);
    assert(sd_bus_new(&client) == 0);
    assert(sd_bus_set_fd(client, pair[0], pair[0]) == 0);
    assert(sd_bus_set_bus_client(client, 0) == 0);
    assert(sd_bus_start(client) == 0);
    assert(sd_bus_message_new_method_call(client, &call, NULL, "/org/example/Peer",
                                           "org.example.Peer", "Probe") == 0);
    assert(sd_bus_call(client, call, 5U * 1000U * 1000U, NULL, &reply) > 0);
    assert(sd_bus_message_read(reply, "s", &text) == 1);
    assert(strcmp(text, "server-ready") == 0);
    sd_bus_message_unref(reply);
    sd_bus_message_unref(call);
    sd_bus_unref(client);
    {
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

static void test_raw_object_manager(void) {
    int pair[2];
    pid_t child;
    sd_bus *client = NULL;
    sd_bus_message *call = NULL;
    sd_bus_message *reply = NULL;
    const char *path = NULL;
    const char *interface = NULL;
    const char *property = NULL;
    const char *value = NULL;
    char entry_type = 0;

    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        sd_bus *server = NULL;
        sd_id128_t id = {{0}};
        int handled = 0;
        id.bytes[15] = 2U;
        close(pair[0]);
        assert(sd_bus_new(&server) == 0);
        assert(sd_bus_set_fd(server, pair[1], pair[1]) == 0);
        assert(sd_bus_set_server(server, 1, id) == 0);
        assert(sd_bus_add_object_vtable(server, NULL, "/org/example/Object",
                                        "org.example.Object", object_vtable,
                                        "ready") == 0);
        assert(sd_bus_add_object_manager(server, NULL, "/org/example") == 0);
        assert(sd_bus_start(server) == 0);
        for (int i = 0; i < 500 && !handled; ++i) {
            int r = sd_bus_process(server, NULL);
            assert(r >= 0);
            handled = r > 0;
            if (!handled)
                usleep(1000);
        }
        sd_bus_unref(server);
        _exit(handled ? 0 : 1);
    }
    close(pair[1]);
    assert(sd_bus_new(&client) == 0);
    assert(sd_bus_set_fd(client, pair[0], pair[0]) == 0);
    assert(sd_bus_start(client) == 0);
    assert(sd_bus_message_new_method_call(client, &call, NULL, "/org/example",
                                           "org.freedesktop.DBus.ObjectManager",
                                           "GetManagedObjects") == 0);
    assert(sd_bus_call(client, call, 5U * 1000U * 1000U, NULL, &reply) > 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY,
                                           "{oa{sa{sv}}}") > 0);
    assert(sd_bus_message_peek_type(reply, &entry_type, NULL) > 0);
    assert(entry_type == SD_BUS_TYPE_DICT_ENTRY);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY,
                                           "oa{sa{sv}}") > 0);
    assert(sd_bus_message_read(reply, "o", &path) == 1);
    assert(strcmp(path, "/org/example/Object") == 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sa{sv}}") > 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}") > 0);
    assert(sd_bus_message_read(reply, "s", &interface) == 1);
    assert(strcmp(interface, "org.example.Object") == 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}") > 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_DICT_ENTRY, "sv") > 0);
    assert(sd_bus_message_read(reply, "s", &property) == 1);
    assert(strcmp(property, "Value") == 0);
    assert(sd_bus_message_enter_container(reply, SD_BUS_TYPE_VARIANT, "s") > 0);
    assert(sd_bus_message_read(reply, "s", &value) == 1);
    assert(strcmp(value, "ready") == 0);
    sd_bus_message_unref(reply);
    sd_bus_message_unref(call);
    sd_bus_unref(client);
    {
        int status = 0;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

#ifdef RUSTD_TEST_EVENT_ATTACHMENT
struct event_test_context {
    int prepared;
    int called;
};

static int event_prepare(sd_event_source *source, void *userdata) {
    struct event_test_context *context = userdata;
    assert(source != NULL);
    context->prepared++;
    return 0;
}

static int event_timer(sd_event_source *source, uint64_t usec, void *userdata) {
    sd_event *event = sd_event_source_get_event(source);
    struct event_test_context *context = userdata;
    assert(usec > 0U);
    context->called++;
    return sd_event_exit(event, 23);
}

static void test_event_attachment(void) {
    sd_bus *bus = NULL;
    sd_event *event = NULL;

    assert(sd_bus_open_user(&bus) == 0);
    assert(sd_event_default(&event) == 0);
    assert(sd_bus_attach_event(bus, event, 17) == 0);
    assert(sd_bus_attach_event(bus, event, 17) == -EBUSY);
    sd_bus_unref(bus);
    sd_event_unref(event);
}

static int event_async_reply(sd_bus_message *reply, void *userdata,
                             sd_bus_error *error) {
    sd_event *event = userdata;
    (void)error;
    assert(reply != NULL);
    return sd_event_exit(event, 31);
}

static void test_event_async_bus(void) {
    sd_bus *bus = NULL;
    sd_bus_message *call = NULL;
    sd_event *event = NULL;
    assert(sd_bus_open_user(&bus) == 0);
    assert(sd_event_default(&event) == 0);
    assert(sd_bus_attach_event(bus, event, 0) == 0);
    assert(sd_bus_message_new_method_call(
               bus, &call, "org.freedesktop.DBus", "/org/freedesktop/DBus",
               "org.freedesktop.DBus", "ListNames") == 0);
    assert(sd_bus_call_async(bus, NULL, call, event_async_reply, event,
                             5U * 1000U * 1000U) == 0);
    assert(sd_event_loop(event) == 31);
    sd_bus_message_unref(call);
    sd_bus_unref(bus);
    sd_event_unref(event);
}

static void test_event_controls(void) {
    struct timespec now;
    sd_event *event = NULL;
    sd_event_source *timer = NULL;
    sd_event_source *disabled = NULL;
    uint64_t usec;
    struct event_test_context context = {0};

    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    usec = (uint64_t)now.tv_sec * 1000000U + (uint64_t)now.tv_nsec / 1000U + 2000U;
    assert(sd_event_default(&event) == 0);
    assert(sd_event_ref(event) == event);
    assert(sd_event_unref(event) == NULL);
    assert(sd_event_add_time(event, &timer, CLOCK_MONOTONIC, usec, 0U,
                             event_timer, &context) == 0);
    assert(sd_event_source_set_description(timer, "test timer") == 0);
    assert(sd_event_source_set_prepare(timer, event_prepare) == 0);
    assert(sd_event_loop(event) == 23);
    assert(context.called == 1);
    assert(context.prepared >= 1);
    assert(sd_event_add_time(event, &disabled, CLOCK_MONOTONIC, usec, 0U,
                             event_timer, &context) == 0);
    assert(sd_event_source_set_enabled(disabled, 0) == 0);
    assert(sd_event_source_set_time(disabled, usec) == 0);
    assert(sd_event_source_disable_unref(disabled) == NULL);
    sd_event_source_unref(timer);
    sd_event_unref(event);
}
#endif

int main(void) {
    test_local_message_codec();
    test_extended_message_codec();
    test_real_session_bus();
    test_matches_and_emission();
    test_async_session_bus();
    test_default_user_lifecycle();
    test_configured_address_client();
    test_raw_peer_call();
    test_raw_server_transport();
    test_raw_object_manager();
#ifdef RUSTD_TEST_EVENT_ATTACHMENT
    test_event_attachment();
    test_event_async_bus();
    test_event_controls();
#endif
    return 0;
}
