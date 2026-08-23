/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <dbus/dbus.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "sd_bus_abi.h"

static int async_called;
static int async_saw_dbus;
static int raw_filter_called;

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

int main(void) {
    test_local_message_codec();
    test_real_session_bus();
    test_async_session_bus();
    test_default_user_lifecycle();
    test_raw_peer_call();
    return 0;
}
