/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int async_called;
static int async_saw_dbus;

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

int main(void) {
    test_local_message_codec();
    test_real_session_bus();
    test_async_session_bus();
    return 0;
}
