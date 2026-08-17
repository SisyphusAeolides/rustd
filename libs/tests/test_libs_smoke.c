/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>
#include <stdio.h>
#include <rustd/service.h>
#include <rustd/journal.h>
#include <rustd/device.h>
#include <rustd/login.h>
#include <rustd/manager.h>

int main(void) {
    assert(rustd_service_abi_version() == 1U);
    assert(rustd_journal_abi_version() == 1U);
    assert(rustd_device_abi_version() == 1U);
    assert(rustd_login_abi_version() == 1U);
    assert(rustd_manager_abi_version() == 1U);

    assert(rustd_listen_fds(0) == 0);
    assert(rustd_notify_ready() == 0 || rustd_notify_ready() < 0);

    {
        rustd_device_ctx *ctx = rustd_device_ctx_new();
        rustd_device_enumerate *enumerate;
        assert(ctx);
        enumerate = rustd_device_enumerate_new(ctx);
        assert(enumerate);
        assert(rustd_device_enumerate_add_match_subsystem(enumerate, "net") == 0);
        assert(rustd_device_enumerate_scan_devices(enumerate) == 0);
        rustd_device_enumerate_unref(enumerate);
        rustd_device_ctx_unref(ctx);
    }

    {
        rustd_journal *journal = NULL;
        int opened = rustd_journal_open(&journal, "/tmp/rustd-journal-missing");
        if (opened == 0) {
            rustd_journal_unref(journal);
        }
    }

    puts("librustd smoke ok");
    return 0;
}
