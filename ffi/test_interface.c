/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>

unsigned rustd_interface_abi_version(void);
int rustd_interface_valid_object_path(const char *path);
int rustd_interface_valid_member_name(const char *name);

int main(void) {
    assert(rustd_interface_abi_version() == 1U);

    assert(rustd_interface_valid_object_path("/") == 1);
    assert(rustd_interface_valid_object_path("/io/rustd/Manager_1") == 1);
    assert(rustd_interface_valid_object_path(NULL) == 0);
    assert(rustd_interface_valid_object_path("") == 0);
    assert(rustd_interface_valid_object_path("relative") == 0);
    assert(rustd_interface_valid_object_path("//bad") == 0);
    assert(rustd_interface_valid_object_path("/bad/") == 0);
    assert(rustd_interface_valid_object_path("/bad-char!") == 0);

    assert(rustd_interface_valid_member_name("Reload") == 1);
    assert(rustd_interface_valid_member_name("reload_2") == 1);
    assert(rustd_interface_valid_member_name(NULL) == 0);
    assert(rustd_interface_valid_member_name("") == 0);
    assert(rustd_interface_valid_member_name("2bad") == 0);
    assert(rustd_interface_valid_member_name("bad.name") == 0);
    return 0;
}
