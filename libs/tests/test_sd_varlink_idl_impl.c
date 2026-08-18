/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>
#include <string.h>

#include "../compat/sd_json_varlink_abi.h"

static void expect_valid(const char *text, const char *name) {
    sd_varlink_interface *interface = NULL;
    unsigned line = 99, column = 99;
    int r = sd_varlink_idl_parse(text, &line, &column, &interface);
    assert(r == 0);
    assert(interface != NULL);
    assert(line == 0U && column == 0U);
    /* Public ABI starts with the borrowed/owned interface name pointer. */
    assert(strcmp(*(const char * const *)interface, name) == 0);
    assert(sd_varlink_interface_free(interface) == NULL);
}

static void expect_invalid(const char *text) {
    sd_varlink_interface *interface = NULL;
    unsigned line = 0, column = 0;
    int r = sd_varlink_idl_parse(text, &line, &column, &interface);
    assert(r < 0);
    assert(interface == NULL);
    assert(line > 0U && column > 0U);
}

int main(void) {
    expect_valid(
        "# service\n"
        "interface org.example.deep\n"
        "type Item (name: string, tags: []string, meta: [string]?string)\n"
        "type Choice (one, two, three)\n"
        "method Lookup(query: string, options: ?[](key: string, value: any)) -> "
        "(item: ?Item, flags: [string]bool)\n"
        "error Missing(name: string)\n"
        "error Empty()\n",
        "org.example.deep");

    expect_valid(
        "interface io.rustd.Test\n"
        "method Ping() -> ()\n",
        "io.rustd.Test");

    expect_invalid("method Ping() -> ()\n");
    expect_invalid("interface invalid\nmethod Ping() -> ()\n");
    expect_invalid("interface org.example.bad\n");
    expect_invalid("interface org.example.bad\nmethod Bad_Name() -> ()\n");
    expect_invalid("interface org.example.bad\ntype Bad_Name (x: int)\n");
    expect_invalid("interface org.example.bad\nmethod Ping() (x: int)\n");
    expect_invalid("interface org.example.bad\nmethod Ping(x: []bogus) -> ()\n");
    expect_invalid("interface org.example.bad\nerror Oops(x string)\n");
    return 0;
}
