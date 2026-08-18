/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * spawn_wire.h — bounded request format shared by the manager side of
 * rustd_spawn() and the helper image that performs child setup.
 *
 * The manager never forks: it serialises the spawn parameters into a sealed
 * memfd and posix_spawn()s a fresh RustD image in helper mode.  The helper is
 * the final service process, so every field the child used to read from
 * inherited manager memory has to survive the exec through this format.
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

#define RUSTD_SPAWN_WIRE_MAGIC UINT32_C(0x52535057) /* "RSPW" */
#define RUSTD_SPAWN_WIRE_VERSION UINT32_C(2)

/*
 * Request bounds.  Every count is validated on both sides so a malformed or
 * hostile request can never drive an unbounded allocation or a wild read.
 */
#define RUSTD_SPAWN_MAX_REQUEST_BYTES ((size_t)256 * 1024)
#define RUSTD_SPAWN_MAX_STRING_BYTES ((size_t)64 * 1024)
#define RUSTD_SPAWN_MAX_ARGV 1024u
#define RUSTD_SPAWN_MAX_ENV 4096u
#define RUSTD_SPAWN_MAX_RLIMITS 64u
#define RUSTD_SPAWN_MAX_LISTEN_FDS 256
#define RUSTD_SPAWN_MAX_SECCOMP_RULES 8192u
#define RUSTD_SPAWN_MAX_READ_WRITE_PATHS 256u

/*
 * File descriptor layout handed to the helper image.  Slots 3..5 are always
 * accounted for: the helper closes any slot the manager did not map, so no
 * manager descriptor can survive at a fixed number.
 */
#define RUSTD_SPAWN_REQUEST_FD 3
#define RUSTD_SPAWN_ERROR_FD 4
#define RUSTD_SPAWN_IDLE_FD 5
#define RUSTD_SPAWN_LISTEN_FD_BASE 6

/* First descriptor number seen by the executed service for listener passing. */
#define RUSTD_LISTEN_FDS_START 3

/* argv[1] of the helper image.  Not a documented or supported invocation. */
#define RUSTD_SPAWN_HELPER_ARGUMENT "--rustd-internal-spawn-helper"

#define RUSTD_SPAWN_FLAG_WAIT_FOR_EXEC (UINT32_C(1) << 0)
#define RUSTD_SPAWN_FLAG_HAS_ENVIRONMENT (UINT32_C(1) << 1)
#define RUSTD_SPAWN_FLAG_HAS_SANDBOX (UINT32_C(1) << 2)
#define RUSTD_SPAWN_FLAG_HAS_IDLE_GATE (UINT32_C(1) << 3)
#define RUSTD_SPAWN_FLAG_HAS_CWD (UINT32_C(1) << 4)
#define RUSTD_SPAWN_FLAG_HAS_CGROUP (UINT32_C(1) << 5)
#define RUSTD_SPAWN_FLAG_HAS_SELINUX (UINT32_C(1) << 6)
#define RUSTD_SPAWN_FLAG_HAS_APPARMOR (UINT32_C(1) << 7)
#define RUSTD_SPAWN_FLAG_SELINUX_IGNORE (UINT32_C(1) << 8)
#define RUSTD_SPAWN_FLAG_APPARMOR_IGNORE (UINT32_C(1) << 9)
#define RUSTD_SPAWN_FLAG_HAS_NOTIFY_SOCKET (UINT32_C(1) << 10)
#define RUSTD_SPAWN_FLAG_ALL                                                   \
    (RUSTD_SPAWN_FLAG_WAIT_FOR_EXEC | RUSTD_SPAWN_FLAG_HAS_ENVIRONMENT         \
     | RUSTD_SPAWN_FLAG_HAS_SANDBOX | RUSTD_SPAWN_FLAG_HAS_IDLE_GATE           \
     | RUSTD_SPAWN_FLAG_HAS_CWD | RUSTD_SPAWN_FLAG_HAS_CGROUP                  \
     | RUSTD_SPAWN_FLAG_HAS_SELINUX | RUSTD_SPAWN_FLAG_HAS_APPARMOR            \
     | RUSTD_SPAWN_FLAG_SELINUX_IGNORE | RUSTD_SPAWN_FLAG_APPARMOR_IGNORE      \
     | RUSTD_SPAWN_FLAG_HAS_NOTIFY_SOCKET)

/*
 * Fixed request header.  The payload that follows carries, in this order:
 * path, argv, environment, cwd, cgroup.procs path, SELinux context, AppArmor
 * profile, notify socket, ReadWritePaths entries, rlimits, and compiled
 * seccomp rules. Optional entries are present only when their flag bit/count
 * indicates that they exist.
 */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t header_bytes;
    uint32_t total_bytes;
    uint32_t flags;
    uint32_t n_argv;
    uint32_t n_env;
    uint32_t n_rlimits;
    uint32_t n_listen_fds;
    uint32_t n_seccomp_rules;
    uint32_t n_read_write_paths;
    uint32_t seccomp_default_action;
    uint32_t uid;
    uint32_t gid;
    uint32_t no_new_privs;
    uint32_t private_tmp;
    uint32_t private_devices;
    uint32_t private_network;
    uint32_t private_mounts;
    uint32_t protect_system;
    uint32_t protect_home;
    uint32_t protect_kernel_tunables;
    uint32_t protect_kernel_modules;
    uint32_t protect_kernel_logs;
    uint32_t protect_clock;
    uint32_t protect_control_groups;
    uint32_t restrict_suid_sgid;
    uint32_t restrict_realtime;
    uint32_t restrict_namespaces;
    uint32_t memory_deny_write_execute;
    uint32_t syscall_filter_enabled;
    uint32_t restrict_native_syscalls;
    uint32_t reserved;
    uint64_t cap_bounding_set;
    uint64_t ambient_caps;
    uint64_t watchdog_usec;
} rustd_spawn_wire_header;

/*
 * Writer.  With data == NULL the writer only measures, so the manager sizes
 * the request with the same code that fills it.
 */
typedef struct {
    unsigned char *data;
    size_t capacity;
    size_t offset;
    int failed;
} rustd_spawn_writer;

static inline void rustd_spawn_write_bytes(
        rustd_spawn_writer *writer,
        const void *bytes,
        size_t length) {
    if (writer->failed)
        return;
    if (length > SIZE_MAX - writer->offset) {
        writer->failed = 1;
        return;
    }
    if (writer->data) {
        if (length > writer->capacity - writer->offset) {
            writer->failed = 1;
            return;
        }
        memcpy(writer->data + writer->offset, bytes, length);
    }
    writer->offset += length;
}

static inline void rustd_spawn_write_u32(rustd_spawn_writer *writer, uint32_t value) {
    rustd_spawn_write_bytes(writer, &value, sizeof(value));
}

static inline void rustd_spawn_write_u64(rustd_spawn_writer *writer, uint64_t value) {
    rustd_spawn_write_bytes(writer, &value, sizeof(value));
}

/* Strings are stored as a length prefix, the bytes, and a NUL terminator. */
static inline void rustd_spawn_write_string(
        rustd_spawn_writer *writer,
        const char *value,
        size_t length) {
    static const char terminator = '\0';
    if (length > RUSTD_SPAWN_MAX_STRING_BYTES) {
        writer->failed = 1;
        return;
    }
    rustd_spawn_write_u32(writer, (uint32_t)length);
    rustd_spawn_write_bytes(writer, value, length);
    rustd_spawn_write_bytes(writer, &terminator, 1);
}

typedef struct {
    const unsigned char *data;
    size_t size;
    size_t offset;
} rustd_spawn_reader;

static inline int rustd_spawn_read_bytes(
        rustd_spawn_reader *reader,
        void *out,
        size_t length) {
    if (length > reader->size - reader->offset)
        return -EPROTO;
    memcpy(out, reader->data + reader->offset, length);
    reader->offset += length;
    return 0;
}

static inline int rustd_spawn_read_u32(rustd_spawn_reader *reader, uint32_t *out) {
    return rustd_spawn_read_bytes(reader, out, sizeof(*out));
}

static inline int rustd_spawn_read_u64(rustd_spawn_reader *reader, uint64_t *out) {
    return rustd_spawn_read_bytes(reader, out, sizeof(*out));
}

/*
 * Return a pointer to a NUL-terminated string inside the request buffer.  The
 * bytes are validated to be terminator-free so the helper can hand the pointer
 * straight to execve(2) without copying.
 */
static inline int rustd_spawn_read_string(rustd_spawn_reader *reader, const char **out) {
    uint32_t length;
    int r = rustd_spawn_read_u32(reader, &length);
    if (r < 0)
        return r;
    if ((size_t)length > RUSTD_SPAWN_MAX_STRING_BYTES)
        return -EPROTO;
    size_t total = (size_t)length + 1;
    if (total > reader->size - reader->offset)
        return -EPROTO;

    const char *value = (const char *)(reader->data + reader->offset);
    if (value[length] != '\0')
        return -EPROTO;
    if (length > 0 && memchr(value, '\0', length) != NULL)
        return -EPROTO;

    reader->offset += total;
    *out = value;
    return 0;
}
