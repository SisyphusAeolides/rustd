/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * journal.h — journal socket receiver and binary-format helpers.
 *
 * Upstream reference: src/journal/ (v261)
 */

/* ── socket helpers ─────────────────────────────────────────────────────── */

/*
 * rustd_journal_socket_bind: create and bind the SOCK_DGRAM AF_UNIX socket at
 * /run/rustd/journal/socket.  The socket is made world-writable so
 * unprivileged services can submit log entries. SO_PASSCRED is enabled so
 * recv can recover peer credentials. An existing path is never removed and
 * causes bind to fail.
 * Returns fd on success, -errno on failure.
 */
int rustd_journal_socket_bind(void);

/*
 * rustd_journal_socket_recv: receive one datagram from the journal socket.
 * When SO_PASSCRED is enabled, peer credentials are written to the optional
 * pid/uid/gid out-parameters (pass NULL to ignore). SCM_RIGHTS fds are closed.
 * Returns bytes received on success, -errno on failure (-EAGAIN if empty).
 */
ssize_t rustd_journal_socket_recv(
    int fd,
    void *buf,
    size_t len,
    pid_t *pid,
    uid_t *uid,
    gid_t *gid);

/* ── stdout stream socket ───────────────────────────────────────────────── */

/*
 * rustd_journal_stdout_bind: create and bind the SOCK_STREAM AF_UNIX socket at
 * /run/rustd/journal/stdout and begin listening. An existing path is never
 * removed and causes bind to fail.
 * Returns fd on success, -errno on failure.
 */
int rustd_journal_stdout_bind(void);

/* ── compressed journal DATA helpers ────────────────────────────────────── */

/*
 * Decode a compressed journal DATA payload. flags uses the upstream object
 * compression bits: 1=XZ, 2=LZ4, 4=ZSTD. When destination is NULL, formats
 * with an encoded output size return that size; XZ returns -ENODATA.
 * Returns decoded bytes on success, -ENOBUFS when destination is too small,
 * -EOPNOTSUPP when the required runtime library is unavailable, or -errno.
 */
ssize_t rustd_journal_decompress_payload(
    uint8_t flags,
    const uint8_t *source,
    size_t source_size,
    uint8_t *destination,
    size_t destination_size);

/* ── binary journal file helpers ────────────────────────────────────────── */

/*
 * SdJournalField: a single structured key=value field for journal entries.
 */
typedef struct SdJournalField {
    const char    *key;
    const uint8_t *value;
    size_t         value_len;
} SdJournalField;

/*
 * rustd_journal_file_open: open or create a binary journal file at path.
 * A new file receives the upstream regular journal header plus real DATA/FIELD
 * hash-table objects. An existing compatible offline file is reopened for append.
 * Returns fd (O_RDWR) on success, -errno on failure.
 */
int rustd_journal_file_open(const char *path);

/*
 * rustd_journal_file_append: append one entry object to an open journal file.
 * Returns 0 on success, -errno on failure.
 */
int rustd_journal_file_append(int fd, const SdJournalField *fields, size_t n_fields,
                            uint64_t realtime_usec, uint64_t seqnum);

/*
 * rustd_journal_file_close: fsync and close the journal file.
 * Returns 0 on success, -errno on failure.
 */
int rustd_journal_file_close(int fd);
