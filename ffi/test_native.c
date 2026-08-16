/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * test_native.c — tests for ffi/native.c.
 * Compiled and run by `make check-native`.
 */
#include "journal.h"
#include "native.h"

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static void expect_notification(
        int receiver,
        int (*notify_function)(void),
        const char *expected) {
    assert(notify_function() == 1);

    char buffer[64];
    const ssize_t received = recv(receiver, buffer, sizeof(buffer), 0);
    assert(received == (ssize_t)strlen(expected));
    assert(memcmp(buffer, expected, (size_t)received) == 0);
}

static void test_filesystem_notifications(void) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    const int written = snprintf(
        path,
        sizeof(path),
        "/tmp/rustd-notify-%ld.sock",
        (long)getpid());
    assert(written > 0 && (size_t)written < sizeof(path));
    (void)unlink(path);

    const int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(receiver >= 0);

    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    assert(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    const socklen_t length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
    assert(bind(receiver, (const struct sockaddr *)&address, length) == 0);
    assert(setenv("NOTIFY_SOCKET", path, 1) == 0);

    expect_notification(receiver, rustd_notify_ready, "READY=1\n");
    expect_notification(receiver, rustd_notify_stopping, "STOPPING=1\n");
    expect_notification(receiver, rustd_notify_watchdog, "WATCHDOG=1\n");

    close(receiver);
    (void)unlink(path);
}

static void test_abstract_notifications(void) {
    char socket_name[80];
    const int written = snprintf(
        socket_name,
        sizeof(socket_name),
        "@rustd-notify-%ld",
        (long)getpid());
    assert(written > 1 && (size_t)written < sizeof(socket_name));

    const int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(receiver >= 0);

    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    assert(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, socket_name + 1, strlen(socket_name) - 1);
    const socklen_t length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(socket_name));
    assert(bind(receiver, (const struct sockaddr *)&address, length) == 0);
    assert(setenv("NOTIFY_SOCKET", socket_name, 1) == 0);

    expect_notification(receiver, rustd_notify_ready, "READY=1\n");
    close(receiver);
}

static void test_notify_messages(void) {
    assert(unsetenv("NOTIFY_SOCKET") == 0);
    assert(rustd_notify_ready() == 0);

    test_filesystem_notifications();
    test_abstract_notifications();

    assert(setenv("NOTIFY_SOCKET", "relative-name", 1) == 0);
    assert(rustd_notify_ready() == -EINVAL);
    assert(unsetenv("NOTIFY_SOCKET") == 0);
}

static void test_watchdog_environment(void) {
    assert(unsetenv("WATCHDOG_USEC") == 0);
    assert(unsetenv("WATCHDOG_PID") == 0);

    uint64_t usec = UINT64_MAX;
    assert(rustd_watchdog_enabled(0, &usec) == 0);
    assert(usec == UINT64_MAX);

    assert(setenv("WATCHDOG_USEC", "2500000", 1) == 0);
    usec = 0;
    assert(rustd_watchdog_enabled(0, &usec) == 1);
    assert(usec == UINT64_C(2500000));

    char pid[32];
    assert(snprintf(pid, sizeof(pid), "%ld", (long)getpid()) > 0);
    assert(setenv("WATCHDOG_PID", pid, 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == 1);

    assert(snprintf(pid, sizeof(pid), "%ld", (long)getpid() + 1L) > 0);
    assert(setenv("WATCHDOG_PID", pid, 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == 0);

    assert(setenv("WATCHDOG_PID", "not-a-pid", 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == -EINVAL);
    assert(setenv("WATCHDOG_PID", "", 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == -EINVAL);

    assert(unsetenv("WATCHDOG_PID") == 0);
    assert(setenv("WATCHDOG_USEC", "0", 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == -EINVAL);
    assert(setenv("WATCHDOG_USEC", "12x", 1) == 0);
    assert(rustd_watchdog_enabled(0, NULL) == -EINVAL);

    assert(setenv("WATCHDOG_USEC", "1000000", 1) == 0);
    assert(setenv("WATCHDOG_PID", "1", 1) == 0);
    assert(rustd_watchdog_enabled(1, NULL) == 0);
    assert(getenv("WATCHDOG_USEC") == NULL);
    assert(getenv("WATCHDOG_PID") == NULL);
}

static void install_activation_descriptors(void) {
    int descriptors[2];
    assert(pipe(descriptors) == 0);

    const int source_read = fcntl(descriptors[0], F_DUPFD_CLOEXEC, 10);
    const int source_write = fcntl(descriptors[1], F_DUPFD_CLOEXEC, 10);
    assert(source_read >= 10);
    assert(source_write >= 10);
    close(descriptors[0]);
    close(descriptors[1]);

    assert(dup2(source_read, 3) == 3);
    assert(dup2(source_write, 4) == 4);
    close(source_read);
    close(source_write);
}

static void set_matching_pidfd_id(void) {
#if defined(SYS_pidfd_open)
    const int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0U);
    if (pidfd < 0)
        return;

    struct stat pidfd_stat;
    assert(fstat(pidfd, &pidfd_stat) == 0);
    close(pidfd);

    char inode[32];
    const int written = snprintf(
        inode,
        sizeof(inode),
        "%llu",
        (unsigned long long)pidfd_stat.st_ino);
    assert(written > 0 && (size_t)written < sizeof(inode));
    assert(setenv("LISTEN_PIDFDID", inode, 1) == 0);
#endif
}

static void test_listen_fds(void) {
    assert(unsetenv("LISTEN_PID") == 0);
    assert(unsetenv("LISTEN_PIDFDID") == 0);
    assert(unsetenv("LISTEN_FDS") == 0);
    assert(unsetenv("LISTEN_FDNAMES") == 0);
    assert(rustd_listen_fds(0) == 0);

    char pid[32];
    assert(snprintf(pid, sizeof(pid), "%ld", (long)getpid() + 1L) > 0);
    assert(setenv("LISTEN_PID", pid, 1) == 0);
    assert(setenv("LISTEN_FDS", "1", 1) == 0);
    assert(rustd_listen_fds(1) == 0);
    assert(getenv("LISTEN_PID") == NULL);
    assert(getenv("LISTEN_FDS") == NULL);

    install_activation_descriptors();
    assert(snprintf(pid, sizeof(pid), "%ld", (long)getpid()) > 0);
    assert(setenv("LISTEN_PID", pid, 1) == 0);
    set_matching_pidfd_id();
    assert(setenv("LISTEN_FDS", "2", 1) == 0);
    assert(setenv("LISTEN_FDNAMES", "read:write", 1) == 0);
    assert(rustd_listen_fds(1) == 2);
    assert((fcntl(3, F_GETFD) & FD_CLOEXEC) != 0);
    assert((fcntl(4, F_GETFD) & FD_CLOEXEC) != 0);
    assert(getenv("LISTEN_PID") == NULL);
    assert(getenv("LISTEN_PIDFDID") == NULL);
    assert(getenv("LISTEN_FDS") == NULL);
    assert(getenv("LISTEN_FDNAMES") == NULL);
    close(3);
    close(4);

    assert(setenv("LISTEN_PID", pid, 1) == 0);
    assert(setenv("LISTEN_PIDFDID", "invalid", 1) == 0);
    assert(setenv("LISTEN_FDS", "1", 1) == 0);
    assert(rustd_listen_fds(1) == -EINVAL);
    assert(getenv("LISTEN_PID") == NULL);
    assert(getenv("LISTEN_PIDFDID") == NULL);
    assert(getenv("LISTEN_FDS") == NULL);

    assert(setenv("LISTEN_PID", pid, 1) == 0);
    assert(setenv("LISTEN_FDS", "invalid", 1) == 0);
    assert(rustd_listen_fds(1) == -EINVAL);
}

static void test_socket_and_peer_helpers(void) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(rustd_is_socket(sockets[0], AF_UNIX, SOCK_STREAM, 0) == 1);
    assert(rustd_is_socket(sockets[0], AF_INET, SOCK_STREAM, 0) == 0);
    assert(rustd_is_socket(sockets[0], AF_UNIX, SOCK_DGRAM, 0) == 0);
    assert(rustd_is_socket(sockets[0], AF_UNIX, SOCK_STREAM, 1) == 0);

    uid_t uid = (uid_t)-1;
    pid_t pid = (pid_t)-1;
    assert(rustd_peer_uid(sockets[0], &uid) == 0);
    assert(uid == getuid());
    assert(rustd_peer_pid(sockets[0], &pid) == 0);
    assert(pid == getpid());
    assert(rustd_peer_uid(-1, &uid) == -EBADF);
    assert(rustd_peer_pid(sockets[0], NULL) == -EINVAL);

    int pipe_fds[2];
    assert(pipe(pipe_fds) == 0);
    assert(rustd_is_socket(pipe_fds[0], 0, 0, -1) == 0);
    assert(rustd_is_socket(-1, 0, 0, -1) == -EBADF);
    assert(rustd_is_socket(sockets[0], -1, 0, -1) == -EINVAL);

    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(sockets[0]);
    close(sockets[1]);
}

static void test_journal_boot_identity(void) {
    char path[] = "/tmp/rustd-journal-XXXXXX";
    int seed_fd = mkstemp(path);
    assert(seed_fd >= 0);
    close(seed_fd);
    assert(unlink(path) == 0);

    static const char message[] = "journal parity entry";
    static const char unit[] = "journal-parity.service";
    static const char priority[] = "5";
    const SdJournalField fields[] = {
        {"MESSAGE", (const uint8_t *)message, sizeof(message) - 1},
        {"_SYSTEMD_UNIT", (const uint8_t *)unit, sizeof(unit) - 1},
        {"PRIORITY", (const uint8_t *)priority, sizeof(priority) - 1},
    };

    int fd = rustd_journal_file_open(path);
    assert(fd >= 0);
    assert(rustd_journal_file_append(fd, fields, 3, UINT64_C(123), UINT64_C(456)) == 0);

    uint8_t header_boot_id[16];
    uint8_t entry_boot_id[16];
    const uint8_t zero_id[16] = {0};
    assert(pread(fd, header_boot_id, sizeof(header_boot_id), 56) ==
           (ssize_t)sizeof(header_boot_id));

    uint64_t tail_entry_offset_le = 0;
    assert(pread(fd, &tail_entry_offset_le, sizeof(tail_entry_offset_le), 264) ==
           (ssize_t)sizeof(tail_entry_offset_le));
    uint64_t tail_entry_offset = le64toh(tail_entry_offset_le);
    assert(tail_entry_offset >= 272);
    assert(pread(fd, entry_boot_id, sizeof(entry_boot_id), (off_t)(tail_entry_offset + 40)) ==
           (ssize_t)sizeof(entry_boot_id));
    assert(memcmp(header_boot_id, zero_id, sizeof(header_boot_id)) != 0);
    assert(memcmp(entry_boot_id, header_boot_id, sizeof(entry_boot_id)) == 0);

    assert(rustd_journal_file_close(fd) == 0);

    fd = rustd_journal_file_open(path);
    assert(fd >= 0);
    assert(rustd_journal_file_append(fd, fields, 3, UINT64_C(124), UINT64_C(457)) == 0);
    assert(rustd_journal_file_close(fd) == 0);
    assert(unlink(path) == 0);
}

int main(void) {
    assert(rustd_install_signal_handlers() == 0);
    test_notify_messages();
    test_watchdog_environment();
    test_listen_fds();
    test_socket_and_peer_helpers();
    test_journal_boot_identity();

    puts("test_native: all assertions passed");
    return 0;
}
