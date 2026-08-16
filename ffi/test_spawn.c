/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * test_spawn.c — smoke tests for rustd_spawn().
 *
 * Upstream reference: src/core/execute.c exec_child() (v261)
 */

#include "capability.h"
#include "spawn.h"
#include "spawn_wire.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Linked with -Wl,--wrap=fork so the helper path can prove it never forks. */
extern pid_t __real_fork(void);
static int forbid_manager_fork;

pid_t __wrap_fork(void) {
    if (forbid_manager_fork) {
        fputs("unexpected fork() on the configured helper spawn path\n", stderr);
        abort();
    }
    return __real_fork();
}

static rustd_spawn_params spawn_params(const char * const *argv) {
    rustd_spawn_params p;
    memset(&p, 0, sizeof(p));
    p.path = argv ? argv[0] : NULL;
    p.argv = argv;
    p.uid = (uid_t)-1;
    p.gid = (gid_t)-1;
    p.stdin_fd = -1;
    p.stdout_fd = -1;
    p.stderr_fd = -1;
    p.notify_fd = -1;
    p.cap_bounding_set = UINT64_MAX;
    p.idle_read_fd = -1;
    p.idle_write_fd = -1;
    return p;
}

static void wait_pid(pid_t pid, int expected_exit) {
    int status;
    pid_t w = waitpid(pid, &status, 0);
    assert(w == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == expected_exit);
}

static void configure_self_as_helper(void) {
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    assert(length > 0);
    path[length] = '\0';
    assert(rustd_spawn_helper_configure(path) == 0);
    assert(rustd_spawn_helper_configured() != 0);
}

static void test_spawn_requires_helper(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    assert(rustd_spawn_helper_configured() == 0);
    assert(rustd_spawn(&p) == -ENOSYS);
    printf("test_spawn_requires_helper: ok\n");
}

static void test_spawn_cgroup_self_attach(void) {
    char path[] = "/tmp/rustd-cgroup-procs-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);

    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.cgroup_procs_path = path;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);

    fd = open(path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    char contents[8] = {0};
    ssize_t n = read(fd, contents, sizeof(contents) - 1);
    assert(n == 2);
    assert(memcmp(contents, "0\n", 2) == 0);
    close(fd);
    unlink(path);
    printf("test_spawn_cgroup_self_attach: ok\n");
}

static void test_mount_sandbox_namespace_requirements(void) {
    rustd_spawn_sandbox sandbox;
    memset(&sandbox, 0, sizeof(sandbox));
    assert(rustd_spawn_sandbox_needs_mount_namespace(&sandbox) == 0);

#define CHECK_MOUNT_FIELD(field, value) do { \
    memset(&sandbox, 0, sizeof(sandbox)); \
    sandbox.field = (value); \
    assert(rustd_spawn_sandbox_needs_mount_namespace(&sandbox) != 0); \
} while (0)

    CHECK_MOUNT_FIELD(private_tmp, 1);
    CHECK_MOUNT_FIELD(private_devices, 1);
    CHECK_MOUNT_FIELD(private_mounts, 1);
    CHECK_MOUNT_FIELD(protect_system, 1);
    CHECK_MOUNT_FIELD(protect_home, 1);
    CHECK_MOUNT_FIELD(protect_kernel_tunables, 1);
    CHECK_MOUNT_FIELD(protect_kernel_modules, 1);
    CHECK_MOUNT_FIELD(protect_kernel_logs, 1);
    CHECK_MOUNT_FIELD(protect_clock, 1);
    CHECK_MOUNT_FIELD(protect_control_groups, 1);
    CHECK_MOUNT_FIELD(restrict_suid_sgid, 1);
#undef CHECK_MOUNT_FIELD

    memset(&sandbox, 0, sizeof(sandbox));
    sandbox.private_network = 1;
    assert(rustd_spawn_sandbox_needs_mount_namespace(&sandbox) == 0);
    printf("test_mount_sandbox_namespace_requirements: ok\n");
}

static void test_spawn_separate_argv0(void) {
    const char *argv[] = { "custom-argv0", "-c", "test \"$0\" = custom-argv0", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.path = "/bin/sh";

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_separate_argv0: ok\n");
}

static void test_spawn_search_path(void) {
    const char *argv[] = {"true", NULL};
    rustd_spawn_params p = spawn_params(argv);
    p.path = "true";
    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    puts("test_spawn_search_path: ok");
}

static void test_spawn_rlimit_nofile(void) {
    const char *argv[] = { "/bin/sh", "-c", "test \"$(ulimit -n)\" -eq 32", NULL };
    rustd_spawn_rlimit limit = { .resource = RLIMIT_NOFILE, .soft = 32, .hard = 32 };
    rustd_spawn_params p = spawn_params(argv);
    p.rlimits = &limit;
    p.n_rlimits = 1;
    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_rlimit_nofile: ok\n");
}

static void test_spawn_true(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_true: ok\n");
}

static void test_spawn_false(void) {
    const char *argv[] = { "/bin/false", NULL };
    rustd_spawn_params p = spawn_params(argv);

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 1);
    printf("test_spawn_false: ok\n");
}

static void test_spawn_nonexistent(void) {
    const char *argv[] = { "/nonexistent_binary_xyz", NULL };
    rustd_spawn_params p = spawn_params(argv);

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 127);
    printf("test_spawn_nonexistent: ok\n");
}

static void test_spawn_exec_handshake_success(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.wait_for_exec = 1;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_exec_handshake_success: ok\n");
}

static void test_spawn_exec_handshake_failure(void) {
    const char *argv[] = { "/nonexistent_binary_xyz", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.wait_for_exec = 1;

    pid_t pid = rustd_spawn(&p);
    assert(pid == -ENOENT);
    printf("test_spawn_exec_handshake_failure: ok\n");
}

static void test_spawn_memory_deny_write_execute(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_sandbox sandbox = { .memory_deny_write_execute = 1 };
    rustd_spawn_params p = spawn_params(argv);
    p.sandbox = &sandbox;
    p.wait_for_exec = 1;
    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_memory_deny_write_execute: ok\n");
}

static void test_spawn_restrict_namespaces(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_sandbox sandbox = { .restrict_namespaces = 1 };
    rustd_spawn_params p = spawn_params(argv);
    p.sandbox = &sandbox;
    p.wait_for_exec = 1;
    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_restrict_namespaces: ok\n");
}

static void test_protect_kernel_logs_filter(void) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        if (rustd_sandbox_no_new_privs() < 0)
            _exit(89);
        if (rustd_seccomp_protect_kernel_logs() < 0)
            _exit(90);
#ifdef SYS_syslog
        errno = 0;
        long r = syscall(SYS_syslog, 3, NULL, 0);
        _exit(r == -1 && errno == EPERM ? 0 : 91);
#else
        _exit(0);
#endif
    }
    wait_pid(pid, 0);
    printf("test_protect_kernel_logs_filter: ok\n");
}

static void test_protect_clock_filter(void) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        if (rustd_sandbox_no_new_privs() < 0)
            _exit(92);
        if (rustd_seccomp_protect_clock() < 0)
            _exit(93);
#ifdef SYS_clock_settime
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
        errno = 0;
        long r = syscall(SYS_clock_settime, -1, &ts);
        _exit(r == -1 && errno == EPERM ? 0 : 94);
#else
        _exit(0);
#endif
    }
    wait_pid(pid, 0);
    printf("test_protect_clock_filter: ok\n");
}

static void test_spawn_idle_gate(void) {
    int gate[2];
    assert(pipe2(gate, O_CLOEXEC) == 0);
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.idle_read_fd = gate[0];
    p.idle_write_fd = gate[1];

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    close(gate[0]);

    usleep(100000);
    int status = 0;
    assert(waitpid(pid, &status, WNOHANG) == 0);

    close(gate[1]);
    wait_pid(pid, 0);
    printf("test_spawn_idle_gate: ok\n");
}

static void test_spawn_cwd(void) {
    const char *argv[] = { "/bin/sh", "-c", "test -d \"$PWD\"", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.cwd = "/tmp";

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_cwd: ok\n");
}

static void test_spawn_env(void) {
    const char *env[] = { "MY_VAR=hello", NULL };
    const char *argv[] = { "/bin/sh", "-c", "test \"$MY_VAR\" = hello", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.envp = env;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 0);
    printf("test_spawn_env: ok\n");
}

static void test_spawn_notify_environment(void) {
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    assert(setenv("RUSTD_NOTIFY_SOCKET", "@rustd/test-notify", 1) == 0);

    char command[512];
    snprintf(
        command,
        sizeof(command),
        "test \"$MY_VAR\" = hello "
        "&& test \"$NOTIFY_SOCKET\" = '@rustd/test-notify' "
        "&& test \"$WATCHDOG_USEC\" = 500000 "
        "&& test \"$WATCHDOG_PID\" = \"$$\" "
        "&& test ! -e /proc/$$/fd/%d",
        pipefd[0]);

    const char *env[] = { "MY_VAR=hello", NULL };
    const char *argv[] = { "/bin/sh", "-c", command, NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.envp = env;
    p.notify_fd = pipefd[0];
    p.watchdog_usec = 500000;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    close(pipefd[0]);
    close(pipefd[1]);
    wait_pid(pid, 0);
    unsetenv("RUSTD_NOTIFY_SOCKET");
    printf("test_spawn_notify_environment: ok\n");
}

static void test_spawn_listen_fds(void) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);

    const char *argv[] = {
        "/bin/sh",
        "-c",
        "test \"$LISTEN_FDS\" = 1 "
        "&& test \"$LISTEN_PID\" = \"$$\" "
        "&& test -e /proc/$$/fd/3 "
        "&& test ! -e /proc/$$/fd/4",
        NULL,
    };
    rustd_spawn_params p = spawn_params(argv);
    p.listen_fds = &sockets[0];
    p.n_listen_fds = 1;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    close(sockets[0]);
    close(sockets[1]);
    wait_pid(pid, 0);
    printf("test_spawn_listen_fds: ok\n");
}

static void test_spawn_rejects_oversized_listen_count(void) {
    int dummy = 0;
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.listen_fds = &dummy;
    p.n_listen_fds = RUSTD_SPAWN_MAX_LISTEN_FDS + 1;
    assert(rustd_spawn(&p) == -E2BIG);
    printf("test_spawn_rejects_oversized_listen_count: ok\n");
}

static void test_spawn_rejects_invalid_listen_vectors(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.n_listen_fds = -1;
    assert(rustd_spawn(&p) == -EINVAL);

    p.n_listen_fds = 1;
    p.listen_fds = NULL;
    assert(rustd_spawn(&p) == -EINVAL);
    printf("test_spawn_rejects_invalid_listen_vectors: ok\n");
}

static void test_spawn_rejects_malformed_environment(void) {
    const char *env[] = { "NOEQUALS", NULL };
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.envp = env;
    assert(rustd_spawn(&p) == -EINVAL);
    printf("test_spawn_rejects_malformed_environment: ok\n");
}

static void test_capability_names(void) {
    assert(rustd_capability_name_to_num("CAP_NET_ADMIN") == 12);
    assert(rustd_capability_name_to_num("cap_checkpoint_restore") == 40);
    assert(rustd_capability_name_to_num("not_a_capability") == -1);
    printf("test_capability_names: ok\n");
}

static void test_spawn_rejects_unsupported_bounding_bit(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.cap_bounding_set = UINT64_C(1) << 63;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 125);
    printf("test_spawn_rejects_unsupported_bounding_bit: ok\n");
}

static void test_spawn_rejects_unsupported_ambient_bit(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.ambient_caps = UINT64_C(1) << 63;

    pid_t pid = rustd_spawn(&p);
    assert(pid > 0);
    wait_pid(pid, 125);
    printf("test_spawn_rejects_unsupported_ambient_bit: ok\n");
}

static void test_spawn_null_params(void) {
    pid_t pid = rustd_spawn(NULL);
    assert(pid == -EINVAL);
    printf("test_spawn_null_params: ok\n");
}

/*
 * Prove the configured helper path never calls fork() in the manager.  The
 * test binary wraps fork(2); any call from rustd_spawn() aborts.
 */
static void test_spawn_helper_path_uses_no_manager_fork(void) {
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.wait_for_exec = 1;

    forbid_manager_fork = 1;
    pid_t pid = rustd_spawn(&p);
    forbid_manager_fork = 0;

    assert(pid > 0);
    assert(getpgid(pid) >= 0);
    wait_pid(pid, 0);
    printf("test_spawn_helper_path_uses_no_manager_fork: ok\n");
}

typedef struct {
    pid_t pid;
    int ok;
} concurrent_result;

static void *concurrent_spawn(void *arg) {
    concurrent_result *result = arg;
    const char *argv[] = { "/bin/true", NULL };
    rustd_spawn_params p = spawn_params(argv);
    p.wait_for_exec = 1;
    result->pid = rustd_spawn(&p);
    result->ok = result->pid > 0;
    return NULL;
}

static void test_spawn_concurrent_helper_path(void) {
    enum { N = 8 };
    pthread_t threads[N];
    concurrent_result results[N];
    memset(results, 0, sizeof(results));

    for (int i = 0; i < N; i++)
        assert(pthread_create(&threads[i], NULL, concurrent_spawn, &results[i]) == 0);
    for (int i = 0; i < N; i++)
        assert(pthread_join(threads[i], NULL) == 0);

    for (int i = 0; i < N; i++) {
        assert(results[i].ok);
        wait_pid(results[i].pid, 0);
        for (int j = 0; j < i; j++)
            assert(results[i].pid != results[j].pid);
    }
    printf("test_spawn_concurrent_helper_path: ok\n");
}

/*
 * Production gate: 10,000 helper spawns under concurrent control-plane load.
 * Waves of workers prove the manager never hangs, leaks zombies, or returns
 * duplicate PIDs after the post-thread fork() path was removed.
 */
static void test_spawn_helper_stress_10000(void) {
    enum { TOTAL = 10000, WAVE = 64 };
    forbid_manager_fork = 1;
    for (int completed = 0; completed < TOTAL; ) {
        int batch = TOTAL - completed;
        if (batch > WAVE)
            batch = WAVE;
        pthread_t threads[WAVE];
        concurrent_result results[WAVE];
        memset(results, 0, sizeof(results));
        for (int i = 0; i < batch; i++)
            assert(pthread_create(&threads[i], NULL, concurrent_spawn, &results[i]) == 0);
        for (int i = 0; i < batch; i++)
            assert(pthread_join(threads[i], NULL) == 0);
        for (int i = 0; i < batch; i++) {
            assert(results[i].ok);
            wait_pid(results[i].pid, 0);
            for (int j = 0; j < i; j++)
                assert(results[i].pid != results[j].pid);
        }
        completed += batch;
    }
    forbid_manager_fork = 0;
    printf("test_spawn_helper_stress_10000: ok\n");
}

int main(void) {
    test_spawn_requires_helper();
    configure_self_as_helper();

    test_spawn_cgroup_self_attach();
    test_mount_sandbox_namespace_requirements();
    test_spawn_separate_argv0();
    test_spawn_search_path();
    test_spawn_rlimit_nofile();
    test_spawn_true();
    test_spawn_false();
    test_spawn_nonexistent();
    test_spawn_exec_handshake_success();
    test_spawn_exec_handshake_failure();
    test_spawn_memory_deny_write_execute();
    test_spawn_restrict_namespaces();
    test_protect_kernel_logs_filter();
    test_protect_clock_filter();
    test_spawn_idle_gate();
    test_spawn_cwd();
    test_spawn_env();
    test_spawn_notify_environment();
    test_spawn_listen_fds();
    test_spawn_rejects_oversized_listen_count();
    test_spawn_rejects_invalid_listen_vectors();
    test_spawn_rejects_malformed_environment();
    test_capability_names();
    test_spawn_rejects_unsupported_bounding_bit();
    test_spawn_rejects_unsupported_ambient_bit();
    test_spawn_null_params();
    test_spawn_helper_path_uses_no_manager_fork();
    test_spawn_concurrent_helper_path();
    test_spawn_helper_stress_10000();
    printf("test_spawn: all assertions passed\n");
    return 0;
}
