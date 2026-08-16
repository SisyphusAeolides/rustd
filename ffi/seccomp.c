/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * seccomp.c — hand-coded BPF seccomp filters.
 *
 * Upstream reference: src/shared/seccomp-util.c (v261)
 *
 * All filters are installed with SECCOMP_SET_MODE_FILTER via prctl(2).
 * Each function builds a sock_filter[] program and calls prctl directly
 * to avoid requiring libseccomp at build time.
 */

#include "seccomp.h"

#include <dlfcn.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ── BPF instruction helpers ─────────────────────────────────────────────── */

/* BPF_STMT and BPF_JUMP are already defined in <linux/filter.h>. */

/* Load arch, syscall number, or argument from seccomp_data. */
#define LOAD_ARCH \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
             (uint32_t)__builtin_offsetof(struct seccomp_data, arch))
#define LOAD_SYSCALL \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
             (uint32_t)__builtin_offsetof(struct seccomp_data, nr))
#define LOAD_ARG(n) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
             (uint32_t)(__builtin_offsetof(struct seccomp_data, args) + (n) * 8))

/* Architecture guard: if not x86_64 or aarch64, allow unconditionally. */
#define ARCH_GUARD_X86_64  AUDIT_ARCH_X86_64
#define ARCH_GUARD_AARCH64 AUDIT_ARCH_AARCH64

/* Common actions */
#define ALLOW  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define KILL   BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
#define EPERM_RET(err) \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((err) & SECCOMP_RET_DATA))

/* Install a filter; return 0 or -errno. */
static int install_filter(struct sock_filter *insns, unsigned int n) {
    struct sock_fprog prog = { .len = (unsigned short)n, .filter = insns };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -errno;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
        return -errno;
    return 0;
}

/* ── rustd_seccomp_memory_deny_write_execute ─────────────────────────────────── */

int rustd_seccomp_memory_deny_write_execute(void) {
    /*
     * Block mmap(2) when (arg2 & (PROT_WRITE|PROT_EXEC)) == (PROT_WRITE|PROT_EXEC)
     * Block mprotect(2) when (arg0 & PROT_EXEC) != 0
     *
     * seccomp_data.args[] holds 64-bit values; we use low-word only (BPF_W).
     * On x86-64 the low 32 bits contain the prot argument.
     *
     * Program layout:
     *  [0]  load arch
     *  [1]  if arch == x86_64, skip to [3]
     *  [2]  if arch == aarch64, skip to [3]; else ALLOW
     *  [3]  load syscall nr
     *  [4]  if nr == __NR_mmap, skip to [6]; else continue
     *  [5]  if nr == __NR_mprotect, skip to [12]; else ALLOW
     *  [6]  load arg2 (prot) for mmap
     *  [7]  mask with PROT_WRITE|PROT_EXEC (0x6)
     *  [8]  if masked == 0x6, skip to [10]; else ALLOW
     *  [9]  ALLOW
     * [10]  EPERM
     * [11]  ALLOW (for mprotect path)
     * [12]  load arg0 (prot) for mprotect (new_prot is arg2 on x86-64)
     * [13]  AND with PROT_EXEC (0x4)
     * [14]  if != 0, EPERM; else ALLOW
     * [15]  ALLOW
     */
    struct sock_filter prog[] = {
        /* [0] arch guard */
        LOAD_ARCH,
        /* [1] x86_64 ok → jump to syscall check */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_X86_64,  1, 0),
        /* [2] aarch64 ok → jump to syscall check; else ALLOW */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_AARCH64, 0, 13),
        /* [3] load syscall nr */
        LOAD_SYSCALL,
        /* [4] mmap? */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap,      2, 0),
        /* [5] mprotect? else ALLOW */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect,  7, 0),
        /* [6] not mmap or mprotect → ALLOW */
        ALLOW,
        /* mmap path: arg2 = prot */
        /* [7] */ LOAD_ARG(2),
        /* [8] mask: keep only PROT_WRITE(2)|PROT_EXEC(4) = 0x6 */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x6),
        /* [9] if both bits set → EPERM */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x6, 1, 0),
        /* [10] */ ALLOW,
        /* [11] */ EPERM_RET(EPERM),
        /* [12] */ ALLOW,   /* placeholder — never reached from mmap path */
        /* mprotect path: arg2 = new_prot (mprotect: addr, len, prot → args[0..2]) */
        /* [13] */ LOAD_ARG(2),
        /* [14] */ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x4), /* PROT_EXEC */
        /* [15] if PROT_EXEC set → EPERM */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        /* [16] */ ALLOW,
        /* [17] */ EPERM_RET(EPERM),
        /* [18] */ ALLOW,  /* unreachable — arch ALLOW */
    };

    return install_filter(prog, sizeof(prog) / sizeof(prog[0]));
}

/* ── rustd_seccomp_restrict_namespaces ─────────────────────────────────────── */

/*
 * CLONE_NEW* bits that correspond to namespace types.
 * Upstream src/shared/namespace-util.h (v261).
 */
#define CLONE_NEWNS_BIT    0x00020000UL
#define CLONE_NEWUTS_BIT   0x04000000UL
#define CLONE_NEWIPC_BIT   0x08000000UL
#define CLONE_NEWUSER_BIT  0x10000000UL
#define CLONE_NEWPID_BIT   0x20000000UL
#define CLONE_NEWNET_BIT   0x40000000UL
#define CLONE_NEWCGROUP_BIT 0x02000000UL

#define ALL_CLONE_NEW_MASK ( \
    CLONE_NEWNS_BIT | CLONE_NEWUTS_BIT | CLONE_NEWIPC_BIT | \
    CLONE_NEWUSER_BIT | CLONE_NEWPID_BIT | CLONE_NEWNET_BIT | \
    CLONE_NEWCGROUP_BIT)

int rustd_seccomp_restrict_namespaces(uint64_t allowed_mask) {
    uint32_t blocked = (uint32_t)(ALL_CLONE_NEW_MASK & ~allowed_mask);

    if (blocked == 0)
        return 0;

#ifndef __NR_clone3
#define __NR_clone3 0xffffffffU
#endif

    /*
     * Upstream cannot inspect clone3() flags through classic seccomp BPF, so
     * it returns ENOSYS and lets libc fall back to clone(). setns(fd, 0) is
     * rejected whenever namespace restrictions are active because the target
     * namespace type cannot be inferred from the flags argument.
     */
    struct sock_filter prog[] = {
        /* [0] */ LOAD_ARCH,
        /* [1] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_X86_64, 1, 0),
        /* [2] */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_AARCH64, 0, 18),
        /* [3] */ LOAD_SYSCALL,
        /* [4] clone3 -> ENOSYS */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        /* [5] */ EPERM_RET(ENOSYS),
        /* [6] unshare -> arg0 namespace flags */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 2, 0),
        /* [7] clone -> arg0 namespace flags */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 1, 0),
        /* [8] setns -> arg1 namespace type */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 6, 0),
        /* [9] unrelated syscall */ ALLOW,
        /* [10] clone/unshare flags */ LOAD_ARG(0),
        /* [11] */ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, blocked),
        /* [12] zero blocked flags -> allow */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        /* [13] */ ALLOW,
        /* [14] */ EPERM_RET(EPERM),
        /* [15] setns flags */ LOAD_ARG(1),
        /* [16] flags == 0 -> EPERM */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0),
        /* [17] */ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, blocked),
        /* [18] zero blocked flags -> allow */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        /* [19] */ ALLOW,
        /* [20] */ EPERM_RET(EPERM),
        /* [21] unsupported architecture */ ALLOW,
    };

    return install_filter(prog, sizeof(prog) / sizeof(prog[0]));
}

int rustd_seccomp_protect_kernel_logs(void) {
    static const char *const deny[] = {
        "syslog",
        NULL,
    };
    return rustd_seccomp_syscall_filter(NULL, deny, EPERM);
}

int rustd_seccomp_protect_clock(void) {
    static const char *const deny[] = {
        "adjtimex",
        "clock_adjtime",
        "clock_settime",
        "settimeofday",
        NULL,
    };
    return rustd_seccomp_syscall_filter(NULL, deny, EPERM);
}

/* ── Native libseccomp syscall resolution ────────────────────────────────── */

typedef int (*seccomp_resolve_name_fn)(const char *name);
typedef char *(*seccomp_resolve_num_arch_fn)(uint32_t arch, int num);

static void *libseccomp_handle;
static seccomp_resolve_name_fn libseccomp_resolve_name;
static seccomp_resolve_num_arch_fn libseccomp_resolve_num_arch;

static int load_libseccomp_resolvers(void) {
    if (libseccomp_resolve_name && libseccomp_resolve_num_arch)
        return 0;

    if (!libseccomp_handle) {
        libseccomp_handle = dlopen("libseccomp.so.2", RTLD_LAZY | RTLD_LOCAL);
        if (!libseccomp_handle)
            return -EOPNOTSUPP;
    }

    void *name_symbol = dlsym(libseccomp_handle, "seccomp_syscall_resolve_name");
    void *num_symbol = dlsym(libseccomp_handle, "seccomp_syscall_resolve_num_arch");
    if (!name_symbol || !num_symbol)
        return -EOPNOTSUPP;

    memcpy(&libseccomp_resolve_name, &name_symbol, sizeof(name_symbol));
    memcpy(&libseccomp_resolve_num_arch, &num_symbol, sizeof(num_symbol));
    return 0;
}

int rustd_seccomp_syscall_resolve_name(const char *name, int *ret_nr) {
    if (!name || !ret_nr)
        return -EINVAL;

    int r = load_libseccomp_resolvers();
    if (r < 0)
        return r;

    int nr = libseccomp_resolve_name(name);
    if (nr == -1)
        return -ENOENT;

    *ret_nr = nr;
    return 0;
}

int rustd_seccomp_syscall_is_known(int nr) {
    int r = load_libseccomp_resolvers();
    if (r < 0)
        return r;

    /* SCMP_ARCH_NATIVE is defined as zero by libseccomp's public ABI. */
    char *name = libseccomp_resolve_num_arch(0U, nr);
    if (!name)
        return 0;
    free(name);
    return 1;
}

/* ── Syscall name → number table ─────────────────────────────────────────── */

typedef struct {
    const char *name;
    int         nr;
} syscall_entry;

/* Table of the most common Linux x86-64 syscall names. */
static const syscall_entry syscall_table[] = {
    { "read",               __NR_read },
    { "write",              __NR_write },
    { "open",               __NR_open },
    { "close",              __NR_close },
    { "stat",               __NR_stat },
    { "fstat",              __NR_fstat },
    { "lstat",              __NR_lstat },
    { "poll",               __NR_poll },
    { "lseek",              __NR_lseek },
    { "mmap",               __NR_mmap },
    { "mprotect",           __NR_mprotect },
    { "munmap",             __NR_munmap },
    { "brk",                __NR_brk },
    { "rt_sigaction",       __NR_rt_sigaction },
    { "rt_sigprocmask",     __NR_rt_sigprocmask },
    { "rt_sigreturn",       __NR_rt_sigreturn },
    { "ioctl",              __NR_ioctl },
    { "pread64",            __NR_pread64 },
    { "pwrite64",           __NR_pwrite64 },
    { "readv",              __NR_readv },
    { "writev",             __NR_writev },
    { "access",             __NR_access },
    { "pipe",               __NR_pipe },
    { "select",             __NR_select },
    { "sched_yield",        __NR_sched_yield },
    { "mremap",             __NR_mremap },
    { "msync",              __NR_msync },
    { "mincore",            __NR_mincore },
    { "madvise",            __NR_madvise },
    { "shmget",             __NR_shmget },
    { "shmat",              __NR_shmat },
    { "shmctl",             __NR_shmctl },
    { "dup",                __NR_dup },
    { "dup2",               __NR_dup2 },
    { "pause",              __NR_pause },
    { "nanosleep",          __NR_nanosleep },
    { "getitimer",          __NR_getitimer },
    { "alarm",              __NR_alarm },
    { "setitimer",          __NR_setitimer },
    { "getpid",             __NR_getpid },
    { "sendfile",           __NR_sendfile },
    { "socket",             __NR_socket },
    { "connect",            __NR_connect },
    { "accept",             __NR_accept },
    { "sendto",             __NR_sendto },
    { "recvfrom",           __NR_recvfrom },
    { "sendmsg",            __NR_sendmsg },
    { "recvmsg",            __NR_recvmsg },
    { "shutdown",           __NR_shutdown },
    { "bind",               __NR_bind },
    { "listen",             __NR_listen },
    { "getsockname",        __NR_getsockname },
    { "getpeername",        __NR_getpeername },
    { "socketpair",         __NR_socketpair },
    { "setsockopt",         __NR_setsockopt },
    { "getsockopt",         __NR_getsockopt },
    { "clone",              __NR_clone },
    { "fork",               __NR_fork },
    { "vfork",              __NR_vfork },
    { "execve",             __NR_execve },
    { "exit",               __NR_exit },
    { "wait4",              __NR_wait4 },
    { "kill",               __NR_kill },
    { "uname",              __NR_uname },
    { "semget",             __NR_semget },
    { "semop",              __NR_semop },
    { "semctl",             __NR_semctl },
    { "shmdt",              __NR_shmdt },
    { "msgget",             __NR_msgget },
    { "msgsnd",             __NR_msgsnd },
    { "msgrcv",             __NR_msgrcv },
    { "msgctl",             __NR_msgctl },
    { "fcntl",              __NR_fcntl },
    { "flock",              __NR_flock },
    { "fsync",              __NR_fsync },
    { "fdatasync",          __NR_fdatasync },
    { "truncate",           __NR_truncate },
    { "ftruncate",          __NR_ftruncate },
    { "getdents",           __NR_getdents },
    { "getcwd",             __NR_getcwd },
    { "chdir",              __NR_chdir },
    { "fchdir",             __NR_fchdir },
    { "rename",             __NR_rename },
    { "mkdir",              __NR_mkdir },
    { "rmdir",              __NR_rmdir },
    { "creat",              __NR_creat },
    { "link",               __NR_link },
    { "unlink",             __NR_unlink },
    { "symlink",            __NR_symlink },
    { "readlink",           __NR_readlink },
    { "chmod",              __NR_chmod },
    { "fchmod",             __NR_fchmod },
    { "chown",              __NR_chown },
    { "fchown",             __NR_fchown },
    { "lchown",             __NR_lchown },
    { "umask",              __NR_umask },
    { "gettimeofday",       __NR_gettimeofday },
    { "getrlimit",          __NR_getrlimit },
    { "getrusage",          __NR_getrusage },
    { "sysinfo",            __NR_sysinfo },
    { "times",              __NR_times },
    { "ptrace",             __NR_ptrace },
    { "getuid",             __NR_getuid },
    { "syslog",             __NR_syslog },
    { "getgid",             __NR_getgid },
    { "setuid",             __NR_setuid },
    { "setgid",             __NR_setgid },
    { "geteuid",            __NR_geteuid },
    { "getegid",            __NR_getegid },
    { "setpgid",            __NR_setpgid },
    { "getppid",            __NR_getppid },
    { "getpgrp",            __NR_getpgrp },
    { "setsid",             __NR_setsid },
    { "setreuid",           __NR_setreuid },
    { "setregid",           __NR_setregid },
    { "getgroups",          __NR_getgroups },
    { "setgroups",          __NR_setgroups },
    { "setresuid",          __NR_setresuid },
    { "getresuid",          __NR_getresuid },
    { "setresgid",          __NR_setresgid },
    { "getresgid",          __NR_getresgid },
    { "getpgid",            __NR_getpgid },
    { "setfsuid",           __NR_setfsuid },
    { "setfsgid",           __NR_setfsgid },
    { "getsid",             __NR_getsid },
    { "capget",             __NR_capget },
    { "capset",             __NR_capset },
    { "rt_sigpending",      __NR_rt_sigpending },
    { "rt_sigtimedwait",    __NR_rt_sigtimedwait },
    { "rt_sigqueueinfo",    __NR_rt_sigqueueinfo },
    { "rt_sigsuspend",      __NR_rt_sigsuspend },
    { "sigaltstack",        __NR_sigaltstack },
    { "utime",              __NR_utime },
    { "mknod",              __NR_mknod },
    { "personality",        __NR_personality },
    { "statfs",             __NR_statfs },
    { "fstatfs",            __NR_fstatfs },
    { "getpriority",        __NR_getpriority },
    { "setpriority",        __NR_setpriority },
    { "sched_setparam",     __NR_sched_setparam },
    { "sched_getparam",     __NR_sched_getparam },
    { "sched_setscheduler", __NR_sched_setscheduler },
    { "sched_getscheduler", __NR_sched_getscheduler },
    { "sched_get_priority_max", __NR_sched_get_priority_max },
    { "sched_get_priority_min", __NR_sched_get_priority_min },
    { "sched_rr_get_interval",  __NR_sched_rr_get_interval },
    { "mlock",              __NR_mlock },
    { "munlock",            __NR_munlock },
    { "mlockall",           __NR_mlockall },
    { "munlockall",         __NR_munlockall },
    { "vhangup",            __NR_vhangup },
    { "pivot_root",         __NR_pivot_root },
    { "prctl",              __NR_prctl },
    { "arch_prctl",         __NR_arch_prctl },
    { "adjtimex",           __NR_adjtimex },
    { "setrlimit",          __NR_setrlimit },
    { "chroot",             __NR_chroot },
    { "sync",               __NR_sync },
    { "acct",               __NR_acct },
    { "settimeofday",       __NR_settimeofday },
    { "mount",              __NR_mount },
    { "umount2",            __NR_umount2 },
    { "swapon",             __NR_swapon },
    { "swapoff",            __NR_swapoff },
    { "reboot",             __NR_reboot },
    { "sethostname",        __NR_sethostname },
    { "setdomainname",      __NR_setdomainname },
    { "init_module",        __NR_init_module },
    { "delete_module",      __NR_delete_module },
    { "quotactl",           __NR_quotactl },
    { "gettid",             __NR_gettid },
    { "readahead",          __NR_readahead },
    { "setxattr",           __NR_setxattr },
    { "lsetxattr",          __NR_lsetxattr },
    { "fsetxattr",          __NR_fsetxattr },
    { "getxattr",           __NR_getxattr },
    { "lgetxattr",          __NR_lgetxattr },
    { "fgetxattr",          __NR_fgetxattr },
    { "listxattr",          __NR_listxattr },
    { "llistxattr",         __NR_llistxattr },
    { "flistxattr",         __NR_flistxattr },
    { "removexattr",        __NR_removexattr },
    { "lremovexattr",       __NR_lremovexattr },
    { "fremovexattr",       __NR_fremovexattr },
    { "tkill",              __NR_tkill },
    { "time",               __NR_time },
    { "futex",              __NR_futex },
    { "sched_setaffinity",  __NR_sched_setaffinity },
    { "sched_getaffinity",  __NR_sched_getaffinity },
    { "io_setup",           __NR_io_setup },
    { "io_destroy",         __NR_io_destroy },
    { "io_getevents",       __NR_io_getevents },
    { "io_submit",          __NR_io_submit },
    { "io_cancel",          __NR_io_cancel },
    { "epoll_create",       __NR_epoll_create },
    { "getdents64",         __NR_getdents64 },
    { "set_tid_address",    __NR_set_tid_address },
    { "restart_syscall",    __NR_restart_syscall },
    { "semtimedop",         __NR_semtimedop },
    { "fadvise64",          __NR_fadvise64 },
    { "timer_create",       __NR_timer_create },
    { "timer_settime",      __NR_timer_settime },
    { "timer_gettime",      __NR_timer_gettime },
    { "timer_getoverrun",   __NR_timer_getoverrun },
    { "timer_delete",       __NR_timer_delete },
    { "clock_settime",      __NR_clock_settime },
    { "clock_gettime",      __NR_clock_gettime },
    { "clock_getres",       __NR_clock_getres },
    { "clock_nanosleep",    __NR_clock_nanosleep },
    { "exit_group",         __NR_exit_group },
    { "epoll_wait",         __NR_epoll_wait },
    { "epoll_ctl",          __NR_epoll_ctl },
    { "tgkill",             __NR_tgkill },
    { "utimes",             __NR_utimes },
    { "mq_open",            __NR_mq_open },
    { "mq_unlink",          __NR_mq_unlink },
    { "mq_timedsend",       __NR_mq_timedsend },
    { "mq_timedreceive",    __NR_mq_timedreceive },
    { "mq_notify",          __NR_mq_notify },
    { "mq_getsetattr",      __NR_mq_getsetattr },
    { "kexec_load",         __NR_kexec_load },
    { "waitid",             __NR_waitid },
    { "add_key",            __NR_add_key },
    { "request_key",        __NR_request_key },
    { "keyctl",             __NR_keyctl },
    { "ioprio_set",         __NR_ioprio_set },
    { "ioprio_get",         __NR_ioprio_get },
    { "inotify_init",       __NR_inotify_init },
    { "inotify_add_watch",  __NR_inotify_add_watch },
    { "inotify_rm_watch",   __NR_inotify_rm_watch },
    { "openat",             __NR_openat },
    { "mkdirat",            __NR_mkdirat },
    { "mknodat",            __NR_mknodat },
    { "fchownat",           __NR_fchownat },
    { "futimesat",          __NR_futimesat },
    { "newfstatat",         __NR_newfstatat },
    { "unlinkat",           __NR_unlinkat },
    { "renameat",           __NR_renameat },
    { "linkat",             __NR_linkat },
    { "symlinkat",          __NR_symlinkat },
    { "readlinkat",         __NR_readlinkat },
    { "fchmodat",           __NR_fchmodat },
    { "faccessat",          __NR_faccessat },
    { "pselect6",           __NR_pselect6 },
    { "ppoll",              __NR_ppoll },
    { "unshare",            __NR_unshare },
    { "set_robust_list",    __NR_set_robust_list },
    { "get_robust_list",    __NR_get_robust_list },
    { "splice",             __NR_splice },
    { "tee",                __NR_tee },
    { "sync_file_range",    __NR_sync_file_range },
    { "vmsplice",           __NR_vmsplice },
    { "move_pages",         __NR_move_pages },
    { "utimensat",          __NR_utimensat },
    { "epoll_pwait",        __NR_epoll_pwait },
    { "signalfd",           __NR_signalfd },
    { "timerfd_create",     __NR_timerfd_create },
    { "eventfd",            __NR_eventfd },
    { "fallocate",          __NR_fallocate },
    { "timerfd_settime",    __NR_timerfd_settime },
    { "timerfd_gettime",    __NR_timerfd_gettime },
    { "accept4",            __NR_accept4 },
    { "signalfd4",          __NR_signalfd4 },
    { "eventfd2",           __NR_eventfd2 },
    { "epoll_create1",      __NR_epoll_create1 },
    { "dup3",               __NR_dup3 },
    { "pipe2",              __NR_pipe2 },
    { "inotify_init1",      __NR_inotify_init1 },
    { "preadv",             __NR_preadv },
    { "pwritev",            __NR_pwritev },
    { "rt_tgsigqueueinfo",  __NR_rt_tgsigqueueinfo },
    { "perf_event_open",    __NR_perf_event_open },
    { "recvmmsg",           __NR_recvmmsg },
    { "fanotify_init",      __NR_fanotify_init },
    { "fanotify_mark",      __NR_fanotify_mark },
    { "prlimit64",          __NR_prlimit64 },
    { "name_to_handle_at",  __NR_name_to_handle_at },
    { "open_by_handle_at",  __NR_open_by_handle_at },
    { "clock_adjtime",      __NR_clock_adjtime },
    { "syncfs",             __NR_syncfs },
    { "sendmmsg",           __NR_sendmmsg },
    { "setns",              __NR_setns },
    { "getcpu",             __NR_getcpu },
    { "process_vm_readv",   __NR_process_vm_readv },
    { "process_vm_writev",  __NR_process_vm_writev },
    { "kcmp",               __NR_kcmp },
    { "finit_module",       __NR_finit_module },
    { "sched_setattr",      __NR_sched_setattr },
    { "sched_getattr",      __NR_sched_getattr },
    { "renameat2",          __NR_renameat2 },
    { "seccomp",            __NR_seccomp },
    { "getrandom",          __NR_getrandom },
    { "memfd_create",       __NR_memfd_create },
    { "kexec_file_load",    __NR_kexec_file_load },
    { "bpf",                __NR_bpf },
    { "execveat",           __NR_execveat },
    { "userfaultfd",        __NR_userfaultfd },
    { "membarrier",         __NR_membarrier },
    { "mlock2",             __NR_mlock2 },
    { "copy_file_range",    __NR_copy_file_range },
    { "preadv2",            __NR_preadv2 },
    { "pwritev2",           __NR_pwritev2 },
    { "pkey_mprotect",      __NR_pkey_mprotect },
    { "pkey_alloc",         __NR_pkey_alloc },
    { "pkey_free",          __NR_pkey_free },
    { "statx",              __NR_statx },
    { "io_pgetevents",      __NR_io_pgetevents },
    { "rseq",               __NR_rseq },
    { "pidfd_send_signal",  __NR_pidfd_send_signal },
    { "io_uring_setup",     __NR_io_uring_setup },
    { "io_uring_enter",     __NR_io_uring_enter },
    { "io_uring_register",  __NR_io_uring_register },
    { "open_tree",          __NR_open_tree },
    { "move_mount",         __NR_move_mount },
    { "fsopen",             __NR_fsopen },
    { "fsconfig",           __NR_fsconfig },
    { "fsmount",            __NR_fsmount },
    { "fspick",             __NR_fspick },
    { "pidfd_open",         __NR_pidfd_open },
#ifdef __NR_clone3
    { "clone3",             __NR_clone3 },
#endif
    { "close_range",        __NR_close_range },
    { "openat2",            __NR_openat2 },
    { "pidfd_getfd",        __NR_pidfd_getfd },
    { "faccessat2",         __NR_faccessat2 },
    { "process_madvise",    __NR_process_madvise },
    { "epoll_pwait2",       __NR_epoll_pwait2 },
    { "mount_setattr",      __NR_mount_setattr },
    { "quotactl_fd",        __NR_quotactl_fd },
#ifdef __NR_landlock_create_ruleset
    { "landlock_create_ruleset", __NR_landlock_create_ruleset },
    { "landlock_add_rule",       __NR_landlock_add_rule },
    { "landlock_restrict_self",  __NR_landlock_restrict_self },
#endif
#ifdef __NR_memfd_secret
    { "memfd_secret",       __NR_memfd_secret },
#endif
#ifdef __NR_process_mrelease
    { "process_mrelease",   __NR_process_mrelease },
#endif
    { NULL, 0 }
};

static int lookup_syscall(const char *name) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (strcmp(syscall_table[i].name, name) == 0)
            return syscall_table[i].nr;
    }
    return -1;
}

/* ── rustd_seccomp_syscall_filter ───────────────────────────────────────────── */

/*
 * Maximum number of syscall entries we allow in the filter before falling
 * back to ALLOW-all.  Each syscall costs 2 BPF instructions in the list.
 * Header is 4 instructions (arch guard + syscall load).
 * Tail is 2 instructions.
 * So: 4 + 2*N + 2 <= 4096 → N <= 2045.
 */
#define MAX_FILTER_SYSCALLS 2045
#define MAX_BPF_INSNS       4096

static int valid_rule_action(uint32_t action) {
    uint32_t kind = action & SECCOMP_RET_ACTION_FULL;
    if (kind == SECCOMP_RET_ALLOW || kind == SECCOMP_RET_KILL_PROCESS)
        return 1;
    if (kind == SECCOMP_RET_ERRNO)
        return (action & SECCOMP_RET_DATA) > 0;
    return 0;
}

static int native_audit_arch(uint32_t *ret) {
    if (!ret)
        return -EINVAL;
#if defined(__x86_64__)
    *ret = AUDIT_ARCH_X86_64;
    return 0;
#elif defined(__aarch64__)
    *ret = AUDIT_ARCH_AARCH64;
    return 0;
#else
    return -EOPNOTSUPP;
#endif
}

int rustd_seccomp_restrict_native_architecture(void) {
    uint32_t arch;
    int r = native_audit_arch(&arch);
    if (r < 0)
        return r;

    struct sock_filter filter[] = {
        LOAD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    return install_filter(filter, (unsigned int)(sizeof(filter) / sizeof(filter[0])));
}

int rustd_seccomp_syscall_rules(const rustd_seccomp_rule *rules,
                             size_t n_rules,
                             uint32_t default_action) {
    if (n_rules > 0 && !rules)
        return -EINVAL;
    if (n_rules > MAX_FILTER_SYSCALLS)
        return -E2BIG;
    if (!valid_rule_action(default_action))
        return -EINVAL;

    for (size_t i = 0; i < n_rules; i++) {
        if (!valid_rule_action(rules[i].action))
            return -EINVAL;
    }

    uint32_t arch;
    int r = native_audit_arch(&arch);
    if (r < 0)
        return r;

    unsigned int prog_len = 5U + 2U * (unsigned int)n_rules;
    if (prog_len > MAX_BPF_INSNS)
        return -E2BIG;

    struct sock_filter *prog = calloc(prog_len, sizeof(struct sock_filter));
    if (!prog)
        return -ENOMEM;

    unsigned int idx = 0;
    prog[idx++] = (struct sock_filter)LOAD_ARCH;
    prog[idx++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0);
    prog[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, default_action);
    prog[idx++] = (struct sock_filter)LOAD_SYSCALL;

    for (size_t i = 0; i < n_rules; i++) {
        prog[idx++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)rules[i].nr, 0, 1);
        prog[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, rules[i].action);
    }
    prog[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, default_action);

    if (idx != prog_len) {
        free(prog);
        return -EINVAL;
    }

    r = install_filter(prog, prog_len);
    free(prog);
    return r;
}

int rustd_seccomp_syscall_filter(const char *const *allow_list,
                     const char *const *deny_list,
                     int error_number) {
    if ((allow_list == NULL) == (deny_list == NULL))
        return -EINVAL;
    if (error_number <= 0 || error_number > (int)SECCOMP_RET_DATA)
        return -EINVAL;

    const char *const *list = allow_list != NULL ? allow_list : deny_list;
    int is_allowlist = allow_list != NULL;
    int n = 0;
    for (; list[n] != NULL; n++)
        ;

    if (n == 0)
        return is_allowlist ? -EINVAL : 0;
    if (n > MAX_FILTER_SYSCALLS)
        return -E2BIG;

    int *nrs = malloc((size_t)n * sizeof(int));
    if (nrs == NULL)
        return -ENOMEM;

    int valid = 0;
    for (int i = 0; i < n; i++) {
        int nr = lookup_syscall(list[i]);
        if (nr >= 0)
  nrs[valid++] = nr;
    }

    if (valid == 0) {
        free(nrs);
        return is_allowlist ? -EINVAL : 0;
    }

    /* Five-instruction header, two instructions per entry, one default. */
    unsigned int prog_len = 6U + 2U * (unsigned int)valid;
    struct sock_filter *prog = malloc(prog_len * sizeof(struct sock_filter));
    if (prog == NULL) {
        free(nrs);
        return -ENOMEM;
    }

    unsigned int idx = 0;
    prog[idx++] = (struct sock_filter)LOAD_ARCH;
    prog[idx++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_X86_64, 2, 0);
    prog[idx++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, ARCH_GUARD_AARCH64, 1, 0);
    prog[idx++] = (struct sock_filter)ALLOW;
    prog[idx++] = (struct sock_filter)LOAD_SYSCALL;

    for (int i = 0; i < valid; i++) {
        prog[idx++] = (struct sock_filter)BPF_JUMP(
  BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nrs[i], 0, 1);
        prog[idx++] = is_allowlist
  ? (struct sock_filter)ALLOW
  : (struct sock_filter)EPERM_RET((unsigned int)error_number);
    }

    prog[idx++] = is_allowlist
        ? (struct sock_filter)EPERM_RET((unsigned int)error_number)
        : (struct sock_filter)ALLOW;

    int rc = install_filter(prog, prog_len);
    free(prog);
    free(nrs);
    return rc;
}
