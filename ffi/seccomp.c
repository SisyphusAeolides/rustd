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

/* Common Linux syscall names, compiled only when present in the target ABI. */
static const syscall_entry syscall_table[] = {
#ifdef __NR_read
    { "read",               __NR_read },
#endif
#ifdef __NR_write
    { "write",              __NR_write },
#endif
#ifdef __NR_open
    { "open",               __NR_open },
#endif
#ifdef __NR_close
    { "close",              __NR_close },
#endif
#ifdef __NR_stat
    { "stat",               __NR_stat },
#endif
#ifdef __NR_fstat
    { "fstat",              __NR_fstat },
#endif
#ifdef __NR_lstat
    { "lstat",              __NR_lstat },
#endif
#ifdef __NR_poll
    { "poll",               __NR_poll },
#endif
#ifdef __NR_lseek
    { "lseek",              __NR_lseek },
#endif
#ifdef __NR_mmap
    { "mmap",               __NR_mmap },
#endif
#ifdef __NR_mprotect
    { "mprotect",           __NR_mprotect },
#endif
#ifdef __NR_munmap
    { "munmap",             __NR_munmap },
#endif
#ifdef __NR_brk
    { "brk",                __NR_brk },
#endif
#ifdef __NR_rt_sigaction
    { "rt_sigaction",       __NR_rt_sigaction },
#endif
#ifdef __NR_rt_sigprocmask
    { "rt_sigprocmask",     __NR_rt_sigprocmask },
#endif
#ifdef __NR_rt_sigreturn
    { "rt_sigreturn",       __NR_rt_sigreturn },
#endif
#ifdef __NR_ioctl
    { "ioctl",              __NR_ioctl },
#endif
#ifdef __NR_pread64
    { "pread64",            __NR_pread64 },
#endif
#ifdef __NR_pwrite64
    { "pwrite64",           __NR_pwrite64 },
#endif
#ifdef __NR_readv
    { "readv",              __NR_readv },
#endif
#ifdef __NR_writev
    { "writev",             __NR_writev },
#endif
#ifdef __NR_access
    { "access",             __NR_access },
#endif
#ifdef __NR_pipe
    { "pipe",               __NR_pipe },
#endif
#ifdef __NR_select
    { "select",             __NR_select },
#endif
#ifdef __NR_sched_yield
    { "sched_yield",        __NR_sched_yield },
#endif
#ifdef __NR_mremap
    { "mremap",             __NR_mremap },
#endif
#ifdef __NR_msync
    { "msync",              __NR_msync },
#endif
#ifdef __NR_mincore
    { "mincore",            __NR_mincore },
#endif
#ifdef __NR_madvise
    { "madvise",            __NR_madvise },
#endif
#ifdef __NR_shmget
    { "shmget",             __NR_shmget },
#endif
#ifdef __NR_shmat
    { "shmat",              __NR_shmat },
#endif
#ifdef __NR_shmctl
    { "shmctl",             __NR_shmctl },
#endif
#ifdef __NR_dup
    { "dup",                __NR_dup },
#endif
#ifdef __NR_dup2
    { "dup2",               __NR_dup2 },
#endif
#ifdef __NR_pause
    { "pause",              __NR_pause },
#endif
#ifdef __NR_nanosleep
    { "nanosleep",          __NR_nanosleep },
#endif
#ifdef __NR_getitimer
    { "getitimer",          __NR_getitimer },
#endif
#ifdef __NR_alarm
    { "alarm",              __NR_alarm },
#endif
#ifdef __NR_setitimer
    { "setitimer",          __NR_setitimer },
#endif
#ifdef __NR_getpid
    { "getpid",             __NR_getpid },
#endif
#ifdef __NR_sendfile
    { "sendfile",           __NR_sendfile },
#endif
#ifdef __NR_socket
    { "socket",             __NR_socket },
#endif
#ifdef __NR_connect
    { "connect",            __NR_connect },
#endif
#ifdef __NR_accept
    { "accept",             __NR_accept },
#endif
#ifdef __NR_sendto
    { "sendto",             __NR_sendto },
#endif
#ifdef __NR_recvfrom
    { "recvfrom",           __NR_recvfrom },
#endif
#ifdef __NR_sendmsg
    { "sendmsg",            __NR_sendmsg },
#endif
#ifdef __NR_recvmsg
    { "recvmsg",            __NR_recvmsg },
#endif
#ifdef __NR_shutdown
    { "shutdown",           __NR_shutdown },
#endif
#ifdef __NR_bind
    { "bind",               __NR_bind },
#endif
#ifdef __NR_listen
    { "listen",             __NR_listen },
#endif
#ifdef __NR_getsockname
    { "getsockname",        __NR_getsockname },
#endif
#ifdef __NR_getpeername
    { "getpeername",        __NR_getpeername },
#endif
#ifdef __NR_socketpair
    { "socketpair",         __NR_socketpair },
#endif
#ifdef __NR_setsockopt
    { "setsockopt",         __NR_setsockopt },
#endif
#ifdef __NR_getsockopt
    { "getsockopt",         __NR_getsockopt },
#endif
#ifdef __NR_clone
    { "clone",              __NR_clone },
#endif
#ifdef __NR_fork
    { "fork",               __NR_fork },
#endif
#ifdef __NR_vfork
    { "vfork",              __NR_vfork },
#endif
#ifdef __NR_execve
    { "execve",             __NR_execve },
#endif
#ifdef __NR_exit
    { "exit",               __NR_exit },
#endif
#ifdef __NR_wait4
    { "wait4",              __NR_wait4 },
#endif
#ifdef __NR_kill
    { "kill",               __NR_kill },
#endif
#ifdef __NR_uname
    { "uname",              __NR_uname },
#endif
#ifdef __NR_semget
    { "semget",             __NR_semget },
#endif
#ifdef __NR_semop
    { "semop",              __NR_semop },
#endif
#ifdef __NR_semctl
    { "semctl",             __NR_semctl },
#endif
#ifdef __NR_shmdt
    { "shmdt",              __NR_shmdt },
#endif
#ifdef __NR_msgget
    { "msgget",             __NR_msgget },
#endif
#ifdef __NR_msgsnd
    { "msgsnd",             __NR_msgsnd },
#endif
#ifdef __NR_msgrcv
    { "msgrcv",             __NR_msgrcv },
#endif
#ifdef __NR_msgctl
    { "msgctl",             __NR_msgctl },
#endif
#ifdef __NR_fcntl
    { "fcntl",              __NR_fcntl },
#endif
#ifdef __NR_flock
    { "flock",              __NR_flock },
#endif
#ifdef __NR_fsync
    { "fsync",              __NR_fsync },
#endif
#ifdef __NR_fdatasync
    { "fdatasync",          __NR_fdatasync },
#endif
#ifdef __NR_truncate
    { "truncate",           __NR_truncate },
#endif
#ifdef __NR_ftruncate
    { "ftruncate",          __NR_ftruncate },
#endif
#ifdef __NR_getdents
    { "getdents",           __NR_getdents },
#endif
#ifdef __NR_getcwd
    { "getcwd",             __NR_getcwd },
#endif
#ifdef __NR_chdir
    { "chdir",              __NR_chdir },
#endif
#ifdef __NR_fchdir
    { "fchdir",             __NR_fchdir },
#endif
#ifdef __NR_rename
    { "rename",             __NR_rename },
#endif
#ifdef __NR_mkdir
    { "mkdir",              __NR_mkdir },
#endif
#ifdef __NR_rmdir
    { "rmdir",              __NR_rmdir },
#endif
#ifdef __NR_creat
    { "creat",              __NR_creat },
#endif
#ifdef __NR_link
    { "link",               __NR_link },
#endif
#ifdef __NR_unlink
    { "unlink",             __NR_unlink },
#endif
#ifdef __NR_symlink
    { "symlink",            __NR_symlink },
#endif
#ifdef __NR_readlink
    { "readlink",           __NR_readlink },
#endif
#ifdef __NR_chmod
    { "chmod",              __NR_chmod },
#endif
#ifdef __NR_fchmod
    { "fchmod",             __NR_fchmod },
#endif
#ifdef __NR_chown
    { "chown",              __NR_chown },
#endif
#ifdef __NR_fchown
    { "fchown",             __NR_fchown },
#endif
#ifdef __NR_lchown
    { "lchown",             __NR_lchown },
#endif
#ifdef __NR_umask
    { "umask",              __NR_umask },
#endif
#ifdef __NR_gettimeofday
    { "gettimeofday",       __NR_gettimeofday },
#endif
#ifdef __NR_getrlimit
    { "getrlimit",          __NR_getrlimit },
#endif
#ifdef __NR_getrusage
    { "getrusage",          __NR_getrusage },
#endif
#ifdef __NR_sysinfo
    { "sysinfo",            __NR_sysinfo },
#endif
#ifdef __NR_times
    { "times",              __NR_times },
#endif
#ifdef __NR_ptrace
    { "ptrace",             __NR_ptrace },
#endif
#ifdef __NR_getuid
    { "getuid",             __NR_getuid },
#endif
#ifdef __NR_syslog
    { "syslog",             __NR_syslog },
#endif
#ifdef __NR_getgid
    { "getgid",             __NR_getgid },
#endif
#ifdef __NR_setuid
    { "setuid",             __NR_setuid },
#endif
#ifdef __NR_setgid
    { "setgid",             __NR_setgid },
#endif
#ifdef __NR_geteuid
    { "geteuid",            __NR_geteuid },
#endif
#ifdef __NR_getegid
    { "getegid",            __NR_getegid },
#endif
#ifdef __NR_setpgid
    { "setpgid",            __NR_setpgid },
#endif
#ifdef __NR_getppid
    { "getppid",            __NR_getppid },
#endif
#ifdef __NR_getpgrp
    { "getpgrp",            __NR_getpgrp },
#endif
#ifdef __NR_setsid
    { "setsid",             __NR_setsid },
#endif
#ifdef __NR_setreuid
    { "setreuid",           __NR_setreuid },
#endif
#ifdef __NR_setregid
    { "setregid",           __NR_setregid },
#endif
#ifdef __NR_getgroups
    { "getgroups",          __NR_getgroups },
#endif
#ifdef __NR_setgroups
    { "setgroups",          __NR_setgroups },
#endif
#ifdef __NR_setresuid
    { "setresuid",          __NR_setresuid },
#endif
#ifdef __NR_getresuid
    { "getresuid",          __NR_getresuid },
#endif
#ifdef __NR_setresgid
    { "setresgid",          __NR_setresgid },
#endif
#ifdef __NR_getresgid
    { "getresgid",          __NR_getresgid },
#endif
#ifdef __NR_getpgid
    { "getpgid",            __NR_getpgid },
#endif
#ifdef __NR_setfsuid
    { "setfsuid",           __NR_setfsuid },
#endif
#ifdef __NR_setfsgid
    { "setfsgid",           __NR_setfsgid },
#endif
#ifdef __NR_getsid
    { "getsid",             __NR_getsid },
#endif
#ifdef __NR_capget
    { "capget",             __NR_capget },
#endif
#ifdef __NR_capset
    { "capset",             __NR_capset },
#endif
#ifdef __NR_rt_sigpending
    { "rt_sigpending",      __NR_rt_sigpending },
#endif
#ifdef __NR_rt_sigtimedwait
    { "rt_sigtimedwait",    __NR_rt_sigtimedwait },
#endif
#ifdef __NR_rt_sigqueueinfo
    { "rt_sigqueueinfo",    __NR_rt_sigqueueinfo },
#endif
#ifdef __NR_rt_sigsuspend
    { "rt_sigsuspend",      __NR_rt_sigsuspend },
#endif
#ifdef __NR_sigaltstack
    { "sigaltstack",        __NR_sigaltstack },
#endif
#ifdef __NR_utime
    { "utime",              __NR_utime },
#endif
#ifdef __NR_mknod
    { "mknod",              __NR_mknod },
#endif
#ifdef __NR_personality
    { "personality",        __NR_personality },
#endif
#ifdef __NR_statfs
    { "statfs",             __NR_statfs },
#endif
#ifdef __NR_fstatfs
    { "fstatfs",            __NR_fstatfs },
#endif
#ifdef __NR_getpriority
    { "getpriority",        __NR_getpriority },
#endif
#ifdef __NR_setpriority
    { "setpriority",        __NR_setpriority },
#endif
#ifdef __NR_sched_setparam
    { "sched_setparam",     __NR_sched_setparam },
#endif
#ifdef __NR_sched_getparam
    { "sched_getparam",     __NR_sched_getparam },
#endif
#ifdef __NR_sched_setscheduler
    { "sched_setscheduler", __NR_sched_setscheduler },
#endif
#ifdef __NR_sched_getscheduler
    { "sched_getscheduler", __NR_sched_getscheduler },
#endif
#ifdef __NR_sched_get_priority_max
    { "sched_get_priority_max", __NR_sched_get_priority_max },
#endif
#ifdef __NR_sched_get_priority_min
    { "sched_get_priority_min", __NR_sched_get_priority_min },
#endif
#ifdef __NR_sched_rr_get_interval
    { "sched_rr_get_interval",  __NR_sched_rr_get_interval },
#endif
#ifdef __NR_mlock
    { "mlock",              __NR_mlock },
#endif
#ifdef __NR_munlock
    { "munlock",            __NR_munlock },
#endif
#ifdef __NR_mlockall
    { "mlockall",           __NR_mlockall },
#endif
#ifdef __NR_munlockall
    { "munlockall",         __NR_munlockall },
#endif
#ifdef __NR_vhangup
    { "vhangup",            __NR_vhangup },
#endif
#ifdef __NR_pivot_root
    { "pivot_root",         __NR_pivot_root },
#endif
#ifdef __NR_prctl
    { "prctl",              __NR_prctl },
#endif
#ifdef __NR_arch_prctl
    { "arch_prctl",         __NR_arch_prctl },
#endif
#ifdef __NR_adjtimex
    { "adjtimex",           __NR_adjtimex },
#endif
#ifdef __NR_setrlimit
    { "setrlimit",          __NR_setrlimit },
#endif
#ifdef __NR_chroot
    { "chroot",             __NR_chroot },
#endif
#ifdef __NR_sync
    { "sync",               __NR_sync },
#endif
#ifdef __NR_acct
    { "acct",               __NR_acct },
#endif
#ifdef __NR_settimeofday
    { "settimeofday",       __NR_settimeofday },
#endif
#ifdef __NR_mount
    { "mount",              __NR_mount },
#endif
#ifdef __NR_umount2
    { "umount2",            __NR_umount2 },
#endif
#ifdef __NR_swapon
    { "swapon",             __NR_swapon },
#endif
#ifdef __NR_swapoff
    { "swapoff",            __NR_swapoff },
#endif
#ifdef __NR_reboot
    { "reboot",             __NR_reboot },
#endif
#ifdef __NR_sethostname
    { "sethostname",        __NR_sethostname },
#endif
#ifdef __NR_setdomainname
    { "setdomainname",      __NR_setdomainname },
#endif
#ifdef __NR_init_module
    { "init_module",        __NR_init_module },
#endif
#ifdef __NR_delete_module
    { "delete_module",      __NR_delete_module },
#endif
#ifdef __NR_quotactl
    { "quotactl",           __NR_quotactl },
#endif
#ifdef __NR_gettid
    { "gettid",             __NR_gettid },
#endif
#ifdef __NR_readahead
    { "readahead",          __NR_readahead },
#endif
#ifdef __NR_setxattr
    { "setxattr",           __NR_setxattr },
#endif
#ifdef __NR_lsetxattr
    { "lsetxattr",          __NR_lsetxattr },
#endif
#ifdef __NR_fsetxattr
    { "fsetxattr",          __NR_fsetxattr },
#endif
#ifdef __NR_getxattr
    { "getxattr",           __NR_getxattr },
#endif
#ifdef __NR_lgetxattr
    { "lgetxattr",          __NR_lgetxattr },
#endif
#ifdef __NR_fgetxattr
    { "fgetxattr",          __NR_fgetxattr },
#endif
#ifdef __NR_listxattr
    { "listxattr",          __NR_listxattr },
#endif
#ifdef __NR_llistxattr
    { "llistxattr",         __NR_llistxattr },
#endif
#ifdef __NR_flistxattr
    { "flistxattr",         __NR_flistxattr },
#endif
#ifdef __NR_removexattr
    { "removexattr",        __NR_removexattr },
#endif
#ifdef __NR_lremovexattr
    { "lremovexattr",       __NR_lremovexattr },
#endif
#ifdef __NR_fremovexattr
    { "fremovexattr",       __NR_fremovexattr },
#endif
#ifdef __NR_tkill
    { "tkill",              __NR_tkill },
#endif
#ifdef __NR_time
    { "time",               __NR_time },
#endif
#ifdef __NR_futex
    { "futex",              __NR_futex },
#endif
#ifdef __NR_sched_setaffinity
    { "sched_setaffinity",  __NR_sched_setaffinity },
#endif
#ifdef __NR_sched_getaffinity
    { "sched_getaffinity",  __NR_sched_getaffinity },
#endif
#ifdef __NR_io_setup
    { "io_setup",           __NR_io_setup },
#endif
#ifdef __NR_io_destroy
    { "io_destroy",         __NR_io_destroy },
#endif
#ifdef __NR_io_getevents
    { "io_getevents",       __NR_io_getevents },
#endif
#ifdef __NR_io_submit
    { "io_submit",          __NR_io_submit },
#endif
#ifdef __NR_io_cancel
    { "io_cancel",          __NR_io_cancel },
#endif
#ifdef __NR_epoll_create
    { "epoll_create",       __NR_epoll_create },
#endif
#ifdef __NR_getdents64
    { "getdents64",         __NR_getdents64 },
#endif
#ifdef __NR_set_tid_address
    { "set_tid_address",    __NR_set_tid_address },
#endif
#ifdef __NR_restart_syscall
    { "restart_syscall",    __NR_restart_syscall },
#endif
#ifdef __NR_semtimedop
    { "semtimedop",         __NR_semtimedop },
#endif
#ifdef __NR_fadvise64
    { "fadvise64",          __NR_fadvise64 },
#endif
#ifdef __NR_timer_create
    { "timer_create",       __NR_timer_create },
#endif
#ifdef __NR_timer_settime
    { "timer_settime",      __NR_timer_settime },
#endif
#ifdef __NR_timer_gettime
    { "timer_gettime",      __NR_timer_gettime },
#endif
#ifdef __NR_timer_getoverrun
    { "timer_getoverrun",   __NR_timer_getoverrun },
#endif
#ifdef __NR_timer_delete
    { "timer_delete",       __NR_timer_delete },
#endif
#ifdef __NR_clock_settime
    { "clock_settime",      __NR_clock_settime },
#endif
#ifdef __NR_clock_gettime
    { "clock_gettime",      __NR_clock_gettime },
#endif
#ifdef __NR_clock_getres
    { "clock_getres",       __NR_clock_getres },
#endif
#ifdef __NR_clock_nanosleep
    { "clock_nanosleep",    __NR_clock_nanosleep },
#endif
#ifdef __NR_exit_group
    { "exit_group",         __NR_exit_group },
#endif
#ifdef __NR_epoll_wait
    { "epoll_wait",         __NR_epoll_wait },
#endif
#ifdef __NR_epoll_ctl
    { "epoll_ctl",          __NR_epoll_ctl },
#endif
#ifdef __NR_tgkill
    { "tgkill",             __NR_tgkill },
#endif
#ifdef __NR_utimes
    { "utimes",             __NR_utimes },
#endif
#ifdef __NR_mq_open
    { "mq_open",            __NR_mq_open },
#endif
#ifdef __NR_mq_unlink
    { "mq_unlink",          __NR_mq_unlink },
#endif
#ifdef __NR_mq_timedsend
    { "mq_timedsend",       __NR_mq_timedsend },
#endif
#ifdef __NR_mq_timedreceive
    { "mq_timedreceive",    __NR_mq_timedreceive },
#endif
#ifdef __NR_mq_notify
    { "mq_notify",          __NR_mq_notify },
#endif
#ifdef __NR_mq_getsetattr
    { "mq_getsetattr",      __NR_mq_getsetattr },
#endif
#ifdef __NR_kexec_load
    { "kexec_load",         __NR_kexec_load },
#endif
#ifdef __NR_waitid
    { "waitid",             __NR_waitid },
#endif
#ifdef __NR_add_key
    { "add_key",            __NR_add_key },
#endif
#ifdef __NR_request_key
    { "request_key",        __NR_request_key },
#endif
#ifdef __NR_keyctl
    { "keyctl",             __NR_keyctl },
#endif
#ifdef __NR_ioprio_set
    { "ioprio_set",         __NR_ioprio_set },
#endif
#ifdef __NR_ioprio_get
    { "ioprio_get",         __NR_ioprio_get },
#endif
#ifdef __NR_inotify_init
    { "inotify_init",       __NR_inotify_init },
#endif
#ifdef __NR_inotify_add_watch
    { "inotify_add_watch",  __NR_inotify_add_watch },
#endif
#ifdef __NR_inotify_rm_watch
    { "inotify_rm_watch",   __NR_inotify_rm_watch },
#endif
#ifdef __NR_openat
    { "openat",             __NR_openat },
#endif
#ifdef __NR_mkdirat
    { "mkdirat",            __NR_mkdirat },
#endif
#ifdef __NR_mknodat
    { "mknodat",            __NR_mknodat },
#endif
#ifdef __NR_fchownat
    { "fchownat",           __NR_fchownat },
#endif
#ifdef __NR_futimesat
    { "futimesat",          __NR_futimesat },
#endif
#ifdef __NR_newfstatat
    { "newfstatat",         __NR_newfstatat },
#endif
#ifdef __NR_unlinkat
    { "unlinkat",           __NR_unlinkat },
#endif
#ifdef __NR_renameat
    { "renameat",           __NR_renameat },
#endif
#ifdef __NR_linkat
    { "linkat",             __NR_linkat },
#endif
#ifdef __NR_symlinkat
    { "symlinkat",          __NR_symlinkat },
#endif
#ifdef __NR_readlinkat
    { "readlinkat",         __NR_readlinkat },
#endif
#ifdef __NR_fchmodat
    { "fchmodat",           __NR_fchmodat },
#endif
#ifdef __NR_faccessat
    { "faccessat",          __NR_faccessat },
#endif
#ifdef __NR_pselect6
    { "pselect6",           __NR_pselect6 },
#endif
#ifdef __NR_ppoll
    { "ppoll",              __NR_ppoll },
#endif
#ifdef __NR_unshare
    { "unshare",            __NR_unshare },
#endif
#ifdef __NR_set_robust_list
    { "set_robust_list",    __NR_set_robust_list },
#endif
#ifdef __NR_get_robust_list
    { "get_robust_list",    __NR_get_robust_list },
#endif
#ifdef __NR_splice
    { "splice",             __NR_splice },
#endif
#ifdef __NR_tee
    { "tee",                __NR_tee },
#endif
#ifdef __NR_sync_file_range
    { "sync_file_range",    __NR_sync_file_range },
#endif
#ifdef __NR_vmsplice
    { "vmsplice",           __NR_vmsplice },
#endif
#ifdef __NR_move_pages
    { "move_pages",         __NR_move_pages },
#endif
#ifdef __NR_utimensat
    { "utimensat",          __NR_utimensat },
#endif
#ifdef __NR_epoll_pwait
    { "epoll_pwait",        __NR_epoll_pwait },
#endif
#ifdef __NR_signalfd
    { "signalfd",           __NR_signalfd },
#endif
#ifdef __NR_timerfd_create
    { "timerfd_create",     __NR_timerfd_create },
#endif
#ifdef __NR_eventfd
    { "eventfd",            __NR_eventfd },
#endif
#ifdef __NR_fallocate
    { "fallocate",          __NR_fallocate },
#endif
#ifdef __NR_timerfd_settime
    { "timerfd_settime",    __NR_timerfd_settime },
#endif
#ifdef __NR_timerfd_gettime
    { "timerfd_gettime",    __NR_timerfd_gettime },
#endif
#ifdef __NR_accept4
    { "accept4",            __NR_accept4 },
#endif
#ifdef __NR_signalfd4
    { "signalfd4",          __NR_signalfd4 },
#endif
#ifdef __NR_eventfd2
    { "eventfd2",           __NR_eventfd2 },
#endif
#ifdef __NR_epoll_create1
    { "epoll_create1",      __NR_epoll_create1 },
#endif
#ifdef __NR_dup3
    { "dup3",               __NR_dup3 },
#endif
#ifdef __NR_pipe2
    { "pipe2",              __NR_pipe2 },
#endif
#ifdef __NR_inotify_init1
    { "inotify_init1",      __NR_inotify_init1 },
#endif
#ifdef __NR_preadv
    { "preadv",             __NR_preadv },
#endif
#ifdef __NR_pwritev
    { "pwritev",            __NR_pwritev },
#endif
#ifdef __NR_rt_tgsigqueueinfo
    { "rt_tgsigqueueinfo",  __NR_rt_tgsigqueueinfo },
#endif
#ifdef __NR_perf_event_open
    { "perf_event_open",    __NR_perf_event_open },
#endif
#ifdef __NR_recvmmsg
    { "recvmmsg",           __NR_recvmmsg },
#endif
#ifdef __NR_fanotify_init
    { "fanotify_init",      __NR_fanotify_init },
#endif
#ifdef __NR_fanotify_mark
    { "fanotify_mark",      __NR_fanotify_mark },
#endif
#ifdef __NR_prlimit64
    { "prlimit64",          __NR_prlimit64 },
#endif
#ifdef __NR_name_to_handle_at
    { "name_to_handle_at",  __NR_name_to_handle_at },
#endif
#ifdef __NR_open_by_handle_at
    { "open_by_handle_at",  __NR_open_by_handle_at },
#endif
#ifdef __NR_clock_adjtime
    { "clock_adjtime",      __NR_clock_adjtime },
#endif
#ifdef __NR_syncfs
    { "syncfs",             __NR_syncfs },
#endif
#ifdef __NR_sendmmsg
    { "sendmmsg",           __NR_sendmmsg },
#endif
#ifdef __NR_setns
    { "setns",              __NR_setns },
#endif
#ifdef __NR_getcpu
    { "getcpu",             __NR_getcpu },
#endif
#ifdef __NR_process_vm_readv
    { "process_vm_readv",   __NR_process_vm_readv },
#endif
#ifdef __NR_process_vm_writev
    { "process_vm_writev",  __NR_process_vm_writev },
#endif
#ifdef __NR_kcmp
    { "kcmp",               __NR_kcmp },
#endif
#ifdef __NR_finit_module
    { "finit_module",       __NR_finit_module },
#endif
#ifdef __NR_sched_setattr
    { "sched_setattr",      __NR_sched_setattr },
#endif
#ifdef __NR_sched_getattr
    { "sched_getattr",      __NR_sched_getattr },
#endif
#ifdef __NR_renameat2
    { "renameat2",          __NR_renameat2 },
#endif
#ifdef __NR_seccomp
    { "seccomp",            __NR_seccomp },
#endif
#ifdef __NR_getrandom
    { "getrandom",          __NR_getrandom },
#endif
#ifdef __NR_memfd_create
    { "memfd_create",       __NR_memfd_create },
#endif
#ifdef __NR_kexec_file_load
    { "kexec_file_load",    __NR_kexec_file_load },
#endif
#ifdef __NR_bpf
    { "bpf",                __NR_bpf },
#endif
#ifdef __NR_execveat
    { "execveat",           __NR_execveat },
#endif
#ifdef __NR_userfaultfd
    { "userfaultfd",        __NR_userfaultfd },
#endif
#ifdef __NR_membarrier
    { "membarrier",         __NR_membarrier },
#endif
#ifdef __NR_mlock2
    { "mlock2",             __NR_mlock2 },
#endif
#ifdef __NR_copy_file_range
    { "copy_file_range",    __NR_copy_file_range },
#endif
#ifdef __NR_preadv2
    { "preadv2",            __NR_preadv2 },
#endif
#ifdef __NR_pwritev2
    { "pwritev2",           __NR_pwritev2 },
#endif
#ifdef __NR_pkey_mprotect
    { "pkey_mprotect",      __NR_pkey_mprotect },
#endif
#ifdef __NR_pkey_alloc
    { "pkey_alloc",         __NR_pkey_alloc },
#endif
#ifdef __NR_pkey_free
    { "pkey_free",          __NR_pkey_free },
#endif
#ifdef __NR_statx
    { "statx",              __NR_statx },
#endif
#ifdef __NR_io_pgetevents
    { "io_pgetevents",      __NR_io_pgetevents },
#endif
#ifdef __NR_rseq
    { "rseq",               __NR_rseq },
#endif
#ifdef __NR_pidfd_send_signal
    { "pidfd_send_signal",  __NR_pidfd_send_signal },
#endif
#ifdef __NR_io_uring_setup
    { "io_uring_setup",     __NR_io_uring_setup },
#endif
#ifdef __NR_io_uring_enter
    { "io_uring_enter",     __NR_io_uring_enter },
#endif
#ifdef __NR_io_uring_register
    { "io_uring_register",  __NR_io_uring_register },
#endif
#ifdef __NR_open_tree
    { "open_tree",          __NR_open_tree },
#endif
#ifdef __NR_move_mount
    { "move_mount",         __NR_move_mount },
#endif
#ifdef __NR_fsopen
    { "fsopen",             __NR_fsopen },
#endif
#ifdef __NR_fsconfig
    { "fsconfig",           __NR_fsconfig },
#endif
#ifdef __NR_fsmount
    { "fsmount",            __NR_fsmount },
#endif
#ifdef __NR_fspick
    { "fspick",             __NR_fspick },
#endif
#ifdef __NR_pidfd_open
    { "pidfd_open",         __NR_pidfd_open },
#endif
#ifdef __NR_clone3
    { "clone3",             __NR_clone3 },
#endif
#ifdef __NR_close_range
    { "close_range",        __NR_close_range },
#endif
#ifdef __NR_openat2
    { "openat2",            __NR_openat2 },
#endif
#ifdef __NR_pidfd_getfd
    { "pidfd_getfd",        __NR_pidfd_getfd },
#endif
#ifdef __NR_faccessat2
    { "faccessat2",         __NR_faccessat2 },
#endif
#ifdef __NR_process_madvise
    { "process_madvise",    __NR_process_madvise },
#endif
#ifdef __NR_epoll_pwait2
    { "epoll_pwait2",       __NR_epoll_pwait2 },
#endif
#ifdef __NR_mount_setattr
    { "mount_setattr",      __NR_mount_setattr },
#endif
#ifdef __NR_quotactl_fd
    { "quotactl_fd",        __NR_quotactl_fd },
#endif
#ifdef __NR_landlock_create_ruleset
    { "landlock_create_ruleset", __NR_landlock_create_ruleset },
#endif
#ifdef __NR_landlock_add_rule
    { "landlock_add_rule",       __NR_landlock_add_rule },
#endif
#ifdef __NR_landlock_restrict_self
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
