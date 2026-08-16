/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/*
 * journal.c — journal socket receiver and binary-format helpers.
 *
 * Upstream reference: src/journal/ (v261)
 */

#include "journal.h"

#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ── internal constants ─────────────────────────────────────────────────── */

#define JOURNAL_DIR          "/run/rustd/journal"
#define JOURNAL_SOCKET_PATH  "/run/rustd/journal/socket"
#define JOURNAL_STDOUT_PATH  "/run/rustd/journal/stdout"

/* ── internal helpers ───────────────────────────────────────────────────── */

/*
 * ensure_journal_dir: mkdir /run/systemd/journal with mode 0755 if absent.
 * Ignores EEXIST.  Returns 0 or -errno.
 */
static int ensure_journal_dir(void) {
    if (mkdir(JOURNAL_DIR, 0755) < 0 && errno != EEXIST)
        return -errno;
    if (chmod(JOURNAL_DIR, 0755) < 0)
        return -errno;
    return 0;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 * read_id128_file: read an ID128 identity file and decode it into 16 raw
 * bytes. Both compact 32-hex forms (e.g. /etc/machine-id) and the canonical
 * hyphenated UUID form exposed by /proc/sys/kernel/random/boot_id are
 * accepted. Returns 0 on success, -errno or -EINVAL on failure.
 */
static int read_id128_file(const char *path, uint8_t out[16]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    int saved = errno;
    close(fd);
    if (n < 0)
        return -saved;

    memset(out, 0, 16);
    size_t digits = 0;
    for (ssize_t i = 0; i < n; i++) {
        char c = buf[i];
        if (c == '-' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;

        int nibble = hex_nibble(c);
        if (nibble < 0 || digits >= 32)
            return -EINVAL;

        if ((digits & 1u) == 0)
            out[digits / 2] = (uint8_t)((unsigned)nibble << 4);
        else
            out[digits / 2] |= (uint8_t)nibble;
        digits++;
    }

    return digits == 32 ? 0 : -EINVAL;
}

/*
 * random_id128: fill buf[16] from /dev/urandom.
 * Returns 0 or -errno.
 */
static int random_id128(uint8_t buf[16]) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    ssize_t n = read(fd, buf, 16);
    close(fd);
    if (n < 16)
        return -EIO;
    return 0;
}

/* ── compressed DATA payload helpers ────────────────────────────────────── */

#define JOURNAL_COMPRESSED_XZ   1u
#define JOURNAL_COMPRESSED_LZ4  2u
#define JOURNAL_COMPRESSED_ZSTD 4u

#define LZMA_OK_VALUE        0
#define LZMA_BUF_ERROR_VALUE 10
#define ZSTD_CONTENTSIZE_UNKNOWN_VALUE UINT64_MAX
#define ZSTD_CONTENTSIZE_ERROR_VALUE   (UINT64_MAX - 1u)

typedef int (*LzmaStreamBufferDecodeFn)(
    uint64_t *memlimit,
    uint32_t flags,
    const void *allocator,
    const uint8_t *input,
    size_t *input_pos,
    size_t input_size,
    uint8_t *output,
    size_t *output_pos,
    size_t output_size);
typedef int (*Lz4DecompressSafeFn)(
    const char *source,
    char *destination,
    int compressed_size,
    int destination_capacity);
typedef unsigned long long (*ZstdFrameContentSizeFn)(const void *source, size_t source_size);
typedef size_t (*ZstdDecompressFn)(
    void *destination,
    size_t destination_capacity,
    const void *source,
    size_t compressed_size);
typedef unsigned int (*ZstdIsErrorFn)(size_t code);

static int load_dynamic_symbol(
        void *handle,
        const char *name,
        void *target,
        size_t target_size) {
    void *symbol;

    if (!handle || !name || !target)
        return -EINVAL;

    symbol = dlsym(handle, name);
    if (!symbol || target_size != sizeof(symbol))
        return -EOPNOTSUPP;

    memcpy(target, &symbol, sizeof(symbol));
    return 0;
}

static ssize_t decompress_journal_xz(
        const uint8_t *source,
        size_t source_size,
        uint8_t *destination,
        size_t destination_size) {
    void *handle;
    LzmaStreamBufferDecodeFn decode = NULL;
    uint64_t memory_limit = UINT64_MAX;
    size_t input_pos = 0;
    size_t output_pos = 0;
    int r;

    if (!destination)
        return -ENODATA;

    handle = dlopen("liblzma.so.5", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return -EOPNOTSUPP;
    r = load_dynamic_symbol(
        handle,
        "lzma_stream_buffer_decode",
        &decode,
        sizeof(decode));
    if (r < 0) {
        dlclose(handle);
        return r;
    }

    r = decode(
        &memory_limit,
        0,
        NULL,
        source,
        &input_pos,
        source_size,
        destination,
        &output_pos,
        destination_size);
    dlclose(handle);

    if (r == LZMA_OK_VALUE && input_pos == source_size) {
        if (output_pos > (size_t)SSIZE_MAX)
            return -EFBIG;
        return (ssize_t)output_pos;
    }
    if (r == LZMA_BUF_ERROR_VALUE)
        return -ENOBUFS;
    return -EBADMSG;
}

static ssize_t decompress_journal_lz4(
        const uint8_t *source,
        size_t source_size,
        uint8_t *destination,
        size_t destination_size) {
    void *handle;
    Lz4DecompressSafeFn decompress = NULL;
    uint64_t expected_le;
    uint64_t expected;
    int r;

    if (source_size <= sizeof(expected_le))
        return -EBADMSG;
    memcpy(&expected_le, source, sizeof(expected_le));
    expected = le64toh(expected_le);
    if (expected == 0 || expected > INT_MAX || expected > (uint64_t)SSIZE_MAX)
        return -EFBIG;
    if (source_size - sizeof(expected_le) > INT_MAX)
        return -EFBIG;
    if (!destination)
        return (ssize_t)expected;
    if (destination_size < expected)
        return -ENOBUFS;

    handle = dlopen("liblz4.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return -EOPNOTSUPP;
    r = load_dynamic_symbol(handle, "LZ4_decompress_safe", &decompress, sizeof(decompress));
    if (r < 0) {
        dlclose(handle);
        return r;
    }

    r = decompress(
        (const char *)source + sizeof(expected_le),
        (char *)destination,
        (int)(source_size - sizeof(expected_le)),
        (int)expected);
    dlclose(handle);
    if (r < 0 || (uint64_t)r != expected)
        return -EBADMSG;
    return (ssize_t)expected;
}

static ssize_t decompress_journal_zstd(
        const uint8_t *source,
        size_t source_size,
        uint8_t *destination,
        size_t destination_size) {
    void *handle;
    ZstdFrameContentSizeFn frame_size = NULL;
    ZstdDecompressFn decompress = NULL;
    ZstdIsErrorFn is_error = NULL;
    uint64_t expected;
    size_t decoded;
    int r;

    handle = dlopen("libzstd.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return -EOPNOTSUPP;
    r = load_dynamic_symbol(
        handle,
        "ZSTD_getFrameContentSize",
        &frame_size,
        sizeof(frame_size));
    if (r >= 0)
        r = load_dynamic_symbol(handle, "ZSTD_decompress", &decompress, sizeof(decompress));
    if (r >= 0)
        r = load_dynamic_symbol(handle, "ZSTD_isError", &is_error, sizeof(is_error));
    if (r < 0) {
        dlclose(handle);
        return r;
    }

    expected = frame_size(source, source_size);
    if (expected == ZSTD_CONTENTSIZE_UNKNOWN_VALUE ||
        expected == ZSTD_CONTENTSIZE_ERROR_VALUE ||
        expected > (uint64_t)SSIZE_MAX) {
        dlclose(handle);
        return -EBADMSG;
    }
    if (!destination) {
        dlclose(handle);
        return (ssize_t)expected;
    }
    if (destination_size < expected) {
        dlclose(handle);
        return -ENOBUFS;
    }

    decoded = decompress(destination, destination_size, source, source_size);
    r = is_error(decoded) ? -EBADMSG : 0;
    dlclose(handle);
    if (r < 0 || decoded != expected)
        return -EBADMSG;
    return (ssize_t)decoded;
}

ssize_t rustd_journal_decompress_payload(
        uint8_t flags,
        const uint8_t *source,
        size_t source_size,
        uint8_t *destination,
        size_t destination_size) {
    if (!source || source_size == 0 || (!destination && destination_size != 0))
        return -EINVAL;

    switch (flags) {
    case JOURNAL_COMPRESSED_XZ:
        return decompress_journal_xz(source, source_size, destination, destination_size);
    case JOURNAL_COMPRESSED_LZ4:
        return decompress_journal_lz4(source, source_size, destination, destination_size);
    case JOURNAL_COMPRESSED_ZSTD:
        return decompress_journal_zstd(source, source_size, destination, destination_size);
    default:
        return -EOPNOTSUPP;
    }
}

/* ── rustd_journal_socket_bind ─────────────────────────────────────────────── */

int rustd_journal_socket_bind(void) {
    int r = ensure_journal_dir();
    if (r < 0)
        return r;

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -errno;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, JOURNAL_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }

    if (chmod(JOURNAL_SOCKET_PATH, 0666) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }

    return fd;
}

/* ── rustd_journal_socket_recv ─────────────────────────────────────────────── */

ssize_t rustd_journal_socket_recv(int fd, void *buf, size_t len) {
    /* Provide a small ancillary buffer to absorb SCM_RIGHTS fds silently. */
    char cmsg_buf[256];

    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -EAGAIN;
        return -errno;
    }
    return n;
}

/* ── rustd_journal_stdout_bind ─────────────────────────────────────────────── */

int rustd_journal_stdout_bind(void) {
    int r = ensure_journal_dir();
    if (r < 0)
        return r;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -errno;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, JOURNAL_STDOUT_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }

    if (listen(fd, 128) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }

    return fd;
}

/* ── binary journal file format ─────────────────────────────────────────── */

#define JOURNAL_HEADER_SIZE UINT64_C(272)
#define JOURNAL_COMPATIBLE_TAIL_ENTRY_BOOT_ID (UINT32_C(1) << 1)
#define DATA_HASH_TABLE_BUCKETS UINT64_C(1024)
#define FIELD_HASH_TABLE_BUCKETS UINT64_C(333)

#define OBJECT_UNUSED 0u
#define OBJECT_DATA 1u
#define OBJECT_FIELD 2u
#define OBJECT_ENTRY 3u
#define OBJECT_DATA_HASH_TABLE 4u
#define OBJECT_FIELD_HASH_TABLE 5u
#define OBJECT_ENTRY_ARRAY 6u

#define STATE_OFFLINE 0u
#define STATE_ONLINE 1u
#define STATE_ARCHIVED 2u

#define BUCKET_SIZE (2u * sizeof(uint64_t))
#define DATA_HASH_TABLE_SIZE (DATA_HASH_TABLE_BUCKETS * BUCKET_SIZE)
#define FIELD_HASH_TABLE_SIZE (FIELD_HASH_TABLE_BUCKETS * BUCKET_SIZE)

/* The structures below mirror journal-def.h's regular (non-compact) layout. */
typedef struct __attribute__((packed)) JournalFileHeader {
    uint8_t signature[8];
    uint32_t compatible_flags;
    uint32_t incompatible_flags;
    uint8_t state;
    uint8_t reserved[7];
    uint8_t file_id[16];
    uint8_t machine_id[16];
    uint8_t tail_entry_boot_id[16];
    uint8_t seqnum_id[16];
    uint64_t header_size;
    uint64_t arena_size;
    uint64_t data_hash_table_offset;
    uint64_t data_hash_table_size;
    uint64_t field_hash_table_offset;
    uint64_t field_hash_table_size;
    uint64_t tail_object_offset;
    uint64_t n_objects;
    uint64_t n_entries;
    uint64_t tail_entry_seqnum;
    uint64_t head_entry_seqnum;
    uint64_t entry_array_offset;
    uint64_t head_entry_realtime;
    uint64_t tail_entry_realtime;
    uint64_t tail_entry_monotonic;
    uint64_t n_data;
    uint64_t n_fields;
    uint64_t n_tags;
    uint64_t n_entry_arrays;
    uint64_t data_hash_chain_depth;
    uint64_t field_hash_chain_depth;
    uint32_t tail_entry_array_offset;
    uint32_t tail_entry_array_n_entries;
    uint64_t tail_entry_offset;
} JournalFileHeader;

_Static_assert(sizeof(JournalFileHeader) == 272,
               "JournalFileHeader must be exactly 272 bytes");

typedef struct __attribute__((packed)) ObjectHeader {
    uint8_t type;
    uint8_t flags;
    uint8_t reserved[6];
    uint64_t size;
} ObjectHeader;

_Static_assert(sizeof(ObjectHeader) == 16, "ObjectHeader must be 16 bytes");

typedef struct __attribute__((packed)) HashItem {
    uint64_t head_hash_offset;
    uint64_t tail_hash_offset;
} HashItem;

_Static_assert(sizeof(HashItem) == 16, "HashItem must be 16 bytes");

typedef struct __attribute__((packed)) FieldObject {
    ObjectHeader object;
    uint64_t hash;
    uint64_t next_hash_offset;
    uint64_t head_data_offset;
} FieldObject;

_Static_assert(sizeof(FieldObject) == 40, "FieldObject base must be 40 bytes");

typedef struct __attribute__((packed)) DataObject {
    ObjectHeader object;
    uint64_t hash;
    uint64_t next_hash_offset;
    uint64_t next_field_offset;
    uint64_t entry_offset;
    uint64_t entry_array_offset;
    uint64_t n_entries;
} DataObject;

_Static_assert(sizeof(DataObject) == 64, "DataObject base must be 64 bytes");

typedef struct __attribute__((packed)) EntryObject {
    ObjectHeader object;
    uint64_t seqnum;
    uint64_t realtime;
    uint64_t monotonic;
    uint8_t boot_id[16];
    uint64_t xor_hash;
} EntryObject;

_Static_assert(sizeof(EntryObject) == 64, "EntryObject base must be 64 bytes");

typedef struct __attribute__((packed)) EntryItem {
    uint64_t object_offset;
    uint64_t hash;
} EntryItem;

_Static_assert(sizeof(EntryItem) == 16, "EntryItem must be 16 bytes");

typedef struct __attribute__((packed)) EntryArrayObject {
    ObjectHeader object;
    uint64_t next_entry_array_offset;
} EntryArrayObject;

_Static_assert(sizeof(EntryArrayObject) == 24,
               "EntryArrayObject base must be 24 bytes");

static uint64_t align64(uint64_t value) {
    return (value + UINT64_C(7)) & ~UINT64_C(7);
}

static int pread_full(int fd, void *buf, size_t len, uint64_t offset) {
    uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, p + done, len - done, (off_t)(offset + done));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EIO;
        done += (size_t)n;
    }
    return 0;
}

static int pwrite_full(int fd, const void *buf, size_t len, uint64_t offset) {
    const uint8_t *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = pwrite(fd, p + done, len - done, (off_t)(offset + done));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EIO;
        done += (size_t)n;
    }
    return 0;
}

static int allocate_range(int fd, uint64_t offset, uint64_t size) {
    if (size > UINT64_MAX - offset || offset + size > (uint64_t)INT64_MAX)
        return -EFBIG;
    int r = posix_fallocate(fd, (off_t)offset, (off_t)size);
    if (r == 0)
        return 0;
    if (r != EOPNOTSUPP && r != ENOSYS && r != EINVAL)
        return -r;

    uint64_t end = offset + size;
    if (ftruncate(fd, (off_t)end) < 0)
        return -errno;
    if (size > 0) {
        const uint8_t zero = 0;
        int wr = pwrite_full(fd, &zero, 1, end - 1);
        if (wr < 0)
            return wr;
    }
    return 0;
}

static int header_read(int fd, JournalFileHeader *header) {
    int r = pread_full(fd, header, sizeof(*header), 0);
    if (r < 0)
        return r;
    static const uint8_t magic[8] = {'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H'};
    if (memcmp(header->signature, magic, sizeof(magic)) != 0)
        return -EBADMSG;
    if (le64toh(header->header_size) < sizeof(*header))
        return -EPROTONOSUPPORT;
    if (le32toh(header->incompatible_flags) != 0)
        return -EPROTONOSUPPORT;
    if ((le32toh(header->compatible_flags) & ~JOURNAL_COMPATIBLE_TAIL_ENTRY_BOOT_ID) != 0)
        return -EPROTONOSUPPORT;
    return 0;
}

static int header_write(int fd, const JournalFileHeader *header) {
    return pwrite_full(fd, header, sizeof(*header), 0);
}

static int mark_state(int fd, uint8_t state) {
    if (fdatasync(fd) < 0)
        return -errno;
    int r = pwrite_full(fd, &state, 1, offsetof(JournalFileHeader, state));
    if (r < 0)
        return r;
    if (fdatasync(fd) < 0)
        return -errno;
    return 0;
}

#define ROT32(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define JENKINS_MIX(a, b, c)       \
    do {                            \
        (a) -= (c);                \
        (a) ^= ROT32((c), 4);      \
        (c) += (b);                \
        (b) -= (a);                \
        (b) ^= ROT32((a), 6);      \
        (a) += (c);                \
        (c) -= (b);                \
        (c) ^= ROT32((b), 8);      \
        (b) += (a);                \
        (a) -= (c);                \
        (a) ^= ROT32((c), 16);     \
        (c) += (b);                \
        (b) -= (a);                \
        (b) ^= ROT32((a), 19);     \
        (a) += (c);                \
        (c) -= (b);                \
        (c) ^= ROT32((b), 4);      \
        (b) += (a);                \
    } while (0)

#define JENKINS_FINAL(a, b, c)     \
    do {                            \
        (c) ^= (b);                \
        (c) -= ROT32((b), 14);     \
        (a) ^= (c);                \
        (a) -= ROT32((c), 11);     \
        (b) ^= (a);                \
        (b) -= ROT32((a), 25);     \
        (c) ^= (b);                \
        (c) -= ROT32((b), 16);     \
        (a) ^= (c);                \
        (a) -= ROT32((c), 4);      \
        (b) ^= (a);                \
        (b) -= ROT32((a), 14);     \
        (c) ^= (b);                \
        (c) -= ROT32((b), 24);     \
    } while (0)

/* Bob Jenkins lookup3 hashlittle2 with zero seeds, matching systemd's
 * jenkins_hash64(): primary result in the high 32 bits, secondary in low. */
static uint64_t journal_hash64(const void *data, size_t length) {
    const uint8_t *k = data;
    size_t remaining = length;
    uint32_t a = UINT32_C(0xdeadbeef) + (uint32_t)length;
    uint32_t b = a;
    uint32_t c = a;

    while (remaining > 12) {
        a += (uint32_t)k[0] | ((uint32_t)k[1] << 8) |
             ((uint32_t)k[2] << 16) | ((uint32_t)k[3] << 24);
        b += (uint32_t)k[4] | ((uint32_t)k[5] << 8) |
             ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 24);
        c += (uint32_t)k[8] | ((uint32_t)k[9] << 8) |
             ((uint32_t)k[10] << 16) | ((uint32_t)k[11] << 24);
        JENKINS_MIX(a, b, c);
        k += 12;
        remaining -= 12;
    }

    if (remaining == 0)
        return ((uint64_t)c << 32) | b;

    if (remaining >= 12) c += (uint32_t)k[11] << 24;
    if (remaining >= 11) c += (uint32_t)k[10] << 16;
    if (remaining >= 10) c += (uint32_t)k[9] << 8;
    if (remaining >= 9) c += k[8];
    if (remaining >= 8) b += (uint32_t)k[7] << 24;
    if (remaining >= 7) b += (uint32_t)k[6] << 16;
    if (remaining >= 6) b += (uint32_t)k[5] << 8;
    if (remaining >= 5) b += k[4];
    if (remaining >= 4) a += (uint32_t)k[3] << 24;
    if (remaining >= 3) a += (uint32_t)k[2] << 16;
    if (remaining >= 2) a += (uint32_t)k[1] << 8;
    if (remaining >= 1) a += k[0];

    JENKINS_FINAL(a, b, c);
    return ((uint64_t)c << 32) | b;
}

static bool journal_field_valid(const char *key, size_t length) {
    if (!key || length == 0 || length > 64)
        return false;
    if (key[0] >= '0' && key[0] <= '9')
        return false;
    for (size_t i = 0; i < length; i++) {
        char ch = key[i];
        if ((ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_')
            return false;
    }
    return true;
}

static int read_object_header(int fd, uint64_t offset, ObjectHeader *object) {
    int r = pread_full(fd, object, sizeof(*object), offset);
    if (r < 0)
        return r;
    uint64_t size = le64toh(object->size);
    if (object->type <= OBJECT_UNUSED || object->type > OBJECT_ENTRY_ARRAY || size < sizeof(*object))
        return -EBADMSG;
    return 0;
}

static int append_zero_object(int fd, JournalFileHeader *header, uint8_t type,
                              uint64_t size, uint64_t *ret_offset) {
    uint64_t p = le64toh(header->tail_object_offset);
    if (p == 0) {
        p = le64toh(header->header_size);
    } else {
        ObjectHeader tail;
        int r = read_object_header(fd, p, &tail);
        if (r < 0)
            return r;
        uint64_t tail_size = le64toh(tail.size);
        if (p > UINT64_MAX - align64(tail_size))
            return -EFBIG;
        p += align64(tail_size);
    }

    uint64_t allocated = align64(size);
    if (p > UINT64_MAX - allocated)
        return -EFBIG;
    int r = allocate_range(fd, p, allocated);
    if (r < 0)
        return r;

    ObjectHeader object = {0};
    object.type = type;
    object.size = htole64(size);
    r = pwrite_full(fd, &object, sizeof(object), p);
    if (r < 0)
        return r;

    header->tail_object_offset = htole64(p);
    header->n_objects = htole64(le64toh(header->n_objects) + 1);
    header->arena_size = htole64(p + allocated - le64toh(header->header_size));
    *ret_offset = p;
    return 0;
}

static int hash_item_for(int fd, const JournalFileHeader *header, bool data_table,
                         uint64_t hash, HashItem *item, uint64_t *item_offset) {
    uint64_t table_offset = le64toh(data_table ? header->data_hash_table_offset
                                               : header->field_hash_table_offset);
    uint64_t table_size = le64toh(data_table ? header->data_hash_table_size
                                             : header->field_hash_table_size);
    uint64_t buckets = table_size / sizeof(HashItem);
    if (table_offset == 0 || buckets == 0)
        return -EBADMSG;
    uint64_t offset = table_offset + (hash % buckets) * sizeof(HashItem);
    int r = pread_full(fd, item, sizeof(*item), offset);
    if (r < 0)
        return r;
    *item_offset = offset;
    return 0;
}

static int payload_equals(int fd, uint64_t object_offset, uint64_t base_size,
                          uint64_t object_size, const void *payload, size_t payload_size) {
    if (object_size != base_size + payload_size)
        return 0;
    uint8_t *buffer = malloc(payload_size ? payload_size : 1);
    if (!buffer)
        return -ENOMEM;
    int r = pread_full(fd, buffer, payload_size, object_offset + base_size);
    if (r < 0) {
        free(buffer);
        return r;
    }
    int equal = memcmp(buffer, payload, payload_size) == 0;
    free(buffer);
    return equal;
}

static int find_field_object(int fd, const JournalFileHeader *header,
                             const void *field, size_t field_size, uint64_t hash,
                             uint64_t *ret_offset) {
    HashItem item;
    uint64_t item_offset;
    int r = hash_item_for(fd, header, false, hash, &item, &item_offset);
    (void)item_offset;
    if (r < 0)
        return r;
    uint64_t p = le64toh(item.head_hash_offset);
    while (p != 0) {
        FieldObject object;
        r = pread_full(fd, &object, sizeof(object), p);
        if (r < 0)
            return r;
        if (object.object.type != OBJECT_FIELD)
            return -EBADMSG;
        if (le64toh(object.hash) == hash) {
            r = payload_equals(fd, p, sizeof(object), le64toh(object.object.size), field, field_size);
            if (r < 0)
                return r;
            if (r > 0) {
                *ret_offset = p;
                return 1;
            }
        }
        uint64_t next = le64toh(object.next_hash_offset);
        if (next != 0 && next <= p)
            return -EBADMSG;
        p = next;
    }
    return 0;
}

static int find_data_object(int fd, const JournalFileHeader *header,
                            const void *data, size_t data_size, uint64_t hash,
                            uint64_t *ret_offset) {
    HashItem item;
    uint64_t item_offset;
    int r = hash_item_for(fd, header, true, hash, &item, &item_offset);
    (void)item_offset;
    if (r < 0)
        return r;
    uint64_t p = le64toh(item.head_hash_offset);
    while (p != 0) {
        DataObject object;
        r = pread_full(fd, &object, sizeof(object), p);
        if (r < 0)
            return r;
        if (object.object.type != OBJECT_DATA)
            return -EBADMSG;
        if (le64toh(object.hash) == hash) {
            r = payload_equals(fd, p, sizeof(object), le64toh(object.object.size), data, data_size);
            if (r < 0)
                return r;
            if (r > 0) {
                *ret_offset = p;
                return 1;
            }
        }
        uint64_t next = le64toh(object.next_hash_offset);
        if (next != 0 && next <= p)
            return -EBADMSG;
        p = next;
    }
    return 0;
}

static int link_hash_object(int fd, const JournalFileHeader *header, bool data_table,
                            uint64_t hash, uint64_t object_offset) {
    HashItem item;
    uint64_t item_offset;
    int r = hash_item_for(fd, header, data_table, hash, &item, &item_offset);
    if (r < 0)
        return r;

    uint64_t tail = le64toh(item.tail_hash_offset);
    if (tail == 0) {
        item.head_hash_offset = htole64(object_offset);
    } else {
        uint64_t next_offset = tail + (data_table ? offsetof(DataObject, next_hash_offset)
                                                   : offsetof(FieldObject, next_hash_offset));
        uint64_t encoded = htole64(object_offset);
        r = pwrite_full(fd, &encoded, sizeof(encoded), next_offset);
        if (r < 0)
            return r;
    }
    item.tail_hash_offset = htole64(object_offset);
    return pwrite_full(fd, &item, sizeof(item), item_offset);
}

static int append_field_object(int fd, JournalFileHeader *header,
                               const char *field, size_t field_size, uint64_t *ret_offset) {
    if (!journal_field_valid(field, field_size))
        return -EBADMSG;
    uint64_t hash = journal_hash64(field, field_size);
    int r = find_field_object(fd, header, field, field_size, hash, ret_offset);
    if (r < 0)
        return r;
    if (r > 0)
        return 0;

    uint64_t offset;
    r = append_zero_object(fd, header, OBJECT_FIELD, sizeof(FieldObject) + field_size, &offset);
    if (r < 0)
        return r;

    FieldObject object = {0};
    object.object.type = OBJECT_FIELD;
    object.object.size = htole64(sizeof(FieldObject) + field_size);
    object.hash = htole64(hash);
    r = pwrite_full(fd, &object, sizeof(object), offset);
    if (r < 0)
        return r;
    r = pwrite_full(fd, field, field_size, offset + sizeof(object));
    if (r < 0)
        return r;
    r = link_hash_object(fd, header, false, hash, offset);
    if (r < 0)
        return r;

    header->n_fields = htole64(le64toh(header->n_fields) + 1);
    *ret_offset = offset;
    return 0;
}

typedef struct DataReference {
    uint64_t offset;
    uint64_t hash;
} DataReference;

static int append_data_object(int fd, JournalFileHeader *header,
                              const SdJournalField *field, DataReference *ret) {
    if (!field || !field->key || (!field->value && field->value_len > 0))
        return -EINVAL;
    size_t key_size = strlen(field->key);
    if (!journal_field_valid(field->key, key_size))
        return -EBADMSG;
    if (key_size > SIZE_MAX - 1 - field->value_len)
        return -E2BIG;
    size_t payload_size = key_size + 1 + field->value_len;
    uint8_t *payload = malloc(payload_size ? payload_size : 1);
    if (!payload)
        return -ENOMEM;
    memcpy(payload, field->key, key_size);
    payload[key_size] = '=';
    if (field->value_len > 0)
        memcpy(payload + key_size + 1, field->value, field->value_len);

    uint64_t hash = journal_hash64(payload, payload_size);
    uint64_t offset;
    int r = find_data_object(fd, header, payload, payload_size, hash, &offset);
    if (r < 0) {
        free(payload);
        return r;
    }
    if (r > 0) {
        free(payload);
        ret->offset = offset;
        ret->hash = hash;
        return 0;
    }

    uint64_t field_offset;
    r = append_field_object(fd, header, field->key, key_size, &field_offset);
    if (r < 0) {
        free(payload);
        return r;
    }
    FieldObject field_object;
    r = pread_full(fd, &field_object, sizeof(field_object), field_offset);
    if (r < 0) {
        free(payload);
        return r;
    }

    r = append_zero_object(fd, header, OBJECT_DATA, sizeof(DataObject) + payload_size, &offset);
    if (r < 0) {
        free(payload);
        return r;
    }
    DataObject object = {0};
    object.object.type = OBJECT_DATA;
    object.object.size = htole64(sizeof(DataObject) + payload_size);
    object.hash = htole64(hash);
    object.next_field_offset = field_object.head_data_offset;
    r = pwrite_full(fd, &object, sizeof(object), offset);
    if (r < 0) {
        free(payload);
        return r;
    }
    r = pwrite_full(fd, payload, payload_size, offset + sizeof(object));
    free(payload);
    if (r < 0)
        return r;
    r = link_hash_object(fd, header, true, hash, offset);
    if (r < 0)
        return r;

    uint64_t encoded = htole64(offset);
    r = pwrite_full(fd, &encoded, sizeof(encoded), field_offset + offsetof(FieldObject, head_data_offset));
    if (r < 0)
        return r;

    header->n_data = htole64(le64toh(header->n_data) + 1);
    ret->offset = offset;
    ret->hash = hash;
    return 0;
}

static int append_entry_array(int fd, JournalFileHeader *header, uint64_t entry_offset,
                              uint64_t *ret_offset) {
    uint64_t offset;
    int r = append_zero_object(fd, header, OBJECT_ENTRY_ARRAY,
                               sizeof(EntryArrayObject) + sizeof(uint64_t), &offset);
    if (r < 0)
        return r;
    EntryArrayObject object = {0};
    object.object.type = OBJECT_ENTRY_ARRAY;
    object.object.size = htole64(sizeof(EntryArrayObject) + sizeof(uint64_t));
    r = pwrite_full(fd, &object, sizeof(object), offset);
    if (r < 0)
        return r;
    uint64_t encoded = htole64(entry_offset);
    r = pwrite_full(fd, &encoded, sizeof(encoded), offset + sizeof(object));
    if (r < 0)
        return r;
    header->n_entry_arrays = htole64(le64toh(header->n_entry_arrays) + 1);
    *ret_offset = offset;
    return 0;
}

static int append_data_entry_reference(int fd, JournalFileHeader *header,
                                       uint64_t data_offset, uint64_t entry_offset) {
    DataObject data;
    int r = pread_full(fd, &data, sizeof(data), data_offset);
    if (r < 0)
        return r;
    if (data.object.type != OBJECT_DATA)
        return -EBADMSG;
    uint64_t n = le64toh(data.n_entries);
    if (n == 0) {
        data.entry_offset = htole64(entry_offset);
        data.n_entries = htole64(1);
        return pwrite_full(fd, &data, sizeof(data), data_offset);
    }

    uint64_t new_array;
    r = append_entry_array(fd, header, entry_offset, &new_array);
    if (r < 0)
        return r;
    uint64_t first_array = le64toh(data.entry_array_offset);
    if (first_array == 0) {
        data.entry_array_offset = htole64(new_array);
    } else {
        uint64_t p = first_array;
        for (;;) {
            EntryArrayObject array;
            r = pread_full(fd, &array, sizeof(array), p);
            if (r < 0)
                return r;
            if (array.object.type != OBJECT_ENTRY_ARRAY)
                return -EBADMSG;
            uint64_t next = le64toh(array.next_entry_array_offset);
            if (next == 0) {
                uint64_t encoded = htole64(new_array);
                r = pwrite_full(fd, &encoded, sizeof(encoded),
                                p + offsetof(EntryArrayObject, next_entry_array_offset));
                if (r < 0)
                    return r;
                break;
            }
            if (next <= p)
                return -EBADMSG;
            p = next;
        }
    }
    data.n_entries = htole64(n + 1);
    return pwrite_full(fd, &data, sizeof(data), data_offset);
}

static int append_global_entry_reference(int fd, JournalFileHeader *header,
                                         uint64_t entry_offset) {
    uint64_t new_array;
    int r = append_entry_array(fd, header, entry_offset, &new_array);
    if (r < 0)
        return r;
    if (new_array > UINT32_MAX)
        return -EFBIG;

    uint64_t first = le64toh(header->entry_array_offset);
    if (first == 0) {
        header->entry_array_offset = htole64(new_array);
    } else {
        uint32_t tail32 = le32toh(header->tail_entry_array_offset);
        if (tail32 == 0)
            return -EBADMSG;
        uint64_t encoded = htole64(new_array);
        r = pwrite_full(fd, &encoded, sizeof(encoded),
                        (uint64_t)tail32 + offsetof(EntryArrayObject, next_entry_array_offset));
        if (r < 0)
            return r;
    }
    header->tail_entry_array_offset = htole32((uint32_t)new_array);
    header->tail_entry_array_n_entries = htole32(1);
    return 0;
}

static uint64_t monotonic_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000) + (uint64_t)ts.tv_nsec / UINT64_C(1000);
}

/* ── rustd_journal_file_open ───────────────────────────────────────────────── */

int rustd_journal_file_open(const char *path) {
    if (!path)
        return -EINVAL;

    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
    if (fd < 0) {
        if (errno != EEXIST)
            return -errno;
        fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -errno;

        JournalFileHeader existing;
        int r = header_read(fd, &existing);
        if (r < 0) {
            close(fd);
            return r;
        }
        if (existing.state != STATE_OFFLINE) {
            close(fd);
            return -EBUSY;
        }
        uint8_t machine[16];
        if (read_id128_file("/etc/machine-id", machine) < 0 ||
            memcmp(machine, existing.machine_id, sizeof(machine)) != 0) {
            close(fd);
            return -ESTALE;
        }
        r = mark_state(fd, STATE_ONLINE);
        if (r < 0) {
            close(fd);
            return r;
        }
        return fd;
    }

    JournalFileHeader header = {0};
    static const uint8_t magic[8] = {'L', 'P', 'K', 'S', 'H', 'H', 'R', 'H'};
    memcpy(header.signature, magic, sizeof(magic));
    header.compatible_flags = htole32(JOURNAL_COMPATIBLE_TAIL_ENTRY_BOOT_ID);
    header.state = STATE_ONLINE;
    header.header_size = htole64(sizeof(header));

    if (random_id128(header.file_id) < 0 ||
        read_id128_file("/etc/machine-id", header.machine_id) < 0 ||
        read_id128_file("/proc/sys/kernel/random/boot_id", header.tail_entry_boot_id) < 0) {
        close(fd);
        unlink(path);
        return -EIO;
    }
    memcpy(header.seqnum_id, header.file_id, sizeof(header.seqnum_id));

    int r = allocate_range(fd, 0, sizeof(header));
    if (r < 0)
        goto fail;
    r = header_write(fd, &header);
    if (r < 0)
        goto fail;

    uint64_t data_table_object;
    r = append_zero_object(fd, &header, OBJECT_DATA_HASH_TABLE,
                           sizeof(ObjectHeader) + DATA_HASH_TABLE_SIZE, &data_table_object);
    if (r < 0)
        goto fail;
    header.data_hash_table_offset = htole64(data_table_object + sizeof(ObjectHeader));
    header.data_hash_table_size = htole64(DATA_HASH_TABLE_SIZE);

    uint64_t field_table_object;
    r = append_zero_object(fd, &header, OBJECT_FIELD_HASH_TABLE,
                           sizeof(ObjectHeader) + FIELD_HASH_TABLE_SIZE, &field_table_object);
    if (r < 0)
        goto fail;
    header.field_hash_table_offset = htole64(field_table_object + sizeof(ObjectHeader));
    header.field_hash_table_size = htole64(FIELD_HASH_TABLE_SIZE);

    r = header_write(fd, &header);
    if (r < 0)
        goto fail;
    if (fdatasync(fd) < 0) {
        r = -errno;
        goto fail;
    }
    return fd;

fail:
    close(fd);
    unlink(path);
    return r;
}

/* ── rustd_journal_file_append ─────────────────────────────────────────────── */

int rustd_journal_file_append(int fd, const SdJournalField *fields, size_t n_fields,
                            uint64_t realtime_usec, uint64_t seqnum) {
    if (fd < 0 || (n_fields > 0 && !fields))
        return -EINVAL;

    JournalFileHeader header;
    int r = header_read(fd, &header);
    if (r < 0)
        return r;
    if (header.state != STATE_ONLINE)
        return -EBUSY;

    DataReference *refs = calloc(n_fields ? n_fields : 1, sizeof(*refs));
    if (!refs)
        return -ENOMEM;

    uint64_t xor_hash = 0;
    for (size_t i = 0; i < n_fields; i++) {
        r = append_data_object(fd, &header, &fields[i], &refs[i]);
        if (r < 0) {
            free(refs);
            return r;
        }
        xor_hash ^= refs[i].hash;
    }

    uint64_t previous_seqnum = le64toh(header.tail_entry_seqnum);
    uint64_t actual_seqnum = seqnum;
    if (actual_seqnum == 0 || actual_seqnum <= previous_seqnum)
        actual_seqnum = previous_seqnum + 1;
    uint64_t monotonic = monotonic_usec();
    uint8_t boot_id[16];
    if (read_id128_file("/proc/sys/kernel/random/boot_id", boot_id) < 0) {
        free(refs);
        return -EIO;
    }

    if (n_fields > (UINT64_MAX - sizeof(EntryObject)) / sizeof(EntryItem)) {
        free(refs);
        return -E2BIG;
    }
    uint64_t entry_size = sizeof(EntryObject) + (uint64_t)n_fields * sizeof(EntryItem);
    uint64_t entry_offset;
    r = append_zero_object(fd, &header, OBJECT_ENTRY, entry_size, &entry_offset);
    if (r < 0) {
        free(refs);
        return r;
    }

    EntryObject entry = {0};
    entry.object.type = OBJECT_ENTRY;
    entry.object.size = htole64(entry_size);
    entry.seqnum = htole64(actual_seqnum);
    entry.realtime = htole64(realtime_usec);
    entry.monotonic = htole64(monotonic);
    memcpy(entry.boot_id, boot_id, sizeof(boot_id));
    entry.xor_hash = htole64(xor_hash);
    r = pwrite_full(fd, &entry, sizeof(entry), entry_offset);
    if (r < 0) {
        free(refs);
        return r;
    }
    for (size_t i = 0; i < n_fields; i++) {
        EntryItem item = {
            .object_offset = htole64(refs[i].offset),
            .hash = htole64(refs[i].hash),
        };
        r = pwrite_full(fd, &item, sizeof(item),
                        entry_offset + sizeof(entry) + i * sizeof(item));
        if (r < 0) {
            free(refs);
            return r;
        }
    }

    for (size_t i = 0; i < n_fields; i++) {
        r = append_data_entry_reference(fd, &header, refs[i].offset, entry_offset);
        if (r < 0) {
            free(refs);
            return r;
        }
    }
    free(refs);

    r = append_global_entry_reference(fd, &header, entry_offset);
    if (r < 0)
        return r;

    uint64_t count = le64toh(header.n_entries) + 1;
    header.n_entries = htole64(count);
    header.tail_entry_seqnum = htole64(actual_seqnum);
    header.tail_entry_realtime = htole64(realtime_usec);
    header.tail_entry_monotonic = htole64(monotonic);
    header.tail_entry_offset = htole64(entry_offset);
    memcpy(header.tail_entry_boot_id, boot_id, sizeof(boot_id));
    if (count == 1) {
        header.head_entry_seqnum = htole64(actual_seqnum);
        header.head_entry_realtime = htole64(realtime_usec);
    }

    r = header_write(fd, &header);
    if (r < 0)
        return r;
    uint64_t used = le64toh(header.header_size) + le64toh(header.arena_size);
    if (used <= (uint64_t)INT64_MAX && ftruncate(fd, (off_t)used) < 0)
        return -errno;
    return 0;
}

/* ── rustd_journal_file_close ──────────────────────────────────────────────── */

int rustd_journal_file_close(int fd) {
    if (fd < 0)
        return -EINVAL;
    JournalFileHeader header;
    int r = header_read(fd, &header);
    if (r < 0) {
        int saved = r;
        close(fd);
        return saved;
    }
    if (header.state == STATE_ONLINE) {
        r = mark_state(fd, STATE_OFFLINE);
        if (r < 0) {
            close(fd);
            return r;
        }
    }
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }
    if (close(fd) < 0)
        return -errno;
    return 0;
}
