/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rustd/manager.h>

#define DEFAULT_CONTROL_SOCKET "/run/rustd/ctl.sock"
#define FRAME_MAX 65536

unsigned rustd_manager_abi_version(void) {
    return 1U;
}

struct rustd_manager {
    int fd;
};

static int connect_control_socket(void) {
    const char *path = getenv("RUSTD_CONTROL_SOCKET");
    struct sockaddr_un address;
    size_t length;
    int fd;

    if (!path || !*path)
        path = DEFAULT_CONTROL_SOCKET;
    length = strlen(path);
    if (length >= sizeof(address.sun_path))
        return -ENAMETOOLONG;
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, length + 1U);
    if (connect(fd, (struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1U)) < 0) {
        int saved = -errno;
        close(fd);
        return saved;
    }
    return fd;
}

static int transact(rustd_manager *manager, const char *request, char **response) {
    char buffer[FRAME_MAX];
    ssize_t sent;
    ssize_t received;

    if (!manager || manager->fd < 0 || !request || !response)
        return -EINVAL;
    *response = NULL;
    sent = send(manager->fd, request, strlen(request), MSG_NOSIGNAL);
    if (sent < 0)
        return -errno;
    received = recv(manager->fd, buffer, sizeof(buffer) - 1, 0);
    if (received < 0)
        return -errno;
    buffer[received] = '\0';
    *response = strdup(buffer);
    return *response ? 0 : -ENOMEM;
}

int rustd_manager_connect(rustd_manager **ret) {
    rustd_manager *manager;
    int fd;

    if (!ret)
        return -EINVAL;
    fd = connect_control_socket();
    if (fd < 0)
        return fd;
    manager = calloc(1, sizeof(*manager));
    if (!manager) {
        close(fd);
        return -ENOMEM;
    }
    manager->fd = fd;
    *ret = manager;
    return 0;
}

void rustd_manager_unref(rustd_manager *manager) {
    if (!manager)
        return;
    if (manager->fd >= 0)
        close(manager->fd);
    free(manager);
}

static int simple_command(rustd_manager *manager, const char *request) {
    char *response = NULL;
    int result = transact(manager, request, &response);
    if (result < 0)
        return result;
    if (strstr(response, "\"ok\":false") || strstr(response, "\"err\""))
        result = -EIO;
    free(response);
    return result;
}

int rustd_manager_list_units(rustd_manager *manager, char **out) {
    char *response = NULL;
    int result;

    if (!out)
        return -EINVAL;
    result = transact(manager, "{\"cmd\":\"list-units\"}\n", &response);
    if (result < 0)
        return result;
    *out = response;
    return 0;
}

int rustd_manager_start_unit(rustd_manager *manager, const char *unit) {
    char request[512];
    if (!unit)
        return -EINVAL;
    snprintf(request, sizeof(request),
             "{\"cmd\":\"start\",\"args\":{\"unit\":\"%s\"}}\n", unit);
    return simple_command(manager, request);
}

int rustd_manager_stop_unit(rustd_manager *manager, const char *unit) {
    char request[512];
    if (!unit)
        return -EINVAL;
    snprintf(request, sizeof(request),
             "{\"cmd\":\"stop\",\"args\":{\"unit\":\"%s\"}}\n", unit);
    return simple_command(manager, request);
}

int rustd_manager_restart_unit(rustd_manager *manager, const char *unit) {
    char request[512];
    if (!unit)
        return -EINVAL;
    snprintf(request, sizeof(request),
             "{\"cmd\":\"restart\",\"args\":{\"unit\":\"%s\"}}\n", unit);
    return simple_command(manager, request);
}

int rustd_manager_reload_unit(rustd_manager *manager, const char *unit) {
    char request[512];
    if (!unit)
        return -EINVAL;
    snprintf(request, sizeof(request),
             "{\"cmd\":\"reload\",\"args\":{\"unit\":\"%s\"}}\n", unit);
    return simple_command(manager, request);
}

int rustd_manager_daemon_reload(rustd_manager *manager) {
    return simple_command(manager, "{\"cmd\":\"daemon-reload\"}\n");
}

int rustd_manager_is_active(rustd_manager *manager, const char *unit, int *active) {
    char request[512];
    char *response = NULL;
    int result;

    if (!unit || !active)
        return -EINVAL;
    snprintf(request, sizeof(request),
             "{\"cmd\":\"is-active\",\"args\":{\"unit\":\"%s\"}}\n", unit);
    result = transact(manager, request, &response);
    if (result < 0)
        return result;
    *active = strstr(response, "\"active\":true") || strstr(response, "\"data\":true") ? 1 : 0;
    free(response);
    return 0;
}
