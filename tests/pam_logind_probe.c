/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercise the same PAM open/close path used by a graphical login manager. */

#include <security/pam_appl.h>
#include <stdio.h>

static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)messages;
    (void)data;
    *responses = NULL;
    return count == 0 ? PAM_SUCCESS : PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s USER PAM-CONFDIR\n", argv[0]);
        return 2;
    }

    const struct pam_conv conv = {conversation, NULL};
    pam_handle_t *pamh = NULL;
    int status = pam_start_confdir("probe", argv[1], &conv, argv[2], &pamh);
    printf("pam_start=%d %s\n", status, pam_strerror(pamh, status));
    if (status != PAM_SUCCESS) {
        return status;
    }

    status = pam_open_session(pamh, 0);
    printf("pam_open_session=%d %s\n", status, pam_strerror(pamh, status));
    if (status == PAM_SUCCESS) {
        status = pam_close_session(pamh, 0);
        printf("pam_close_session=%d %s\n", status, pam_strerror(pamh, status));
    }

    int end_status = pam_end(pamh, status);
    printf("pam_end=%d %s\n", end_status, pam_strerror(NULL, end_status));
    return status == PAM_SUCCESS && end_status == PAM_SUCCESS ? 0 : status;
}
