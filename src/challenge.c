#include "challenge.h"

#include "proto.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#define READ_TIMEOUT_SEC (5)

bool secpolicy_challenge_set_data(secpolicy_challenge_t *challenge,
                                  const uint8_t *data, size_t size)
{
    bool ret = false;

    if (challenge && data && size > 0) {
        challenge->data = malloc(size);
        if (challenge->data) {
            memcpy(challenge->data, data, size);
            challenge->size = size;
            ret = true;
        }
    }

    return ret;
}

const uint8_t *secpolicy_challenge_data(const secpolicy_challenge_t *challenge)
{
    return (challenge ? challenge->data : NULL);
}

size_t secpolicy_challenge_size(const secpolicy_challenge_t *challenge)
{
    return (challenge ? challenge->size : 0);
}

void secpolicy_challenge_free(secpolicy_challenge_t *challenge)
{
    if (challenge) {
        free(challenge->data);
        challenge->data = NULL;
    }
}

bool challenge_send_request(int sock, const secpolicy_challenge_t *challenge)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;

    message.type = MESSAGE_TYPE_CHALLENGE_REQUEST;
    message.version = PROTO_VERSION;
    message.payload_size = challenge->size;

    bytes = write(sock, &message, sizeof(message));
    if (bytes == -1 || (size_t)bytes != sizeof(message)) {
        goto done;
    }

    bytes = write(sock, challenge->data, challenge->size);
    if (bytes == -1 || (size_t)bytes != challenge->size) {
        goto done;
    }

    ret = true;
done:
    return ret;
}

bool challenge_send_response(int sock, const secpolicy_challenge_t *challenge)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;

    message.type = MESSAGE_TYPE_CHALLENGE_RESPONSE;
    message.version = PROTO_VERSION;
    message.payload_size = challenge->size;

    bytes = write(sock, &message, sizeof(message));
    if (bytes == -1 || (size_t)bytes != sizeof(message)) {
        goto done;
    }

    bytes = write(sock, challenge->data, challenge->size);
    if (bytes == -1 || (size_t)bytes != challenge->size) {
        goto done;
    }

    ret = true;
done:
    return ret;
}

bool challenge_receive_request(int sock, secpolicy_challenge_t *challenge)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;

    for (;;) {
        fd_set rfds;
        fd_set efds;
        struct timeval tv;
        int select_ret;

        FD_ZERO(&rfds);
        FD_ZERO(&efds);

        FD_SET(sock, &rfds);
        FD_SET(sock, &efds);

        tv.tv_sec = READ_TIMEOUT_SEC;
        tv.tv_usec = 0;

        select_ret = select(sock + 1, &rfds, NULL, &efds, &tv);
        if (select_ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            goto done;
        }
        else if (select_ret == 0) {
            goto done;
        }
        if (FD_ISSET(sock, &efds)) {
            goto done;
        }
        if (!FD_ISSET(sock, &rfds)) {
            goto done;
        }
        break;
    }
    for (;;) {
        bytes = read(sock, &message, sizeof(message));
        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto done;
        }
        break;
    }
    if ((size_t)bytes != sizeof(message)) {
        goto done;
    }
    if (message.version != PROTO_VERSION) {
        goto done;
    }
    if (message.type != MESSAGE_TYPE_CHALLENGE_REQUEST) {
        goto done;
    }
    if (message.payload_size == 0) {
        goto done;
    }
    challenge->size = message.payload_size;
    challenge->data = malloc(message.payload_size);
    if (!challenge->data) {
        goto done;
    }
    bytes = read(sock, challenge->data, message.payload_size);
    if (bytes == -1 || (size_t)bytes != message.payload_size) {
        goto done;
    }

    ret = true;
done:
    return ret;
}

bool challenge_receive_response(int sock, secpolicy_challenge_t *challenge)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;

    for (;;) {
        fd_set rfds;
        fd_set efds;
        struct timeval tv;
        int select_ret;

        FD_ZERO(&rfds);
        FD_ZERO(&efds);

        FD_SET(sock, &rfds);
        FD_SET(sock, &efds);

        tv.tv_sec = READ_TIMEOUT_SEC;
        tv.tv_usec = 0;

        select_ret = select(sock + 1, &rfds, NULL, &efds, &tv);
        if (select_ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            goto done;
        }
        else if (select_ret == 0) {
            goto done;
        }
        if (FD_ISSET(sock, &efds)) {
            goto done;
        }
        if (!FD_ISSET(sock, &rfds)) {
            goto done;
        }
        break;
    }
    for (;;) {
        bytes = read(sock, &message, sizeof(message));
        if (bytes < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto done;
        }
        break;
    }
    if ((size_t)bytes != sizeof(message)) {
        goto done;
    }
    if (message.version != PROTO_VERSION) {
        goto done;
    }
    if (message.type != MESSAGE_TYPE_CHALLENGE_RESPONSE) {
        goto done;
    }
    if (message.payload_size == 0) {
        goto done;
    }
    challenge->size = message.payload_size;
    challenge->data = malloc(message.payload_size);
    if (!challenge->data) {
        goto done;
    }
    bytes = read(sock, challenge->data, message.payload_size);
    if (bytes == -1 || (size_t)bytes != message.payload_size) {
        goto done;
    }

    ret = true;
done:
    return ret;
}
