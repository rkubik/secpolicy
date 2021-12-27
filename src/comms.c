#include "comms.h"
#include "proto.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>

comms_t *comms_create(int sock)
{
    comms_t *comms;

    comms = calloc(1, sizeof(*comms));
    if (comms) {
        comms->sock = sock;
    }

    return comms;
}

void comms_destroy(comms_t *comms)
{
    free(comms);
}

void comms_on_challenge_response(comms_t *comms,
                                 void (*handler)(int,
                                                 const secpolicy_challenge_t *,
                                                 challenge_create_ctx_t *),
                                 void *ctx)
{
    if (comms) {
        comms->handlers.challenge_response = handler;
        comms->handlers.challenge_response_ctx = ctx;
    }
}

void comms_on_challenge_request(comms_t *comms,
                                bool (*handler)(int,
                                                const secpolicy_challenge_t *,
                                                challenge_solve_ctx_t *),
                                void *ctx)
{
    if (comms) {
        comms->handlers.challenge_request = handler;
        comms->handlers.challenge_request_ctx = ctx;
    }
}

bool comms_wait(comms_t *comms, time_t seconds)
{
    bool ret = false;

    if (!comms) {
        goto done;
    }

    if (!comms->handlers.challenge_request &&
        !comms->handlers.challenge_response) {
        ret = true;
        goto done;
    }

    for (;;) {
        fd_set rfds;
        fd_set efds;
        struct timeval tv;
        int select_ret;

        FD_ZERO(&rfds);
        FD_ZERO(&efds);

        FD_SET(comms->sock, &rfds);
        FD_SET(comms->sock, &efds);

        tv.tv_sec = seconds;
        tv.tv_usec = 0;

        select_ret = select(comms->sock + 1, &rfds, NULL, &efds, &tv);
        if (select_ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        else if (select_ret == 0) {
            ret = true;
            break;
        }
        if (FD_ISSET(comms->sock, &efds)) {
            break;
        }
        if (FD_ISSET(comms->sock, &rfds)) {
            message_t message;
            ssize_t bytes;

            bytes = read(comms->sock, &message, sizeof(message));
            if (bytes == 0) {
                ret = true;
                break;
            }
            else if (bytes == -1 || (size_t)bytes != sizeof(message)) {
                break;
            }

            if (message.version != PROTO_VERSION) {
                break;
            }
            if (message.type == MESSAGE_TYPE_CHALLENGE_RESPONSE) {
                secpolicy_challenge_t response;

                if (message.payload_size == 0) {
                    break;
                }

                response.size = message.payload_size;
                response.data = malloc(message.payload_size);
                if (!response.data) {
                    break;
                }

                bytes = read(comms->sock, response.data, message.payload_size);
                if (bytes == -1 || (size_t)bytes != message.payload_size) {
                    break;
                }

                if (comms->handlers.challenge_response) {
                    comms->handlers.challenge_response(
                        comms->sock, &response,
                        comms->handlers.challenge_response_ctx);
                }
            }
            else if (message.type == MESSAGE_TYPE_CHALLENGE_REQUEST) {
                secpolicy_challenge_t challenge;

                if (message.payload_size == 0) {
                    break;
                }

                challenge.size = message.payload_size;
                challenge.data = malloc(message.payload_size);
                if (!challenge.data) {
                    break;
                }

                bytes = read(comms->sock, challenge.data, message.payload_size);
                if (bytes == -1 || (size_t)bytes != message.payload_size) {
                    break;
                }

                if (comms->handlers.challenge_request) {
                    if (!comms->handlers.challenge_request(
                            comms->sock, &challenge,
                            comms->handlers.challenge_request_ctx)) {
                        break;
                    }
                }
            }
        }
    }

done:
    return ret;
}
