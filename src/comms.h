#ifndef COMMS_H
#define COMMS_H

#include "challenge.h"

#include <stdbool.h>
#include <time.h>

typedef struct {
    int sock;
    struct {
        void (*challenge_response)(int sock,
                                   const secpolicy_challenge_t *response,
                                   challenge_create_ctx_t *ctx);
        void *challenge_response_ctx;
        bool (*challenge_request)(int sock,
                                  const secpolicy_challenge_t *challenge,
                                  challenge_solve_ctx_t *ctx);
        void *challenge_request_ctx;
    } handlers;
} comms_t;

comms_t *comms_create(int sock);
void comms_destroy(comms_t *comms);
bool comms_wait(comms_t *comms, time_t seconds);
void comms_on_challenge_response(
    comms_t *comms,
    void (*handler)(int sock, const secpolicy_challenge_t *response,
                    challenge_create_ctx_t *ctx),
    void *ctx);
void comms_on_challenge_request(
    comms_t *comms,
    bool (*handler)(int sock, const secpolicy_challenge_t *challenge,
                    challenge_solve_ctx_t *ctx),
    void *ctx);

#endif /* COMMS_H */
