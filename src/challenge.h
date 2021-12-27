#ifndef CHALLENGE_H
#define CHALLENGE_H

#include "secpolicy/secpolicy.h"

#include <stdbool.h>

typedef struct {
    secpolicy_challenge_t challenge;
    bool (*verify)(const secpolicy_challenge_t *, const secpolicy_challenge_t *,
                   void *);
    void *ctx;
    bool result;
} challenge_create_ctx_t;

typedef struct {
    bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                  void *);
    void (*destroy)(secpolicy_challenge_t *, void *);
    void *ctx;
} challenge_solve_ctx_t;

bool challenge_send(int sock, const secpolicy_challenge_t *challenge);
void challenge_response(int sock, const secpolicy_challenge_t *response,
                        challenge_create_ctx_t *ctx);
bool challenge_request(int sock, const secpolicy_challenge_t *challenge,
                       challenge_solve_ctx_t *ctx);

#endif /* CHALLENGE_H */
