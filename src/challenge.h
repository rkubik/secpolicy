#ifndef CHALLENGE_H
#define CHALLENGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct secpolicy_challenge {
    uint8_t *data;
    size_t size;
} secpolicy_challenge_t;

void secpolicy_challenge_free(secpolicy_challenge_t *challenge);
bool challenge_send_request(int sock, const secpolicy_challenge_t *challenge);
bool challenge_send_response(int sock, const secpolicy_challenge_t *challenge);
bool challenge_receive_request(int sock, secpolicy_challenge_t *challenge);
bool challenge_receive_response(int sock, secpolicy_challenge_t *challenge);

#endif /* CHALLENGE_H */
