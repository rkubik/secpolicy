#ifndef PEER_H
#define PEER_H

#include "secpolicy/secpolicy.h"

#include <stdbool.h>

bool peer_init(int sock, secpolicy_peer_t *peer);

#endif /* PEER_H */
