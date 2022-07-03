#ifndef PEER_H
#define PEER_H

#include "secpolicy/secpolicy.h"

#include <stdbool.h>

#define USER_MAX 32
#define CREDS_MAX 64

struct secpolicy_peer {
    int sock;
    pid_t pid;
    char program[PATH_MAX];
    uid_t uid;
    char user[USER_MAX];
    gid_t gid;
    char group[USER_MAX];
    mode_t perms;
    char creds[CREDS_MAX];
};

bool peer_init(int sock, secpolicy_peer_t *peer);

#endif /* PEER_H */
