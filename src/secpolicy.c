#include "secpolicy/secpolicy.h"

#include "peer.h"
#include "proto.h"
#include "strlcpy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    struct {
        bool enable;
        uid_t uid;
        gid_t gid;
    } peer;
    struct {
        bool enable;
        char user[USER_MAX];
        char group[USER_MAX];
    } peer_name;
    struct {
        bool enable;
        char creds[CREDS_MAX];
    } peer_creds;
    struct {
        bool enable;
        bool (*create)(secpolicy_challenge_t *, void *);
        void (*destroy)(secpolicy_challenge_t *, void *);
        bool (*verify)(const secpolicy_challenge_t *,
                       const secpolicy_challenge_t *, void *);
        bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                      void *);
        void *ctx;
    } challenge;
    struct {
        bool enable;
        char path[PATH_MAX];
    } program;
    struct {
        bool enable;
        mode_t mode;
    } perms;
    struct {
        bool enable;
        bool (*verify)(const secpolicy_peer_t *, void *);
        void *ctx;
    } cb;
} policy_rules_t;

typedef struct secpolicy {
    policy_rules_t rules;
} secpolicy_t;

secpolicy_t *secpolicy_create(void)
{
    return calloc(1, sizeof(secpolicy_t));
}

void secpolicy_destroy(secpolicy_t *policy)
{
    free(policy);
}

void secpolicy_perms(secpolicy_t *policy, mode_t perms)
{
    if (policy) {
        policy->rules.perms.enable = true;
        policy->rules.perms.mode = perms;
    }
}

void secpolicy_challenge(secpolicy_t *policy,
                         bool (*create)(secpolicy_challenge_t *, void *),
                         void (*destroy)(secpolicy_challenge_t *, void *),
                         bool (*verify)(const secpolicy_challenge_t *,
                                        const secpolicy_challenge_t *, void *),
                         bool (*solve)(const secpolicy_challenge_t *,
                                       secpolicy_challenge_t *, void *),
                         void *ctx)
{
    if (policy) {
        policy->rules.challenge.enable = true;
        policy->rules.challenge.create = create;
        policy->rules.challenge.destroy = destroy;
        policy->rules.challenge.verify = verify;
        policy->rules.challenge.solve = solve;
        policy->rules.challenge.ctx = ctx;
    }
}

void secpolicy_peer(secpolicy_t *policy, uid_t uid, gid_t gid)
{
    if (policy) {
        policy->rules.peer.enable = true;
        policy->rules.peer.uid = uid;
        policy->rules.peer.gid = gid;
    }
}

void secpolicy_peer_name(secpolicy_t *policy, const char *user,
                         const char *group)
{
    if (policy && user && group) {
        policy->rules.peer_name.enable = true;
        safe_strcpy(policy->rules.peer_name.user,
                    sizeof(policy->rules.peer_name.user), user);
        safe_strcpy(policy->rules.peer_name.group,
                    sizeof(policy->rules.peer_name.group), group);
    }
}

void secpolicy_peer_creds(secpolicy_t *policy, const char *creds)
{
    if (policy && creds) {
        policy->rules.peer_creds.enable = true;
        safe_strcpy(policy->rules.peer_creds.creds,
                    sizeof(policy->rules.peer_creds.creds), creds);
    }
}

void secpolicy_program(secpolicy_t *policy, const char *program)
{
    if (policy && program) {
        policy->rules.program.enable = true;
        safe_strcpy(policy->rules.program.path,
                    sizeof(policy->rules.program.path), program);
    }
}

void secpolicy_cb(secpolicy_t *policy,
                  bool (*verify)(const secpolicy_peer_t *, void *), void *ctx)
{
    if (policy && verify) {
        policy->rules.cb.enable = true;
        policy->rules.cb.verify = verify;
        policy->rules.cb.ctx = ctx;
    }
}

int secpolicy_apply(secpolicy_t *policy, int sock, secpolicy_result_t *result)
{
    int ret = -1;
    secpolicy_peer_t peer = {0};
    secpolicy_result_t local_result = 0;

    if (!policy) {
        errno = EINVAL;
        goto done;
    }

    if (!peer_init(sock, &peer)) {
        errno = EBADF;
        goto done;
    }

    if (policy->rules.peer.enable) {
        if (policy->rules.peer.uid != peer.uid ||
            policy->rules.peer.gid != peer.gid) {
            local_result |= SECPOLICY_RESULT_PEER;
        }
    }

    if (policy->rules.peer_name.enable) {
        if (strncmp(policy->rules.peer_name.user, peer.user,
                    sizeof(peer.user)) ||
            strncmp(policy->rules.peer_name.group, peer.group,
                    sizeof(peer.group))) {
            local_result |= SECPOLICY_RESULT_PEER_NAME;
        }
    }

    if (policy->rules.peer_creds.enable) {
        if (strncmp(policy->rules.peer_creds.creds, peer.creds,
                    sizeof(peer.creds))) {
            local_result |= SECPOLICY_RESULT_PEER_CREDS;
        }
    }

    if (policy->rules.program.enable) {
        if (strncmp(policy->rules.program.path, peer.program,
                    sizeof(peer.program))) {
            local_result |= SECPOLICY_RESULT_PROGRAM;
        }
    }

    if (policy->rules.perms.enable) {
        if ((policy->rules.perms.mode & 0777) != (peer.perms & 0777)) {
            local_result |= SECPOLICY_RESULT_PERMS;
        }
    }

    if (policy->rules.cb.enable) {
        if (!policy->rules.cb.verify(&peer, policy->rules.cb.ctx)) {
            local_result |= SECPOLICY_RESULT_CB;
        }
    }

    if (policy->rules.challenge.enable) {
        secpolicy_challenge_t challenge;
        secpolicy_challenge_t response;
        bool sent_challenge = false;
        bool sent_response = false;
        bool received_request = false;
        bool solved = false;
        for (;;) {
            fd_set rfds;
            fd_set wfds;
            fd_set efds;
            struct timeval tv;
            int select_ret;

            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            FD_ZERO(&efds);

            FD_SET(sock, &rfds);
            FD_SET(sock, &wfds);
            FD_SET(sock, &efds);

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            select_ret = select(sock + 1, &rfds, &wfds, &efds, &tv);
            if (select_ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            else if (select_ret == 0) {
                break;
            }
            if (FD_ISSET(sock, &efds)) {
                break;
            }
            if (FD_ISSET(sock, &wfds)) {
                if (!sent_challenge && policy->rules.challenge.create) {
                    message_t message;
                    ssize_t bytes;

                    if (!policy->rules.challenge.create(
                            &challenge, policy->rules.challenge.ctx)) {
                        goto done;
                    }

                    message.type = MESSAGE_TYPE_CHALLENGE_REQUEST;
                    message.version = PROTO_VERSION;
                    message.payload_size = challenge.size;

                    bytes = write(sock, &message, sizeof(message));
                    if (bytes == -1 || (size_t)bytes != sizeof(message)) {
                        break;
                    }

                    bytes = write(sock, challenge.data, challenge.size);
                    if (bytes == -1 || (size_t)bytes != challenge.size) {
                        break;
                    }

                    sent_challenge = true;
                }

                if (!sent_response && received_request) {
                    message_t message;
                    ssize_t bytes;

                    message.type = MESSAGE_TYPE_CHALLENGE_RESPONSE;
                    message.version = PROTO_VERSION;
                    message.payload_size = response.size;

                    bytes = write(sock, &message, sizeof(message));
                    if (bytes == -1 || (size_t)bytes != sizeof(message)) {
                        break;
                    }

                    bytes = write(sock, response.data, response.size);
                    if (bytes == -1 || (size_t)bytes != response.size) {
                        break;
                    }

                    sent_response = true;
                    solved = true;
                    break;
                }
            }
            if (FD_ISSET(sock, &rfds)) {
                message_t message;
                ssize_t bytes;

                bytes = read(sock, &message, sizeof(message));
                if (bytes == -1 || (size_t)bytes != sizeof(message)) {
                    break;
                }
                if (message.version != PROTO_VERSION) {
                    break;
                }
                if (message.type == MESSAGE_TYPE_CHALLENGE_RESPONSE) {
                    secpolicy_challenge_t message_response;

                    do {
                        if (message.payload_size == 0) {
                            break;
                        }

                        message_response.size = message.payload_size;
                        message_response.data = malloc(message.payload_size);
                        if (!message_response.data) {
                            break;
                        }

                        bytes = read(sock, message_response.data,
                                     message.payload_size);
                        if (bytes == -1 ||
                            (size_t)bytes != message.payload_size) {
                            break;
                        }

                        if (!solved) {
                            if (!policy->rules.challenge.verify(
                                    &challenge, &message_response,
                                    policy->rules.challenge.ctx)) {
                                break;
                            }

                            solved = true;
                        }
                    } while (0);

                    free(response.data);

                    if (solved) {
                        break;
                    }
                }
                else if (message.type == MESSAGE_TYPE_CHALLENGE_REQUEST) {
                    secpolicy_challenge_t request_challenge;

                    do {
                        if (message.payload_size == 0) {
                            break;
                        }

                        request_challenge.size = message.payload_size;
                        request_challenge.data = malloc(message.payload_size);
                        if (!request_challenge.data) {
                            break;
                        }

                        bytes = read(sock, request_challenge.data,
                                     message.payload_size);
                        if (bytes == -1 ||
                            (size_t)bytes != message.payload_size) {
                            break;
                        }

                        if (!received_request) {
                            if (!policy->rules.challenge.solve(
                                    &request_challenge, &response,
                                    policy->rules.challenge.ctx)) {
                                break;
                            }
                            received_request = true;
                        }
                    } while (0);

                    free(request_challenge.data);

                    if (!received_request) {
                        break;
                    }
                }
            }
        }

        if (policy->rules.challenge.destroy) {
            policy->rules.challenge.destroy(&challenge,
                                            policy->rules.challenge.ctx);
        }

        free(response.data);

        if (!solved) {
            local_result |= SECPOLICY_RESULT_CHALLENGE;
        }
    }

    if (result) {
        *result = local_result;
    }
    ret = 0;
done:
    return ret;
}
