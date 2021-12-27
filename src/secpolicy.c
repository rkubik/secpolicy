#include "secpolicy/secpolicy.h"

#include "challenge.h"
#include "comms.h"
#include "peer.h"
#include "strlcpy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
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
    } challenge_create;
    struct {
        bool enable;
        bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                      void *);
        void (*destroy)(secpolicy_challenge_t *, void *);
        void *ctx;
    } challenge_solve;
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

void secpolicy_challenge_create(
    secpolicy_t *policy, bool (*create)(secpolicy_challenge_t *, void *),
    void (*destroy)(secpolicy_challenge_t *, void *),
    bool (*verify)(const secpolicy_challenge_t *, const secpolicy_challenge_t *,
                   void *),
    void *ctx)
{
    if (policy && create && destroy && verify) {
        policy->rules.challenge_create.enable = true;
        policy->rules.challenge_create.create = create;
        policy->rules.challenge_create.destroy = destroy;
        policy->rules.challenge_create.verify = verify;
        policy->rules.challenge_create.ctx = ctx;
    }
}

void secpolicy_challenge_solve(secpolicy_t *policy,
                               bool (*solve)(const secpolicy_challenge_t *,
                                             secpolicy_challenge_t *, void *),
                               void (*destroy)(secpolicy_challenge_t *, void *),
                               void *ctx)
{
    if (policy && solve && destroy) {
        policy->rules.challenge_solve.enable = true;
        policy->rules.challenge_solve.solve = solve;
        policy->rules.challenge_solve.destroy = destroy;
        policy->rules.challenge_solve.ctx = ctx;
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
    challenge_create_ctx_t challenge_create_ctx = {0};
    challenge_solve_ctx_t challenge_solve_ctx = {0};
    comms_t *comms = NULL;

    if (!policy) {
        errno = EINVAL;
        goto done;
    }

    comms = comms_create(sock);
    if (!comms) {
        errno = ENOMEM;
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
        if (policy->rules.perms.mode != peer.perms) {
            local_result |= SECPOLICY_RESULT_PERMS;
        }
    }

    if (policy->rules.cb.enable) {
        if (!policy->rules.cb.verify(&peer, policy->rules.cb.ctx)) {
            local_result |= SECPOLICY_RESULT_CB;
        }
    }

    if (policy->rules.challenge_create.enable) {
        if (!policy->rules.challenge_create.create(
                &challenge_create_ctx.challenge,
                policy->rules.challenge_create.ctx)) {
            goto done;
        }

        if (!challenge_send(sock, &challenge_create_ctx.challenge)) {
            goto done;
        }

        challenge_create_ctx.verify = policy->rules.challenge_create.verify;
        challenge_create_ctx.ctx = policy->rules.challenge_create.ctx;

        comms_on_challenge_response(comms, challenge_response,
                                    &challenge_create_ctx);
    }

    if (policy->rules.challenge_solve.enable) {
        challenge_solve_ctx.solve = policy->rules.challenge_solve.solve;
        challenge_solve_ctx.destroy = policy->rules.challenge_solve.destroy;
        challenge_solve_ctx.ctx = policy->rules.challenge_solve.ctx;

        comms_on_challenge_request(comms, challenge_request,
                                   &challenge_solve_ctx);
    }

    if (!comms_wait(comms, 1)) {
        goto done;
    }

    if (policy->rules.challenge_create.enable) {
        if (!challenge_create_ctx.result) {
            local_result |= SECPOLICY_RESULT_CHALLENGE;
        }
    }

    if (result) {
        *result = local_result;
    }
    ret = 0;
done:
    comms_destroy(comms);

    return ret;
}
