#include "secpolicy/secpolicy.h"

#include "challenge.h"
#include "peer.h"
#include "proto.h"
#include "strlcpy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    struct {
        bool enable;
        uid_t value;
    } uid;
    struct {
        bool enable;
        gid_t value;
    } gid;
    struct {
        bool enable;
        char name[USER_MAX];
    } user;
    struct {
        bool enable;
        char name[USER_MAX];
    } group;
    struct {
        bool enable;
        char name[CREDS_MAX];
    } creds;
    struct {
        bool enable;
        bool (*create)(secpolicy_challenge_t *, void *);
        bool (*verify)(const secpolicy_challenge_t *,
                       const secpolicy_challenge_t *, void *);
        bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                      void *);
        void *ctx;
    } challenge_send;
    struct {
        bool enable;
        bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                      void *);
        void *ctx;
    } challenge_receive;
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
        bool (*func)(const secpolicy_peer_t *, void *);
        void *ctx;
    } callback;
} policy_rules_t;

typedef struct secpolicy {
    policy_rules_t rules;
} secpolicy_t;

static bool _challenge(secpolicy_t *policy, int sock, bool *result);

secpolicy_t *secpolicy_create(void)
{
    return calloc(1, sizeof(secpolicy_t));
}

void secpolicy_destroy(secpolicy_t *policy)
{
    free(policy);
}

void secpolicy_rule_perms(secpolicy_t *policy, mode_t perms)
{
    if (policy) {
        policy->rules.perms.enable = true;
        policy->rules.perms.mode = perms;
    }
}

void secpolicy_rule_challenge_send(
    secpolicy_t *policy, bool (*create)(secpolicy_challenge_t *, void *),
    bool (*verify)(const secpolicy_challenge_t *, const secpolicy_challenge_t *,
                   void *),
    void *ctx)
{
    if (policy && create && verify) {
        policy->rules.challenge_send.enable = true;
        policy->rules.challenge_send.create = create;
        policy->rules.challenge_send.verify = verify;
        policy->rules.challenge_send.ctx = ctx;
    }
}

void secpolicy_rule_challenge_receive(
    secpolicy_t *policy,
    bool (*solve)(const secpolicy_challenge_t *, secpolicy_challenge_t *,
                  void *),
    void *ctx)
{
    if (policy && solve) {
        policy->rules.challenge_receive.enable = true;
        policy->rules.challenge_receive.solve = solve;
        policy->rules.challenge_receive.ctx = ctx;
    }
}

void secpolicy_rule_uid(secpolicy_t *policy, uid_t uid)
{
    if (policy) {
        policy->rules.uid.enable = true;
        policy->rules.uid.value = uid;
    }
}

void secpolicy_rule_gid(secpolicy_t *policy, gid_t gid)
{
    if (policy) {
        policy->rules.gid.enable = true;
        policy->rules.gid.value = gid;
    }
}

void secpolicy_rule_user(secpolicy_t *policy, const char *user)
{
    if (policy && user) {
        policy->rules.user.enable = true;
        safe_strcpy(policy->rules.user.name, sizeof(policy->rules.user.name),
                    user);
    }
}

void secpolicy_rule_group(secpolicy_t *policy, const char *group)
{
    if (policy && group) {
        policy->rules.group.enable = true;
        safe_strcpy(policy->rules.group.name, sizeof(policy->rules.group.name),
                    group);
    }
}

void secpolicy_rule_creds(secpolicy_t *policy, const char *creds)
{
    if (policy && creds) {
        policy->rules.creds.enable = true;
        safe_strcpy(policy->rules.creds.name, sizeof(policy->rules.creds.name),
                    creds);
    }
}

void secpolicy_rule_program(secpolicy_t *policy, const char *program)
{
    if (policy && program) {
        policy->rules.program.enable = true;
        safe_strcpy(policy->rules.program.path,
                    sizeof(policy->rules.program.path), program);
    }
}

void secpolicy_rule_callback(secpolicy_t *policy,
                             bool (*func)(const secpolicy_peer_t *, void *),
                             void *ctx)
{
    if (policy && func) {
        policy->rules.callback.enable = true;
        policy->rules.callback.func = func;
        policy->rules.callback.ctx = ctx;
    }
}

int secpolicy_apply(secpolicy_t *policy, int sock, secpolicy_result_t *result)
{
    int ret = -1;
    secpolicy_peer_t peer = {0};
    secpolicy_result_t local_result = 0;
    bool challenge_result;

    if (!policy) {
        errno = EINVAL;
        goto done;
    }

    if (!peer_init(sock, &peer)) {
        errno = EBADF;
        goto done;
    }

    if (policy->rules.uid.enable) {
        if (policy->rules.uid.value != peer.uid) {
            local_result |= SECPOLICY_RESULT_UID;
        }
    }

    if (policy->rules.gid.enable) {
        if (policy->rules.gid.value != peer.gid) {
            local_result |= SECPOLICY_RESULT_GID;
        }
    }

    if (policy->rules.user.enable) {
        if (strcmp(policy->rules.user.name, peer.user)) {
            local_result |= SECPOLICY_RESULT_USER;
        }
    }

    if (policy->rules.group.enable) {
        if (strcmp(policy->rules.group.name, peer.group)) {
            local_result |= SECPOLICY_RESULT_GROUP;
        }
    }

    if (policy->rules.creds.enable) {
        if (strcmp(policy->rules.creds.name, peer.creds)) {
            local_result |= SECPOLICY_RESULT_CREDS;
        }
    }

    if (policy->rules.program.enable) {
        if (strcmp(policy->rules.program.path, peer.program)) {
            local_result |= SECPOLICY_RESULT_PROGRAM;
        }
    }

    if (policy->rules.perms.enable) {
        if (policy->rules.perms.mode != peer.perms) {
            local_result |= SECPOLICY_RESULT_PERMS;
        }
    }

    if (policy->rules.callback.enable) {
        if (!policy->rules.callback.func(&peer, policy->rules.callback.ctx)) {
            local_result |= SECPOLICY_RESULT_CALLBACK;
        }
    }

    if (!_challenge(policy, sock, &challenge_result)) {
        goto done;
    }

    if (!challenge_result) {
        local_result |= SECPOLICY_RESULT_CHALLENGE;
    }

    if (result) {
        *result = local_result;
    }

    ret = 0;
done:
    return ret;
}

static bool _challenge(secpolicy_t *policy, int sock, bool *result)
{
    bool ret = false;
    bool local_result = true;
    secpolicy_challenge_t send_challenge = {0};
    secpolicy_challenge_t send_answer = {0};
    secpolicy_challenge_t receive_challenge = {0};
    secpolicy_challenge_t receive_answer = {0};

    if (policy->rules.challenge_send.enable) {
        if (!policy->rules.challenge_send.create(
                &send_challenge, policy->rules.challenge_send.ctx)) {
            goto done;
        }

        if (!challenge_send_request(sock, &send_challenge)) {
            goto done;
        }
    }

    if (policy->rules.challenge_receive.enable) {
        if (!challenge_receive_request(sock, &receive_challenge)) {
            goto done;
        }

        if (!policy->rules.challenge_receive.solve(
                &receive_challenge, &receive_answer,
                policy->rules.challenge_receive.ctx)) {
            goto done;
        }

        if (!challenge_send_response(sock, &receive_answer)) {
            goto done;
        }
    }

    if (policy->rules.challenge_send.enable) {
        if (!challenge_receive_response(sock, &send_answer)) {
            goto done;
        }

        local_result = policy->rules.challenge_send.verify(
            &send_challenge, &send_answer, policy->rules.challenge_send.ctx);
    }

    ret = true;
done:
    *result = local_result;

    secpolicy_challenge_free(&send_challenge);
    secpolicy_challenge_free(&send_answer);
    secpolicy_challenge_free(&receive_challenge);
    secpolicy_challenge_free(&receive_answer);

    return ret;
}
