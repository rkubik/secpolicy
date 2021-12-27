#include "challenge.h"
#include "proto.h"

bool challenge_send(int sock, const secpolicy_challenge_t *challenge)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;

    if (!challenge->data || challenge->size == 0) {
        goto done;
    }

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

void challenge_response(int sock, const secpolicy_challenge_t *response,
                        challenge_create_ctx_t *ctx)
{
    ctx->result = ctx->verify(&ctx->challenge, response, ctx->ctx);
}

bool challenge_request(int sock, const secpolicy_challenge_t *challenge,
                       challenge_solve_ctx_t *ctx)
{
    bool ret = false;
    message_t message;
    ssize_t bytes;
    secpolicy_challenge_t response = {0};

    if (!ctx->solve(challenge, &response, ctx->ctx)) {
        goto done;
    }

    message.type = MESSAGE_TYPE_CHALLENGE_RESPONSE;
    message.version = PROTO_VERSION;
    message.payload_size = response.size;

    bytes = write(sock, &message, sizeof(message));
    if (bytes == -1 || (size_t)bytes != sizeof(message)) {
        goto done;
    }

    bytes = write(sock, response.data, response.size);
    if (bytes == -1 || (size_t)bytes != response.size) {
        goto done;
    }

    ret = true;
done:
    ctx->destroy(&response, ctx->ctx);

    return ret;
}
