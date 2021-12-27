#include "secpolicy/secpolicy.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define die(s)                                                                 \
    {                                                                          \
        perror(s);                                                             \
        exit(1);                                                               \
    }

static int _create_client(const char *path)
{
    int sock;
    struct sockaddr_un name;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        die("socket");
    }

    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, path, sizeof(name.sun_path));

    if (connect(sock, (const struct sockaddr *)&name, sizeof(name))) {
        die("bind");
    }

    return sock;
}

static bool _solve_challenge(const secpolicy_challenge_t *challenge,
                             secpolicy_challenge_t *response, void *ctx)
{
    bool ret = false;

    response->size = challenge->size;
    response->data = malloc(challenge->size);
    if (!response->data) {
        goto done;
    }

    for (size_t i = 0; i < challenge->size; i++) {
        response->data[i] = (challenge->data[i] << 1);
    }

    ret = true;
done:
    return ret;
}

static void _free_challenge(secpolicy_challenge_t *challenge, void *ctx)
{
    free(challenge->data);
}

int main()
{
    int sock;
    secpolicy_t *policy;
    secpolicy_result_t result;

    sock = _create_client("test.sock");

    policy = secpolicy_create();
    if (!policy) {
        die("secpolicy_create");
    }

    secpolicy_challenge_solve(policy, _solve_challenge, _free_challenge, NULL);

    if (secpolicy_apply(policy, sock, &result)) {
        die("secpolicy_apply");
    }
    if (result != 0) {
        fprintf(stderr, "Security policy failed: 0x%" PRIx64 "\n", result);
        (void)close(sock);
        exit(1);
    }

    printf("Server verified: %d\n", sock);

    (void)close(sock);

    secpolicy_destroy(policy);

    return 0;
}
