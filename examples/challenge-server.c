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

static int _create_server(const char *path)
{
    int sock;
    struct sockaddr_un name;

    if (unlink(path)) {
        if (errno != ENOENT) {
            die("unlink");
        }
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        die("socket");
    }

    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, path, sizeof(name.sun_path));

    if (bind(sock, (const struct sockaddr *)&name, sizeof(name))) {
        die("bind");
    }

    if (listen(sock, 1)) {
        die("listen");
    }

    return sock;
}

static bool _create_challenge(secpolicy_challenge_t *challenge, void *ctx)
{
    bool ret = false;
    const size_t size = 10;
    uint8_t data[size];

    memset(data, 5, size);

    if (!secpolicy_challenge_set_data(challenge, data, size)) {
        goto done;
    }

    ret = true;
done:

    return ret;
}

static bool _verify_challenge(const secpolicy_challenge_t *challenge,
                              const secpolicy_challenge_t *response, void *ctx)
{
    bool ret = false;

    if (secpolicy_challenge_size(challenge) !=
        secpolicy_challenge_size(response)) {
        goto done;
    }

    for (size_t i = 0; i < secpolicy_challenge_size(challenge); i++) {
        if (secpolicy_challenge_data(response)[i] !=
            (secpolicy_challenge_data(challenge)[i] << 1)) {
            goto done;
        }
    }

    ret = true;
done:
    return ret;
}

int main()
{
    int sock;
    int client;
    secpolicy_t *policy;
    secpolicy_result_t result;

    sock = _create_server("test.sock");

    policy = secpolicy_create();
    if (!policy) {
        die("secpolicy_create");
    }

    secpolicy_rule_challenge_send(policy, _create_challenge, _verify_challenge,
                                  NULL);

    client = accept(sock, NULL, NULL);
    if (client == -1) {
        die("accept");
    }

    if (secpolicy_apply(policy, client, &result)) {
        die("secpolicy_apply");
    }
    if (result != 0) {
        fprintf(stderr, "Security policy failed: 0x%" PRIx64 "\n", result);
    }
    else {
        printf("Client verified: %d\n", client);
    }

    (void)close(client);
    (void)close(sock);

    secpolicy_destroy(policy);

    return 0;
}
