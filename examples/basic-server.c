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

static bool _verify_peer(const secpolicy_peer_t *peer, void *ctx)
{
    /**
     * Additional user security checks.
     *
     * - Verify that the program executable is signed by a trusted vendor
     */
    printf("Security policy callback for <Client process=%s(%d) user=%s(%d) "
           "group=%s(%d) perms=%3o creds=%s>\n",
           peer->program, peer->pid, peer->user, peer->uid, peer->group,
           peer->gid, peer->perms, peer->creds);
    return true;
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

    /* Client should be running as user id 1000 and group id 1001 */
    secpolicy_peer(policy, 1000, 1001);
    /* Client should be running as user "admin" and group "db" */
    secpolicy_peer_name(policy, "admin", "db");
    /* Socket path should have the following perms */
    secpolicy_perms(policy, S_IRUSR | S_IXUSR | S_IWUSR);
    /* Client process should be running with the following executable */
    secpolicy_program(policy, "/usr/bin/socat");
    /* Client should pass additional security checks */
    secpolicy_cb(policy, _verify_peer, NULL);

    client = accept(sock, NULL, NULL);
    if (client == -1) {
        die("accept");
    }

    if (secpolicy_apply(policy, client, &result)) {
        die("secpolicy_apply");
    }
    if (result != 0) {
        fprintf(stderr, "Security policy failed: 0x%" PRIx64 "\n", result);
        (void)close(client);
        exit(1);
    }

    printf("Client verified: %d\n", client);

    (void)close(client);
    (void)close(sock);

    secpolicy_destroy(policy);

    return 0;
}
