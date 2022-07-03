#include "secpolicy/secpolicy.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
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
    struct statvfs stat;
    if (statvfs(secpolicy_peer_program(peer), &stat)) {
        die("statvfs");
    }
    /* Only connect if the peer's executable path resides on a filesystem that
     * is mounted read-only */
    return (stat.f_flag & ST_RDONLY);
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

    secpolicy_rule_uid(policy, 1000);
    secpolicy_rule_gid(policy, 1000);
    secpolicy_rule_user(policy, "admin");
    secpolicy_rule_group(policy, "root");
    secpolicy_rule_perms(policy, S_IRUSR | S_IXUSR | S_IWUSR);
    secpolicy_rule_program(policy, "/usr/bin/socat");
    secpolicy_rule_callback(policy, _verify_peer, NULL);
    secpolicy_rule_creds(policy, "unconfined");

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
