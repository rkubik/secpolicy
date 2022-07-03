#include "peer.h"
#include "proc.h"
#include "user.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

bool peer_init(int sock, secpolicy_peer_t *peer)
{
    bool ret = false;

    // Sock
    peer->sock = sock;

    // Creds
    {
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);

        if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len)) {
            goto done;
        }
        peer->pid = cred.pid;
        peer->uid = cred.uid;
        peer->gid = cred.gid;
    }

    // Program
    if (!proc_exe(peer->pid, peer->program, sizeof(peer->program))) {
        goto done;
    }

    // User
    if (!user_name(peer->uid, peer->user, sizeof(peer->user))) {
        goto done;
    }

    // Group
    if (!group_name(peer->gid, peer->group, sizeof(peer->group))) {
        goto done;
    }

    // Perms
    {
        struct stat statbuf;
        struct sockaddr_un addr;
        socklen_t len = sizeof(addr);
        if (getsockname(sock, (struct sockaddr *)&addr, &len)) {
            goto done;
        }
        if (addr.sun_path[0] != '\0') {
            if (stat(addr.sun_path, &statbuf)) {
                goto done;
            }
            peer->perms = (statbuf.st_mode & 0777);
        }
    }

    // Credentials
    {
        socklen_t len = sizeof(peer->creds);
        if (getsockopt(sock, SOL_SOCKET, SO_PEERSEC, peer->creds, &len)) {
            if (errno != ENOPROTOOPT) {
                goto done;
            }
        }
    }

    ret = true;
done:
    return ret;
}


int secpolicy_peer_sock(const secpolicy_peer_t *peer)
{
    return (peer ? peer->sock : -1);
}

pid_t secpolicy_peer_pid(const secpolicy_peer_t *peer)
{
    return (peer ? peer->pid : 0);
}

const char *secpolicy_peer_program(const secpolicy_peer_t *peer)
{
    return (peer ? peer->program : NULL);
}

uid_t secpolicy_peer_uid(const secpolicy_peer_t *peer)
{
    return (peer ? peer->uid : 0);
}

gid_t secpolicy_peer_gid(const secpolicy_peer_t *peer)
{
    return (peer ? peer->gid : 0);
}

const char *secpolicy_peer_user(const secpolicy_peer_t *peer)
{
    return (peer ? peer->user : NULL);
}

const char *secpolicy_peer_group(const secpolicy_peer_t *peer)
{
    return (peer ? peer->group : NULL);
}

mode_t secpolicy_peer_perms(const secpolicy_peer_t *peer)
{
    return (peer ? peer->perms : 0);
}

const char *secpolicy_peer_creds(const secpolicy_peer_t *peer)
{
    return (peer ? peer->creds : NULL);
}
