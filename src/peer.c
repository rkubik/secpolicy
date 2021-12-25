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
            peer->perms = statbuf.st_mode;
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