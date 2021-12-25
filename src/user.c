#include "user.h"
#include "strlcpy.h"

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

bool user_name(uid_t uid, char *name, size_t name_size)
{
    bool ret = false;
    char *strbuf = NULL;
    struct passwd pwbuf;
    struct passwd *pw = NULL;
    long val;
    size_t strbuflen;

    val = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (val < 0) {
        goto done;
    }
    strbuflen = val;

    strbuf = malloc(strbuflen);
    if (!strbuf) {
        goto done;
    }

    if (getpwuid_r(uid, &pwbuf, strbuf, strbuflen, &pw) != 0 || pw == NULL) {
        goto done;
    }

    safe_strcpy(name, name_size, pw->pw_name);
    ret = true;
done:
    free(strbuf);
    return ret;
}

bool group_name(gid_t gid, char *name, size_t name_size)
{
    bool ret = false;
    char *strbuf = NULL;
    struct group grbuf;
    struct group *gr = NULL;
    long val;
    size_t strbuflen;

    val = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (val < 0) {
        goto done;
    }
    strbuflen = val;

    strbuf = malloc(strbuflen);
    if (!strbuf) {
        goto done;
    }

    if (getgrgid_r(gid, &grbuf, strbuf, strbuflen, &gr) != 0 || gr == NULL) {
        goto done;
    }

    safe_strcpy(name, name_size, gr->gr_name);
    ret = true;
done:
    free(strbuf);
    return ret;
}
