#ifndef USER_H
#define USER_H

#include "secpolicy/secpolicy.h"

#include <stdbool.h>
#include <sys/types.h>

bool user_name(uid_t uid, char *name, size_t name_size);
bool group_name(gid_t gid, char *name, size_t name_size);

#endif /* USER_H */
