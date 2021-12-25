#ifndef PROC_H
#define PROC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

bool proc_exe(pid_t pid, char *path, size_t path_size);

#endif /* PROC_H */
