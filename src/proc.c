#include "proc.h"

#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

static bool _proc_path(pid_t pid, const char *file, char *path,
                       size_t path_size)
{
    int n = snprintf(path, path_size, "/proc/%d/%s", pid, file);
    return (n > 0 || (size_t)n < path_size);
}

static bool _proc_fd_path(pid_t pid, int fd, char *path, size_t path_size)
{
    int n = snprintf(path, path_size, "/proc/%d/fd/%d", pid, fd);
    return (n > 0 || (size_t)n < path_size);
}

bool proc_exe(pid_t pid, char *path, size_t path_size)
{
    char proc_path[PATH_MAX];
    bool ret = false;
    if (_proc_path(pid, "exe", proc_path, sizeof(proc_path))) {
        ssize_t size = readlink(proc_path, path, path_size - 1);
        if (size != -1) {
            path[size] = '\0';
            ret = true;
        }
    }
    return ret;
}

bool proc_fd_path(pid_t pid, int fd, char *path, size_t path_size)
{
    char proc_path[PATH_MAX];
    bool ret = false;
    if (_proc_fd_path(pid, fd, proc_path, sizeof(proc_path))) {
        ssize_t size = readlink(proc_path, path, path_size - 1);
        if (size != -1) {
            path[size] = '\0';
            ret = true;
        }
    }
    return ret;
}
