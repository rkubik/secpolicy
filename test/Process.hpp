#pragma once

#include <functional>

#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

class Process final {
  public:
    static void spawn(std::function<void()> parent, std::function<void()> child)
    {
        pid_t pid = ::fork();
        if (pid == -1) {
            throw std::runtime_error("spawn failed");
        } else if (pid == 0) {
            child();
            ::exit(0);
        } else {
            parent();
            ::kill(pid, 9);
            ::waitpid(pid, nullptr, 0);
        }
    }
};
