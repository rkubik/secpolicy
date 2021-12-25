#pragma once

#include <string>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

class ServerSocket {
  public:
    bool open(const std::string &path)
    {
        if (unlink(path.c_str())) {
            if (errno != ENOENT) {
                return false;
            }
        }

        sock_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_ == -1) {
            return false;
        }

        struct sockaddr_un name;
        memset(&name, 0, sizeof(name));
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, path.c_str(), sizeof(name.sun_path));

        if (bind(sock_, (const struct sockaddr *)&name, sizeof(name))) {
            return false;
        }

        if (listen(sock_, 1)) {
            return false;
        }

        return true;
    }

    int accept()
    {
        return ::accept(sock_, nullptr, nullptr);
    }

    ~ServerSocket()
    {
        if (sock_ != -1) {
            (void)close(sock_);
        }
    }

  private:
    int sock_ = -1;
};
