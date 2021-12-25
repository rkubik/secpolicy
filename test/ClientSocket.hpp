#pragma once

#include <string>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

class ClientSocket {
  public:
    bool open(const std::string &path)
    {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock == -1) {
            return false;
        }

        struct sockaddr_un name;
        memset(&name, 0, sizeof(name));
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, path.c_str(), sizeof(name.sun_path));

        if (connect(sock, (const struct sockaddr *)&name, sizeof(name))) {
            return false;
        }

        return true;
    }

    ~ClientSocket()
    {
        if (sock_ != -1) {
            (void)close(sock_);
        }
    }

  private:
    int sock_ = -1;
};
