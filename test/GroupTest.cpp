#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
std::string getgroup()
{
    char *strbuf = NULL;
    struct group grbuf;
    struct group *gr = NULL;
    long val;
    size_t strbuflen;

    val = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (val < 0) {
        return {};
    }
    strbuflen = val;

    strbuf = static_cast<char *>(malloc(strbuflen));
    if (!strbuf) {
        return {};
    }

    if (getgrgid_r(getgid(), &grbuf, strbuf, strbuflen, &gr) != 0 ||
        gr == NULL) {
        return {};
    }

    return gr->gr_name;
}
} // namespace

TEST_CASE("Group Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[group, expected_result] :
         {std::tuple<std::string, secpolicy_result_t>{"!@#$%^&*()",
                                                      SECPOLICY_RESULT_GROUP},
          std::tuple<std::string, secpolicy_result_t>{getgroup(), 0}}) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for group " << group)
        {
            secpolicy_rule_group(policy.get(), group.c_str());

            int ret;
            secpolicy_result_t result;
            Process::spawn(
                [&policy, &server, &ret, &result]() {
                    int client = server.accept();
                    ret = secpolicy_apply(policy.get(), client, &result);
                },
                []() {
                    ClientSocket client;
                    client.open("test.sock");
                    ::pause();
                });

            REQUIRE(ret == 0);
            REQUIRE(result == expected_result);
        }
    }
}
