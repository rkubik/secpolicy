#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

TEST_CASE("Gid Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[gid, expected_result] :
         {std::tuple<gid_t, secpolicy_result_t>{getgid() + 1,
                                                SECPOLICY_RESULT_GID},
          std::tuple<gid_t, secpolicy_result_t>{getgid(), 0}}) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for gid " << gid)
        {
            secpolicy_rule_gid(policy.get(), gid);

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
