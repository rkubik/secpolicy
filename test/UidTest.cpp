#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

TEST_CASE("Uid Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[uid, expected_result] : {
             std::tuple<uid_t, secpolicy_result_t>{getuid() + 1,
                                                   SECPOLICY_RESULT_UID},
             std::tuple<uid_t, secpolicy_result_t>{getuid(), 0},
         }) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for uid " << uid)
        {
            secpolicy_rule_uid(policy.get(), uid);

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
