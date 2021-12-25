#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

TEST_CASE("Peer Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[uid, gid, expected_result] : {
             std::tuple<uid_t, gid_t, secpolicy_result_t>{
                 0, 0, SECPOLICY_RESULT_PEER},
             std::tuple<uid_t, gid_t, secpolicy_result_t>{
                 getuid(), 0, SECPOLICY_RESULT_PEER},
             std::tuple<uid_t, gid_t, secpolicy_result_t>{
                 0, getgid(), SECPOLICY_RESULT_PEER},
             std::tuple<uid_t, gid_t, secpolicy_result_t>{getuid(), getgid(),
                                                          0},
         }) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for uid " << uid
                                                << " and gid " << gid)
        {
            secpolicy_peer(policy.get(), uid, gid);

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
                });

            REQUIRE(ret == 0);
            REQUIRE(result == expected_result);
        }
    }
}
