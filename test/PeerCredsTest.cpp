#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

TEST_CASE("Peer Creds Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[creds, expected_result] : {
             std::tuple<std::string, secpolicy_result_t>{
                 "docker-default (enforce)", SECPOLICY_RESULT_PEER_CREDS},
             std::tuple<std::string, secpolicy_result_t>{"", 0},
         }) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for creds " << creds)
        {
            secpolicy_peer_creds(policy.get(), creds.c_str());

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
