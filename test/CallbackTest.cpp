#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

namespace {
bool verify_connection(const secpolicy_peer_t *peer, void *ctx)
{
    bool *ret = static_cast<bool *>(ctx);
    return *ret;
}

} // namespace

TEST_CASE("Peer Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[ret, expected_result] : {
             std::tuple<bool, secpolicy_result_t>{true, 0},
             std::tuple<bool, secpolicy_result_t>{false,
                                                  SECPOLICY_RESULT_CALLBACK},
         }) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " when callback returns "
                                                << (ret ? "true" : "false"))
        {
            bool cb_ret = ret;
            secpolicy_rule_callback(policy.get(), verify_connection,
                                    static_cast<void *>(&cb_ret));

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
