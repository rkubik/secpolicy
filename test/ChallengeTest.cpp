#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>
#include <unistd.h>

namespace {
bool create_challenge(secpolicy_challenge_t *challenge, void *ctx)
{
    challenge->data = new uint8_t[10];
    if (!challenge->data) {
        return false;
    }
    challenge->size = 10;
    return true;
}

void destroy_challenge(secpolicy_challenge_t *challenge, void *ctx)
{
    delete challenge->data;
}

bool verify_challenge(const secpolicy_challenge_t *challenge,
                      const secpolicy_challenge_t *response, void *ctx)
{
    bool *ret = static_cast<bool *>(ctx);
    return *ret;
}

bool solve_challenge(const secpolicy_challenge_t *challenge,
                     secpolicy_challenge_t *response, void *ctx)
{
    response->data = new uint8_t[10];
    if (!response->data) {
        return false;
    }
    response->size = 10;
    return true;
}
} // namespace

TEST_CASE("Challenge Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    SECTION("Policy should fail when peer does not respond")
    {
        secpolicy_challenge_create(policy.get(), create_challenge,
                                   destroy_challenge, verify_challenge,
                                   nullptr);

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
        REQUIRE(result == SECPOLICY_RESULT_CHALLENGE);
    }

    for (auto &&[verify_ret, expected_result] : {
             std::tuple<bool, secpolicy_result_t>{false,
                                                  SECPOLICY_RESULT_CHALLENGE},
             std::tuple<bool, secpolicy_result_t>{true, 0},
         }) {
        DYNAMIC_SECTION("Policy should return "
                        << std::hex << expected_result << " when verify return "
                        << (verify_ret ? "true" : "false"))
        {
            bool verify_ret_local = verify_ret;
            secpolicy_challenge_create(policy.get(), create_challenge,
                                       destroy_challenge, verify_challenge,
                                       static_cast<void *>(&verify_ret_local));

            int ret;
            secpolicy_result_t result;
            Process::spawn(
                [&policy, &server, &ret, &result]() {
                    int client = server.accept();
                    ret = secpolicy_apply(policy.get(), client, &result);
                },
                []() {
                    SecPolicy policy{secpolicy_create()};
                    ClientSocket client;
                    client.open("test.sock");
                    secpolicy_challenge_solve(policy.get(), solve_challenge,
                                              destroy_challenge, nullptr);
                    secpolicy_apply(policy.get(), client.sock(), nullptr);
                });

            REQUIRE(ret == 0);
            REQUIRE(result == expected_result);
        }
    }
}
