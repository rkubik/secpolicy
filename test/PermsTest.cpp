#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>

TEST_CASE("Perms Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[file_perms, policy_perms, expected_result] : {
             std::tuple<mode_t, mode_t, secpolicy_result_t>{
                 S_IXUSR | S_IRUSR | S_IWUSR, S_IXUSR | S_IRUSR | S_IWUSR, 0},
             std::tuple<mode_t, mode_t, secpolicy_result_t>{
                 S_IXUSR | S_IRUSR | S_IWUSR,
                 S_IXUSR | S_IRUSR | S_IWUSR | S_IXGRP, SECPOLICY_RESULT_PERMS},
             std::tuple<mode_t, mode_t, secpolicy_result_t>{
                 S_IXUSR | S_IRUSR | S_IWUSR | S_IXGRP,
                 S_IXUSR | S_IRUSR | S_IWUSR, SECPOLICY_RESULT_PERMS},
         }) {
        DYNAMIC_SECTION("Policy should return "
                        << std::hex << expected_result << " for file perms "
                        << std::oct << (file_perms & 0777)
                        << " and policy perms " << std::oct
                        << (policy_perms & 0777))
        {
            ::chmod("test.sock", file_perms);
            secpolicy_perms(policy.get(), policy_perms);

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
