#define CATCH_CONFIG_MAIN

#include "catch.hpp"

#include "ClientSocket.hpp"
#include "Process.hpp"
#include "SecPolicy.hpp"
#include "ServerSocket.hpp"
#include "secpolicy/secpolicy.h"

#include <iostream>
#include <sstream>

namespace {
std::string getexe()
{
    char exe[PATH_MAX];
    std::stringstream ss;
    ss << "/proc/" << getpid() << "/exe";
    ssize_t size = readlink(ss.str().c_str(), exe, sizeof(exe) - 1);
    if (size == -1) {
        return {};
    }
    return exe;
}
} // namespace

TEST_CASE("Program Test")
{
    SecPolicy policy{secpolicy_create()};
    ServerSocket server;

    REQUIRE(server.open("test.sock"));

    for (auto &&[program, expected_result] : {
             std::tuple<std::string, secpolicy_result_t>{
                 "!@#$%^&*()", SECPOLICY_RESULT_PROGRAM},
             std::tuple<std::string, secpolicy_result_t>{getexe(), 0},
         }) {
        DYNAMIC_SECTION("Policy should return " << std::hex << expected_result
                                                << " for program " << program)
        {
            secpolicy_program(policy.get(), program.c_str());

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
