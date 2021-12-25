#pragma once

#include "secpolicy/secpolicy.h"

#include <memory>

struct SecPolicyDeleter {
    void operator()(secpolicy_t *policy)
    {
        secpolicy_destroy(policy);
    }
};
using SecPolicy = std::unique_ptr<secpolicy_t, SecPolicyDeleter>;
