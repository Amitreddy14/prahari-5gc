// SPDX-License-Identifier: MIT
// libFuzzer target: pfcp::decode must never crash, hang or read out of bounds
// on arbitrary bytes. Built only with -DPRAHARI_FUZZ=ON (Clang).
#include <cstddef>
#include <cstdint>
#include <span>

#include "prahari/pfcp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::span<const std::uint8_t> rest{data, size};
    // Walk follow-on chains the way the live probe will.
    for (int i = 0; i < 64 && !rest.empty(); ++i) {
        const auto r = prahari::pfcp::decode(rest);
        if (!r.ok() || !r.value().header.follow_on) {
            break;
        }
        rest = rest.subspan(r.value().header.total_length());
    }
    return 0;
}
