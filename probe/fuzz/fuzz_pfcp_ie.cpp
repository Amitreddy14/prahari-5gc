// SPDX-License-Identifier: MIT
// libFuzzer target: the PFCP IE walker must survive arbitrary (nested) IE bodies.
#include <cstddef>
#include <cstdint>
#include <span>

#include "prahari/pfcp_ie.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    (void)prahari::pfcp::summarize(std::span<const std::uint8_t>{data, size});
    return 0;
}
