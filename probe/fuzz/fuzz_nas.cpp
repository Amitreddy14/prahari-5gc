// SPDX-License-Identifier: MIT
// libFuzzer target: nas::decode (5GMM/5GSM, security headers, SUCI -> IMSI,
// nested UL/DL NAS Transport) must never crash or read out of bounds.
// The first input byte picks the UE's cipher state: none known, NEA0, or NEA2.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "prahari/nas.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    std::optional<std::uint8_t> cipher;
    switch (data[0] % 3U) {
        case 1:  cipher = 0; break;
        case 2:  cipher = 2; break;
        default: break;
    }
    (void)prahari::nas::decode(std::span<const std::uint8_t>{data + 1, size - 1}, cipher);
    return 0;
}
