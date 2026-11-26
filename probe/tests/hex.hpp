// SPDX-License-Identifier: MIT
// Test helper: hex string -> bytes (test vectors copied from tshark).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace prahari::test {

inline std::vector<std::uint8_t> hex(std::string_view s) {
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(c - 'a' + 10);
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(c - 'A' + 10);
        }
        throw std::invalid_argument("bad hex");
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>((nibble(s[i]) << 4U) | nibble(s[i + 1])));
    }
    return out;
}

}  // namespace prahari::test
