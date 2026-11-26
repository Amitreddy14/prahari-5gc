// SPDX-License-Identifier: MIT
#include "prahari/plmn.hpp"

namespace prahari {

namespace {
char digit(std::uint8_t nibble) {
    return nibble <= 9 ? static_cast<char>('0' + nibble) : '?';
}
}  // namespace

std::string decode_plmn(std::span<const std::uint8_t> three) {
    if (three.size() != 3) {
        return {};
    }
    std::string s;
    s.push_back(digit(three[0] & 0x0FU));                           // MCC digit 1
    s.push_back(digit(static_cast<std::uint8_t>(three[0] >> 4U)));  // MCC digit 2
    s.push_back(digit(three[1] & 0x0FU));                           // MCC digit 3
    s.push_back(digit(three[2] & 0x0FU));                           // MNC digit 1
    s.push_back(digit(static_cast<std::uint8_t>(three[2] >> 4U)));  // MNC digit 2
    const auto mnc3 = static_cast<std::uint8_t>(three[1] >> 4U);
    if (mnc3 != 0x0F) {
        s.push_back(digit(mnc3));  // 3-digit MNC
    }
    return s;
}

std::string decode_bcd(std::span<const std::uint8_t> bytes) {
    std::string s;
    s.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        const auto lo = static_cast<std::uint8_t>(b & 0x0FU);
        const auto hi = static_cast<std::uint8_t>(b >> 4U);
        if (lo == 0x0F) {
            break;
        }
        s.push_back(digit(lo));
        if (hi == 0x0F) {
            break;
        }
        s.push_back(digit(hi));
    }
    return s;
}

}  // namespace prahari
