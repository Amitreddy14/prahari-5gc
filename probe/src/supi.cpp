// SPDX-License-Identifier: MIT
#include "prahari/supi.hpp"

#include <array>
#include <cstdlib>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace prahari {

std::optional<SupiHasher> SupiHasher::from_env(const char* var, std::string& error) {
    const char* value = std::getenv(var);  // NOLINT(concurrency-mt-unsafe): read once at start-up
    if (value == nullptr || *value == '\0') {
        error = std::string{var} + " is not set: SUPIs will be omitted from events";
        return std::nullopt;
    }
    std::string key{value};
    if (key.size() < kMinKeyBytes) {
        error = std::string{var} + " must be at least 16 bytes: SUPIs will be omitted";
        return std::nullopt;
    }
    return SupiHasher{std::move(key)};
}

std::string SupiHasher::hash(std::string_view supi) const {
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    unsigned int mac_len = 0;
    // OpenSSL wants unsigned bytes; copy the (short) SUPI rather than reinterpret it.
    std::vector<unsigned char> msg(supi.begin(), supi.end());
    const auto* ok = HMAC(EVP_sha256(), key_.data(), static_cast<int>(key_.size()), msg.data(),
                          msg.size(), mac.data(), &mac_len);
    if (ok == nullptr || mac_len < 8) {
        return {};
    }
    static constexpr std::array<char, 16> kHex{'0', '1', '2', '3', '4', '5', '6', '7',
                                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out;
    out.reserve(16);
    for (std::size_t i = 0; i < 8; ++i) {
        out.push_back(kHex[mac[i] >> 4U]);
        out.push_back(kHex[mac[i] & 0x0FU]);
    }
    return out;
}

}  // namespace prahari
