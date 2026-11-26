// SPDX-License-Identifier: MIT
// SUPI pseudonymisation: first 64 bits of HMAC-SHA256(key, "imsi-<digits>"), hex.
// Byte-identical to prahari_analytics.events.supi_hash (a test pins both sides).
// A keyed hash is required: the IMSI space is small enough to brute-force SHA-256.
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace prahari {

class SupiHasher {
public:
    static constexpr std::size_t kMinKeyBytes = 16;

    // Reads the key from environment variable `var`. Returns nullopt (and sets
    // `error`) when unset or shorter than kMinKeyBytes.
    [[nodiscard]] static std::optional<SupiHasher> from_env(const char* var, std::string& error);

    explicit SupiHasher(std::string key) : key_(std::move(key)) {}

    [[nodiscard]] std::string hash(std::string_view supi) const;

private:
    std::string key_;
};

}  // namespace prahari
