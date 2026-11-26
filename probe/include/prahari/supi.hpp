// SPDX-License-Identifier: MIT
// SUPI pseudonymisation: first 64 bits of HMAC-SHA256(key, "imsi-<digits>"), hex.
// Byte-identical to prahari_analytics.events.supi_hash (a test pins both sides).
// A keyed hash is required: the IMSI space is small enough to brute-force SHA-256.
#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

struct evp_mac_ctx_st;

namespace prahari {

class SupiHasher {
public:
    static constexpr std::size_t kMinKeyBytes = 16;

    // Reads the key from environment variable `var`. Returns nullopt (and sets
    // `error`) when unset or shorter than kMinKeyBytes.
    [[nodiscard]] static std::optional<SupiHasher> from_env(const char* var, std::string& error);

    // Keys an HMAC-SHA256 context once; hash() clones it, so each call skips the
    // algorithm lookup and key schedule (about 2x faster than one-shot HMAC()).
    explicit SupiHasher(const std::string& key);

    // Returns "" only if OpenSSL fails, which callers treat as "no pseudonym".
    [[nodiscard]] std::string hash(std::string_view supi) const;

private:
    std::shared_ptr<evp_mac_ctx_st> keyed_;  // shared, read-only: copies stay cheap
};

}  // namespace prahari
