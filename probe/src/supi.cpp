// SPDX-License-Identifier: MIT
#include "prahari/supi.hpp"

#include <array>
#include <cstdlib>
#include <memory>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace prahari {

std::optional<SupiHasher> SupiHasher::from_env(const char* var, std::string& error) {
    const char* value = std::getenv(var);  // NOLINT(concurrency-mt-unsafe): read once at start-up
    if (value == nullptr || *value == '\0') {
        error = std::string{var} + " is not set: SUPIs will be omitted from events";
        return std::nullopt;
    }
    const std::string key{value};
    if (key.size() < kMinKeyBytes) {
        error = std::string{var} + " must be at least 16 bytes: SUPIs will be omitted";
        return std::nullopt;
    }
    return SupiHasher{key};
}

SupiHasher::SupiHasher(const std::string& key) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) {
        return;
    }
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);  // the context holds its own reference
    if (ctx == nullptr) {
        return;
    }
    std::array<char, 7> digest{"SHA256"};
    const std::array<OSSL_PARAM, 2> params{
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest.data(), 0),
        OSSL_PARAM_construct_end()};
    std::vector<unsigned char> k(key.begin(), key.end());
    if (EVP_MAC_init(ctx, k.data(), k.size(), params.data()) != 1) {
        EVP_MAC_CTX_free(ctx);
        return;
    }
    keyed_.reset(ctx, &EVP_MAC_CTX_free);
}

std::string SupiHasher::hash(std::string_view supi) const {
    if (!keyed_) {
        return {};
    }
    const std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx{
        EVP_MAC_CTX_dup(keyed_.get()), &EVP_MAC_CTX_free};
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    std::size_t mac_len = 0;
    // OpenSSL wants unsigned bytes; copy the (short) SUPI rather than reinterpret it.
    const std::vector<unsigned char> msg(supi.begin(), supi.end());
    if (!ctx || EVP_MAC_update(ctx.get(), msg.data(), msg.size()) != 1 ||
        EVP_MAC_final(ctx.get(), mac.data(), &mac_len, mac.size()) != 1 || mac_len < 8) {
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
