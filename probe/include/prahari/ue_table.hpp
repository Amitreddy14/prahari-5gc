// SPDX-License-Identifier: MIT
// N2 UE context table: one entry per (gNB address, RAN-UE-NGAP-ID), carrying what
// later messages for that UE do not repeat: AMF-UE-NGAP-ID, the SUPI hash learned
// from its Registration Request, and the NAS ciphering algorithm from its Security
// Mode Command (needed to read NEA0 "ciphered" messages).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "prahari/net.hpp"

namespace prahari::ngap {

struct UeContext {
    std::optional<std::uint64_t> amf_ue_ngap_id;
    std::optional<std::string> supi_hash;
    std::optional<std::uint8_t> cipher_alg;
    std::uint64_t last_seen_ns{};
};

class UeTable {
public:
    explicit UeTable(std::size_t max_contexts = 1'000'000,
                     std::uint64_t idle_timeout_ns = 3'600'000'000'000ULL)
        : max_(max_contexts), idle_timeout_ns_(idle_timeout_ns) {}

    // Existing context, or a new one (nullptr only when the table is full).
    UeContext* touch(const net::IpAddress& gnb, std::uint32_t ran_ue_ngap_id, std::uint64_t now_ns);
    void release(const net::IpAddress& gnb, std::uint32_t ran_ue_ngap_id);

    [[nodiscard]] std::size_t size() const noexcept { return map_.size(); }
    [[nodiscard]] std::uint64_t dropped_full() const noexcept { return dropped_full_; }
    [[nodiscard]] std::uint64_t expired() const noexcept { return expired_; }

private:
    struct Key {
        net::IpAddress gnb;
        std::uint32_t ran{};
        friend bool operator==(const Key&, const Key&) = default;
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return net::IpAddressHash{}(k.gnb) ^ (std::size_t{k.ran} * 0x9E3779B97F4A7C15ULL);
        }
    };
    void sweep(std::uint64_t now_ns);

    std::size_t max_;
    std::uint64_t idle_timeout_ns_;
    std::unordered_map<Key, UeContext, KeyHash> map_;
    std::uint64_t ops_{};
    std::uint64_t dropped_full_{};
    std::uint64_t expired_{};
};

}  // namespace prahari::ngap
