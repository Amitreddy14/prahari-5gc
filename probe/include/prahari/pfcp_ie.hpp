// SPDX-License-Identifier: MIT
// PFCP Information Element walking and extraction (3GPP TS 29.244 section 8).
//
//   Octets 1-2 : IE Type   (bit 16 set => vendor-specific, Enterprise ID follows)
//   Octets 3-4 : IE Length (bytes after these 4 octets, Enterprise ID included)
//   [Octets 5-6: Enterprise ID]
//   rest       : value (grouped IEs contain further IEs)
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "prahari/net.hpp"
#include "prahari/result.hpp"

namespace prahari::pfcp {

namespace ie {
inline constexpr std::uint16_t kCreatePdr = 1;
inline constexpr std::uint16_t kPdi = 2;
inline constexpr std::uint16_t kCreateFar = 3;
inline constexpr std::uint16_t kForwardingParameters = 4;
inline constexpr std::uint16_t kDuplicatingParameters = 5;
inline constexpr std::uint16_t kCreatedPdr = 8;
inline constexpr std::uint16_t kUpdatePdr = 9;
inline constexpr std::uint16_t kUpdateFar = 10;
inline constexpr std::uint16_t kUpdateForwardingParameters = 11;
inline constexpr std::uint16_t kRemovePdr = 15;
inline constexpr std::uint16_t kRemoveFar = 16;
inline constexpr std::uint16_t kCause = 19;
inline constexpr std::uint16_t kPdrId = 56;
inline constexpr std::uint16_t kFSeid = 57;
inline constexpr std::uint16_t kNodeId = 60;
inline constexpr std::uint16_t kRecoveryTimeStamp = 96;
inline constexpr std::uint16_t kFarId = 108;
inline constexpr std::uint16_t kUserId = 141;
inline constexpr std::uint16_t kVendorBit = 0x8000;
}  // namespace ie

struct Ie {
    std::uint16_t type{};
    std::optional<std::uint16_t> enterprise_id;
    std::span<const std::uint8_t> value;  // excludes the Enterprise ID
};

// Splits a buffer into its top-level IEs.
[[nodiscard]] Result<std::vector<Ie>> split_ies(std::span<const std::uint8_t> buf);

struct FSeid {
    std::uint64_t seid{};
    std::optional<net::IpAddress> ipv4;
    std::optional<net::IpAddress> ipv6;
};

// What the probe needs from a PFCP message body. Never holds a copy of subscriber
// identity: `user_id` is a view into the message, valid only while it is, and is
// meant for user_id_imsi() -> SupiHasher, never for output.
struct Summary {
    std::size_t ie_count{};  // top-level IEs
    std::optional<std::string> node_id;
    std::optional<FSeid> f_seid;
    std::optional<std::uint8_t> cause;
    std::size_t pdr_groups{};  // Create / Created / Update / Remove PDR
    std::size_t far_groups{};  // Create / Update / Remove FAR
    std::vector<std::uint16_t> pdr_ids;
    std::vector<std::uint32_t> far_ids;
    bool has_user_id{};
    std::span<const std::uint8_t> user_id;  // User ID IE value (TS 29.244 8.2.101)
    bool has_vendor_ie{};
};

// Walks top-level and grouped IEs (bounded depth). Fails on any malformed IE.
[[nodiscard]] Result<Summary> summarize(std::span<const std::uint8_t> body);

// IMSI digits from a User ID IE value, if its IMSIF flag is set (TBCD, 0xF filler).
[[nodiscard]] std::optional<std::string> user_id_imsi(std::span<const std::uint8_t> value);

[[nodiscard]] std::string_view cause_name(std::uint8_t cause) noexcept;
[[nodiscard]] constexpr bool cause_accepted(std::uint8_t cause) noexcept {
    return cause == 1;
}

}  // namespace prahari::pfcp
