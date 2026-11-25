// SPDX-License-Identifier: MIT
// PFCP (N4, SMF <-> UPF) header decoding per 3GPP TS 29.244 section 7.2.2.
//
//   Octet 1      : Version(3) | Spare(2) | FO(1) | MP(1) | S(1)
//   Octet 2      : Message Type
//   Octets 3-4   : Message Length (bytes after the first 4 octets)
//   Octets 5-12  : SEID                      (only if S = 1)
//   next 3       : Sequence Number
//   next 1       : Message Priority(4) | Spare(4)   (priority only if MP = 1)
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "prahari/result.hpp"

namespace prahari::pfcp {

inline constexpr std::uint8_t kSupportedVersion = 1;
inline constexpr std::size_t kNodeHeaderLen = 8;      // S = 0
inline constexpr std::size_t kSessionHeaderLen = 16;  // S = 1

enum class MessageType : std::uint8_t {
    kHeartbeatRequest = 1,
    kHeartbeatResponse = 2,
    kPfdManagementRequest = 3,
    kPfdManagementResponse = 4,
    kAssociationSetupRequest = 5,
    kAssociationSetupResponse = 6,
    kAssociationUpdateRequest = 7,
    kAssociationUpdateResponse = 8,
    kAssociationReleaseRequest = 9,
    kAssociationReleaseResponse = 10,
    kVersionNotSupportedResponse = 11,
    kNodeReportRequest = 12,
    kNodeReportResponse = 13,
    kSessionSetDeletionRequest = 14,
    kSessionSetDeletionResponse = 15,
    kSessionEstablishmentRequest = 50,
    kSessionEstablishmentResponse = 51,
    kSessionModificationRequest = 52,
    kSessionModificationResponse = 53,
    kSessionDeletionRequest = 54,
    kSessionDeletionResponse = 55,
    kSessionReportRequest = 56,
    kSessionReportResponse = 57,
};

struct Header {
    std::uint8_t version{};
    bool follow_on{};     // FO: another PFCP message follows in the same datagram
    bool has_priority{};  // MP
    bool has_seid{};      // S
    std::uint8_t message_type{};
    std::uint16_t message_length{};
    std::optional<std::uint64_t> seid;
    std::uint32_t sequence{};              // 24-bit
    std::optional<std::uint8_t> priority;  // 4-bit, only when MP = 1

    [[nodiscard]] std::size_t header_length() const noexcept {
        return has_seid ? kSessionHeaderLen : kNodeHeaderLen;
    }
    // Offset of the next PFCP message in the datagram (4 + message_length).
    [[nodiscard]] std::size_t total_length() const noexcept {
        return std::size_t{4} + message_length;
    }
};

struct Message {
    Header header;
    std::span<const std::uint8_t> body;  // IEs, not yet decoded
};

// Decodes one PFCP message at the start of `datagram`. Trailing bytes are
// allowed only when FO = 1 (another message follows); use total_length() to step.
[[nodiscard]] Result<Message> decode(std::span<const std::uint8_t> datagram) noexcept;

// True for the 50..57 range, which 29.244 requires to carry a SEID (S = 1).
[[nodiscard]] constexpr bool is_session_message(std::uint8_t type) noexcept {
    return type >= 50 && type <= 57;
}

[[nodiscard]] std::string_view message_name(std::uint8_t type) noexcept;

}  // namespace prahari::pfcp
