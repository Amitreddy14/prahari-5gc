// SPDX-License-Identifier: MIT
#include "prahari/pfcp.hpp"

#include "prahari/byte_reader.hpp"

namespace prahari::pfcp {

namespace {
constexpr std::uint8_t kVersionShift = 5;
constexpr std::uint8_t kFoBit = 0x04;
constexpr std::uint8_t kMpBit = 0x02;
constexpr std::uint8_t kSBit = 0x01;
constexpr std::uint8_t kPriorityShift = 4;
}  // namespace

Result<Message> decode(std::span<const std::uint8_t> datagram) noexcept {
    ByteReader r{datagram};

    const auto flags = r.u8();
    const auto type = r.u8();
    const auto length = r.u16();
    if (!flags || !type || !length) {
        return DecodeError::kTruncated;
    }

    Header h;
    h.version = static_cast<std::uint8_t>(*flags >> kVersionShift);
    h.follow_on = (*flags & kFoBit) != 0;
    h.has_priority = (*flags & kMpBit) != 0;
    h.has_seid = (*flags & kSBit) != 0;
    h.message_type = *type;
    h.message_length = *length;

    if (h.version != kSupportedVersion) {
        return DecodeError::kBadVersion;
    }
    // The declared length must cover at least the rest of the header.
    if (h.message_length < h.header_length() - 4) {
        return DecodeError::kBadLength;
    }
    if (datagram.size() < h.total_length()) {
        return DecodeError::kTruncated;
    }
    if (!h.follow_on && datagram.size() != h.total_length()) {
        return DecodeError::kBadLength;
    }

    if (h.has_seid) {
        const auto seid = r.u64();
        if (!seid) {
            return DecodeError::kTruncated;
        }
        h.seid = seid;
    }
    const auto seq = r.u24();
    const auto last = r.u8();
    if (!seq || !last) {
        return DecodeError::kTruncated;
    }
    h.sequence = *seq;
    if (h.has_priority) {
        h.priority = static_cast<std::uint8_t>(*last >> kPriorityShift);
    }

    const std::size_t body_len = h.total_length() - h.header_length();
    const auto body = r.bytes(body_len);
    if (!body) {
        return DecodeError::kTruncated;
    }
    return Message{h, *body};
}

std::string_view message_name(std::uint8_t type) noexcept {
    switch (static_cast<MessageType>(type)) {
        case MessageType::kHeartbeatRequest:             return "HeartbeatRequest";
        case MessageType::kHeartbeatResponse:            return "HeartbeatResponse";
        case MessageType::kPfdManagementRequest:         return "PFDManagementRequest";
        case MessageType::kPfdManagementResponse:        return "PFDManagementResponse";
        case MessageType::kAssociationSetupRequest:      return "AssociationSetupRequest";
        case MessageType::kAssociationSetupResponse:     return "AssociationSetupResponse";
        case MessageType::kAssociationUpdateRequest:     return "AssociationUpdateRequest";
        case MessageType::kAssociationUpdateResponse:    return "AssociationUpdateResponse";
        case MessageType::kAssociationReleaseRequest:    return "AssociationReleaseRequest";
        case MessageType::kAssociationReleaseResponse:   return "AssociationReleaseResponse";
        case MessageType::kVersionNotSupportedResponse:  return "VersionNotSupportedResponse";
        case MessageType::kNodeReportRequest:            return "NodeReportRequest";
        case MessageType::kNodeReportResponse:           return "NodeReportResponse";
        case MessageType::kSessionSetDeletionRequest:    return "SessionSetDeletionRequest";
        case MessageType::kSessionSetDeletionResponse:   return "SessionSetDeletionResponse";
        case MessageType::kSessionEstablishmentRequest:  return "SessionEstablishmentRequest";
        case MessageType::kSessionEstablishmentResponse: return "SessionEstablishmentResponse";
        case MessageType::kSessionModificationRequest:   return "SessionModificationRequest";
        case MessageType::kSessionModificationResponse:  return "SessionModificationResponse";
        case MessageType::kSessionDeletionRequest:       return "SessionDeletionRequest";
        case MessageType::kSessionDeletionResponse:      return "SessionDeletionResponse";
        case MessageType::kSessionReportRequest:         return "SessionReportRequest";
        case MessageType::kSessionReportResponse:        return "SessionReportResponse";
    }
    return "Unknown";
}

}  // namespace prahari::pfcp
