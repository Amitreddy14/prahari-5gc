// SPDX-License-Identifier: MIT
// NGAP (N2, gNB <-> AMF) decoding, 3GPP TS 38.413, ASN.1 Aligned PER (X.691).
//
// Decoded as far as detection needs, not the full ASN.1 module:
//   NGAP-PDU CHOICE (initiating / successful / unsuccessful outcome)
//   procedureCode, criticality, the ProtocolIE-Container, and these IEs:
//     85 RAN-UE-NGAP-ID   10 AMF-UE-NGAP-ID   38 NAS-PDU
//     27 GlobalRANNodeID  82 RANNodeName      114 UE-NGAP-IDs (pair or AMF-only)
// Every other IE is counted and its bytes kept, never interpreted.
//
//   byte 0      : ext(1) | pdu type(2) | pad        (0x00, 0x20, 0x40)
//   byte 1      : procedureCode
//   byte 2      : criticality(2) | pad
//   length      : APER length determinant, then the message:
//     ext(1) | pad, IE count (16 bits), then per IE:
//     id (16 bits), criticality(2)|pad, length determinant, value
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "prahari/byte_reader.hpp"
#include "prahari/result.hpp"

namespace prahari::ngap {

enum class PduType : std::uint8_t { kInitiating = 0, kSuccessful = 1, kUnsuccessful = 2 };

[[nodiscard]] std::string_view to_string(PduType t) noexcept;

namespace ie {
inline constexpr std::uint16_t kAmfName = 1;
inline constexpr std::uint16_t kAmfUeNgapId = 10;
inline constexpr std::uint16_t kCause = 15;
inline constexpr std::uint16_t kGlobalRanNodeId = 27;
inline constexpr std::uint16_t kNasPdu = 38;
inline constexpr std::uint16_t kRanNodeName = 82;
inline constexpr std::uint16_t kRanUeNgapId = 85;
inline constexpr std::uint16_t kUeNgapIds = 114;
}  // namespace ie

namespace proc {
inline constexpr std::uint8_t kDownlinkNasTransport = 4;
inline constexpr std::uint8_t kInitialContextSetup = 14;
inline constexpr std::uint8_t kInitialUeMessage = 15;
inline constexpr std::uint8_t kNgSetup = 21;
inline constexpr std::uint8_t kPduSessionResourceSetup = 29;
inline constexpr std::uint8_t kUeContextRelease = 41;
inline constexpr std::uint8_t kUeContextReleaseRequest = 42;
inline constexpr std::uint8_t kUplinkNasTransport = 46;
}  // namespace proc

struct GlobalGnbId {
    std::string plmn;  // MCC+MNC digits, e.g. "00101"
    std::uint32_t gnb_id{};
    std::uint8_t gnb_id_bits{};  // 22..32
};

struct Ie {
    std::uint16_t id{};
    std::uint8_t criticality{};
    std::span<const std::uint8_t> value;
};

struct Message {
    PduType pdu_type{PduType::kInitiating};
    std::uint8_t procedure_code{};
    std::uint8_t criticality{};
    std::vector<Ie> ies;
    std::optional<std::uint32_t> ran_ue_ngap_id;
    std::optional<std::uint64_t> amf_ue_ngap_id;  // 40-bit
    std::vector<std::span<const std::uint8_t>> nas_pdus;
    std::optional<GlobalGnbId> global_gnb_id;
    std::optional<std::string> ran_node_name;  // printable, sanitised
    std::size_t size_bytes{};
};

// Decodes one NGAP PDU (one SCTP DATA chunk). Undecodable known IEs fail the
// whole message; unknown IEs are kept as raw bytes.
[[nodiscard]] Result<Message> decode(std::span<const std::uint8_t> pdu);

// Message name for (procedure, PDU type), e.g. (21, successful) -> "NGSetupResponse".
[[nodiscard]] std::string message_name(std::uint8_t procedure, PduType type);

// Class-2 procedures have no response: their initiating message is an indication.
[[nodiscard]] bool is_class2(std::uint8_t procedure) noexcept;

namespace aper {
// X.691 10.9.3.6 unconstrained length determinant (octet-aligned).
// Fragmented lengths (>= 16K, prefix 11) return kUnsupported.
[[nodiscard]] Result<std::size_t> length(ByteReader& r);
// Constrained whole number with an octet-count prefix of `prefix_bits` bits,
// as used for INTEGER (0..2^32-1) (2 bits) and (0..2^40-1) (3 bits).
[[nodiscard]] Result<std::uint64_t> sized_uint(std::span<const std::uint8_t> v, int prefix_bits);
}  // namespace aper

}  // namespace prahari::ngap
