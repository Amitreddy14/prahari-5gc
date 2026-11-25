// SPDX-License-Identifier: MIT
// Link, network and transport layer decoding for captured frames.
//
// Supported: Ethernet II (+ 802.1Q / 802.1ad VLAN tags), Linux cooked v1 (SLL) and
// v2 (SLL2), raw IP; IPv4 (options, first fragment only) and IPv6 (common extension
// headers); UDP; SCTP common header + DATA chunks (RFC 9260). TCP is identified
// but not reassembled (Phase 3).
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "prahari/result.hpp"

namespace prahari::net {

// pcap link-layer types (https://www.tcpdump.org/linktypes.html).
enum class LinkType : std::uint16_t {
    kEthernet = 1,
    kRaw = 101,
    kLinuxSll = 113,
    kLinuxSll2 = 276,
};

struct IpAddress {
    std::array<std::uint8_t, 16> bytes{};
    bool v6{};

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] static IpAddress v4_from(std::uint32_t host_order) noexcept;
    friend bool operator==(const IpAddress&, const IpAddress&) = default;
};

struct IpAddressHash {
    [[nodiscard]] std::size_t operator()(const IpAddress& a) const noexcept;
};

enum class Transport : std::uint8_t { kUdp, kTcp, kSctp, kOther };

// One SCTP DATA chunk's user data (RFC 9260 section 3.3.1).
struct SctpData {
    std::uint16_t stream_id{};
    std::uint32_t ppid{};  // payload protocol identifier; 60 = NGAP
    std::span<const std::uint8_t> payload;
};

struct Packet {
    IpAddress src;
    IpAddress dst;
    Transport transport{Transport::kOther};
    std::uint8_t ip_protocol{};
    std::uint16_t src_port{};
    std::uint16_t dst_port{};
    // UDP / TCP payload. Empty for SCTP (see sctp_data).
    std::span<const std::uint8_t> payload;
    std::vector<SctpData> sctp_data;  // SCTP may bundle several chunks per packet
};

// Decodes one captured frame. Non-IP frames and IP fragments return kUnsupported;
// damaged headers return kTruncated / kMalformed.
// Lifetime: the returned Packet's spans point into `frame`; keep the frame alive
// for as long as the Packet is used.
[[nodiscard]] Result<Packet> decode_frame(LinkType link, std::span<const std::uint8_t> frame);

inline constexpr std::uint32_t kPpidNgap = 60;
inline constexpr std::uint16_t kPortPfcp = 8805;

}  // namespace prahari::net
