// SPDX-License-Identifier: MIT
#include "prahari/net.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <optional>

#include "prahari/byte_reader.hpp"
#include <arpa/inet.h>

namespace prahari::net {

namespace {

constexpr std::uint16_t kEtherIpv4 = 0x0800;
constexpr std::uint16_t kEtherIpv6 = 0x86DD;
constexpr std::uint16_t kEtherVlan = 0x8100;
constexpr std::uint16_t kEtherQinQ = 0x88A8;
constexpr int kMaxVlanTags = 4;
constexpr int kMaxIpv6ExtHeaders = 8;

constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;
constexpr std::uint8_t kProtoSctp = 132;

constexpr std::uint8_t kSctpChunkData = 0;
constexpr std::uint8_t kSctpDataBeginEnd = 0x03;  // B and E flags: unfragmented message

// Result of stripping the link layer: the ethertype-equivalent and the L3 bytes.
struct L3 {
    std::uint16_t ethertype{};
    std::span<const std::uint8_t> bytes;
};

Result<L3> strip_link(LinkType link, std::span<const std::uint8_t> frame) {
    ByteReader r{frame};
    std::optional<std::uint16_t> ethertype;
    switch (link) {
        case LinkType::kEthernet: {
            if (!r.skip(12)) {
                return DecodeError::kTruncated;
            }
            ethertype = r.u16();
            for (int i = 0; ethertype && (*ethertype == kEtherVlan || *ethertype == kEtherQinQ);
                 ++i) {
                if (i == kMaxVlanTags || !r.skip(2)) {
                    return DecodeError::kMalformed;
                }
                ethertype = r.u16();
            }
            break;
        }
        case LinkType::kLinuxSll:
            if (!r.skip(14)) {
                return DecodeError::kTruncated;
            }
            ethertype = r.u16();
            break;
        case LinkType::kLinuxSll2:
            ethertype = r.u16();
            if (!r.skip(18)) {
                return DecodeError::kTruncated;
            }
            break;
        case LinkType::kRaw: {
            const auto first = r.peek_u8();
            if (!first) {
                return DecodeError::kTruncated;
            }
            const auto version = static_cast<std::uint8_t>(*first >> 4U);
            if (version == 4) {
                ethertype = kEtherIpv4;
            } else if (version == 6) {
                ethertype = kEtherIpv6;
            } else {
                ethertype = 0;
            }
            break;
        }
    }
    if (!ethertype) {
        return DecodeError::kTruncated;
    }
    auto rest = r.bytes(r.remaining());
    return L3{*ethertype, rest ? *rest : std::span<const std::uint8_t>{}};
}

struct L4Input {
    std::uint8_t protocol{};
    std::span<const std::uint8_t> bytes;
};

Result<L4Input> decode_ipv4(std::span<const std::uint8_t> data, Packet& out) {
    ByteReader r{data};
    const auto ver_ihl = r.u8();
    if (!ver_ihl) {
        return DecodeError::kTruncated;
    }
    if ((*ver_ihl >> 4U) != 4) {
        return DecodeError::kMalformed;
    }
    const std::size_t header_len = std::size_t{*ver_ihl & 0x0FU} * 4;
    const auto tos = r.u8();
    const auto total_len = r.u16();
    const auto ident = r.u16();
    const auto frag = r.u16();
    const auto ttl = r.u8();
    const auto proto = r.u8();
    const auto checksum = r.u16();
    const auto src = r.u32();
    const auto dst = r.u32();
    if (!tos || !total_len || !ident || !frag || !ttl || !proto || !checksum || !src || !dst) {
        return DecodeError::kTruncated;
    }
    if (header_len < 20 || *total_len < header_len) {
        return DecodeError::kMalformed;
    }
    if (*total_len > data.size()) {
        return DecodeError::kTruncated;
    }
    constexpr std::uint16_t kMoreFragments = 0x2000;
    constexpr std::uint16_t kOffsetMask = 0x1FFF;
    if ((*frag & kMoreFragments) != 0 || (*frag & kOffsetMask) != 0) {
        return DecodeError::kUnsupported;  // fragments need reassembly; rare on N2/N4
    }
    out.src = IpAddress::v4_from(*src);
    out.dst = IpAddress::v4_from(*dst);
    out.ip_protocol = *proto;
    // Trim Ethernet padding: the IP total length is authoritative.
    return L4Input{*proto, data.subspan(header_len, *total_len - header_len)};
}

Result<L4Input> decode_ipv6(std::span<const std::uint8_t> data, Packet& out) {
    ByteReader r{data};
    const auto first = r.u32();
    const auto payload_len = r.u16();
    auto next = r.u8();
    const auto hop = r.u8();
    const auto src = r.bytes(16);
    const auto dst = r.bytes(16);
    if (!first || !payload_len || !next || !hop || !src || !dst) {
        return DecodeError::kTruncated;
    }
    if ((*first >> 28U) != 6) {
        return DecodeError::kMalformed;
    }
    out.src.v6 = true;
    out.dst.v6 = true;
    std::copy(src->begin(), src->end(), out.src.bytes.begin());
    std::copy(dst->begin(), dst->end(), out.dst.bytes.begin());

    auto body = r.sub(*payload_len);
    if (!body) {
        return DecodeError::kTruncated;
    }
    for (int i = 0; i < kMaxIpv6ExtHeaders; ++i) {
        switch (*next) {
            case 0:     // Hop-by-Hop
            case 43:    // Routing
            case 60: {  // Destination Options
                const auto nh = body->u8();
                const auto len = body->u8();
                if (!nh || !len || !body->skip((std::size_t{*len} + 1) * 8 - 2)) {
                    return DecodeError::kTruncated;
                }
                next = nh;
                continue;
            }
            case 44:  // Fragment
                return DecodeError::kUnsupported;
            default: {
                out.ip_protocol = *next;
                const auto rest = body->bytes(body->remaining());
                return L4Input{*next, rest ? *rest : std::span<const std::uint8_t>{}};
            }
        }
    }
    return DecodeError::kMalformed;  // extension header chain too long
}

Result<bool> decode_udp(std::span<const std::uint8_t> data, Packet& out) {
    ByteReader r{data};
    const auto sport = r.u16();
    const auto dport = r.u16();
    const auto len = r.u16();
    const auto checksum = r.u16();
    if (!sport || !dport || !len || !checksum) {
        return DecodeError::kTruncated;
    }
    if (*len < 8) {
        return DecodeError::kMalformed;
    }
    if (*len > data.size()) {
        return DecodeError::kTruncated;
    }
    out.transport = Transport::kUdp;
    out.src_port = *sport;
    out.dst_port = *dport;
    out.payload = data.subspan(8, *len - std::size_t{8});
    return true;
}

Result<bool> decode_tcp(std::span<const std::uint8_t> data, Packet& out) {
    ByteReader r{data};
    const auto sport = r.u16();
    const auto dport = r.u16();
    const auto seq = r.u32();
    if (!sport || !dport || !seq || !r.skip(4)) {
        return DecodeError::kTruncated;
    }
    const auto offset_byte = r.u8();
    const auto flags = r.u8();
    if (!offset_byte || !flags) {
        return DecodeError::kTruncated;
    }
    const std::size_t header_len = std::size_t{static_cast<std::uint8_t>(*offset_byte >> 4U)} * 4;
    if (header_len < 20) {
        return DecodeError::kMalformed;
    }
    if (header_len > data.size()) {
        return DecodeError::kTruncated;
    }
    out.transport = Transport::kTcp;
    out.src_port = *sport;
    out.dst_port = *dport;
    out.tcp_seq = *seq;
    out.tcp_flags = *flags;
    out.payload = data.subspan(header_len);
    return true;
}

Result<bool> decode_sctp(std::span<const std::uint8_t> data, Packet& out) {
    ByteReader r{data};
    const auto sport = r.u16();
    const auto dport = r.u16();
    if (!sport || !dport || !r.skip(8)) {  // verification tag + checksum
        return DecodeError::kTruncated;
    }
    out.transport = Transport::kSctp;
    out.src_port = *sport;
    out.dst_port = *dport;

    while (r.remaining() >= 4) {
        const auto type = r.u8();
        const auto flags = r.u8();
        const auto length = r.u16();
        if (!type || !flags || !length) {
            return DecodeError::kTruncated;
        }
        if (*length < 4) {
            return DecodeError::kMalformed;
        }
        auto chunk = r.sub(*length - std::size_t{4});
        if (!chunk) {
            return DecodeError::kTruncated;
        }
        // Chunks are padded to a 4-byte boundary; the last chunk's padding may be absent.
        const std::size_t pad = (4U - (std::size_t{*length} % 4U)) % 4U;
        (void)r.skip(std::min(pad, r.remaining()));

        if (*type == kSctpChunkData && (*flags & kSctpDataBeginEnd) == kSctpDataBeginEnd) {
            const auto tsn = chunk->u32();
            const auto stream = chunk->u16();
            const auto ssn = chunk->u16();
            const auto ppid = chunk->u32();
            if (!tsn || !stream || !ssn || !ppid) {
                return DecodeError::kMalformed;
            }
            const auto user = chunk->bytes(chunk->remaining());
            out.sctp_data.push_back(
                SctpData{*stream, *ppid, user ? *user : std::span<const std::uint8_t>{}});
        }
        // Control chunks (INIT, SACK, HEARTBEAT, ...) and fragmented DATA are skipped.
    }
    return true;
}

}  // namespace

std::string IpAddress::to_string() const {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    const char* res = inet_ntop(v6 ? AF_INET6 : AF_INET, bytes.data(), buf.data(),
                                static_cast<socklen_t>(buf.size()));
    return res != nullptr ? std::string{buf.data()} : std::string{"?"};
}

IpAddress IpAddress::v4_from(std::uint32_t host_order) noexcept {
    IpAddress a;
    a.bytes[0] = static_cast<std::uint8_t>(host_order >> 24U);
    a.bytes[1] = static_cast<std::uint8_t>(host_order >> 16U);
    a.bytes[2] = static_cast<std::uint8_t>(host_order >> 8U);
    a.bytes[3] = static_cast<std::uint8_t>(host_order);
    return a;
}

std::size_t IpAddressHash::operator()(const IpAddress& a) const noexcept {
    // FNV-1a over the address bytes and family.
    std::size_t h = 1469598103934665603ULL;
    for (const auto b : a.bytes) {
        h = (h ^ b) * 1099511628211ULL;
    }
    return h ^ static_cast<std::size_t>(a.v6);
}

Result<Packet> decode_frame(LinkType link, std::span<const std::uint8_t> frame) {
    const auto l3 = strip_link(link, frame);
    if (!l3) {
        return l3.error();
    }
    Packet pkt;
    Result<L4Input> l4 = DecodeError::kUnsupported;
    if (l3.value().ethertype == kEtherIpv4) {
        l4 = decode_ipv4(l3.value().bytes, pkt);
    } else if (l3.value().ethertype == kEtherIpv6) {
        l4 = decode_ipv6(l3.value().bytes, pkt);
    }
    if (!l4) {
        return l4.error();
    }
    Result<bool> ok = true;
    switch (l4.value().protocol) {
        case kProtoUdp:  ok = decode_udp(l4.value().bytes, pkt); break;
        case kProtoTcp:  ok = decode_tcp(l4.value().bytes, pkt); break;
        case kProtoSctp: ok = decode_sctp(l4.value().bytes, pkt); break;
        default:         pkt.transport = Transport::kOther; break;
    }
    if (!ok) {
        return ok.error();
    }
    return pkt;
}

}  // namespace prahari::net
