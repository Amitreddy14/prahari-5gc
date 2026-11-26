// SPDX-License-Identifier: MIT
#include "prahari/pfcp_ie.hpp"

#include <algorithm>

#include "prahari/byte_reader.hpp"
#include "prahari/plmn.hpp"

namespace prahari::pfcp {

namespace {

constexpr int kMaxDepth = 6;
constexpr std::size_t kMaxFqdn = 255;

bool is_grouped(std::uint16_t type) noexcept {
    switch (type) {
        case ie::kCreatePdr:
        case ie::kPdi:
        case ie::kCreateFar:
        case ie::kForwardingParameters:
        case ie::kDuplicatingParameters:
        case ie::kCreatedPdr:
        case ie::kUpdatePdr:
        case ie::kUpdateFar:
        case ie::kUpdateForwardingParameters:
        case ie::kRemovePdr:
        case ie::kRemoveFar:                  return true;
        default:                              return false;
    }
}

bool is_pdr_group(std::uint16_t t) noexcept {
    return t == ie::kCreatePdr || t == ie::kCreatedPdr || t == ie::kUpdatePdr ||
           t == ie::kRemovePdr;
}

bool is_far_group(std::uint16_t t) noexcept {
    return t == ie::kCreateFar || t == ie::kUpdateFar || t == ie::kRemoveFar;
}

// Node ID (8.2.38): type in the low nibble of octet 5; 0 IPv4, 1 IPv6, 2 FQDN.
Result<std::string> decode_node_id(std::span<const std::uint8_t> v) {
    ByteReader r{v};
    const auto type_byte = r.u8();
    if (!type_byte) {
        return DecodeError::kTruncated;
    }
    switch (*type_byte & 0x0FU) {
        case 0: {
            const auto ip = r.u32();
            if (!ip) {
                return DecodeError::kTruncated;
            }
            return net::IpAddress::v4_from(*ip).to_string();
        }
        case 1: {
            const auto ip = r.bytes(16);
            if (!ip) {
                return DecodeError::kTruncated;
            }
            net::IpAddress a;
            a.v6 = true;
            std::copy(ip->begin(), ip->end(), a.bytes.begin());
            return a.to_string();
        }
        case 2: {
            // DNS label encoding: <len><label>...; render as dotted, printable only.
            std::string out;
            while (!r.empty() && out.size() < kMaxFqdn) {
                const auto len = r.u8();
                if (!len || *len == 0) {
                    break;
                }
                const auto label = r.bytes(*len);
                if (!label) {
                    return DecodeError::kMalformed;
                }
                if (!out.empty()) {
                    out.push_back('.');
                }
                for (const auto c : *label) {
                    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                                    (c >= 'A' && c <= 'Z') || c == '-' || c == '_';
                    out.push_back(ok ? static_cast<char>(c) : '?');
                }
            }
            if (out.empty()) {
                return DecodeError::kMalformed;
            }
            return out;
        }
        default: return DecodeError::kUnsupported;
    }
}

// F-SEID (8.2.37): flags (bit 1 V6, bit 2 V4), SEID, then IPv4 and/or IPv6.
Result<FSeid> decode_f_seid(std::span<const std::uint8_t> v) {
    ByteReader r{v};
    const auto flags = r.u8();
    const auto seid = r.u64();
    if (!flags || !seid) {
        return DecodeError::kTruncated;
    }
    FSeid f;
    f.seid = *seid;
    if ((*flags & 0x02U) != 0) {
        const auto ip = r.u32();
        if (!ip) {
            return DecodeError::kTruncated;
        }
        f.ipv4 = net::IpAddress::v4_from(*ip);
    }
    if ((*flags & 0x01U) != 0) {
        const auto ip = r.bytes(16);
        if (!ip) {
            return DecodeError::kTruncated;
        }
        net::IpAddress a;
        a.v6 = true;
        std::copy(ip->begin(), ip->end(), a.bytes.begin());
        f.ipv6 = a;
    }
    return f;
}

// Recursion is bounded by kMaxDepth (grouped IEs nest at most a few levels).
// NOLINTNEXTLINE(misc-no-recursion)
Result<bool> walk(std::span<const std::uint8_t> buf, int depth, std::uint16_t parent, Summary& s) {
    if (depth > kMaxDepth) {
        return DecodeError::kMalformed;
    }
    auto ies = split_ies(buf);
    if (!ies) {
        return ies.error();
    }
    if (depth == 0) {
        s.ie_count = ies.value().size();
    }
    for (const auto& e : ies.value()) {
        if (e.enterprise_id) {
            s.has_vendor_ie = true;
            continue;
        }
        if (depth == 0) {
            if (is_pdr_group(e.type)) {
                ++s.pdr_groups;
            }
            if (is_far_group(e.type)) {
                ++s.far_groups;
            }
        }
        switch (e.type) {
            case ie::kCause:
                if (depth == 0) {
                    ByteReader r{e.value};
                    const auto c = r.u8();
                    if (!c) {
                        return DecodeError::kTruncated;
                    }
                    s.cause = c;
                }
                break;
            case ie::kNodeId:
                if (depth == 0) {
                    auto n = decode_node_id(e.value);
                    if (!n) {
                        return n.error();
                    }
                    s.node_id = std::move(n).value();
                }
                break;
            case ie::kFSeid:
                if (depth == 0) {
                    auto f = decode_f_seid(e.value);
                    if (!f) {
                        return f.error();
                    }
                    s.f_seid = f.value();
                }
                break;
            case ie::kPdrId:
                if (is_pdr_group(parent)) {
                    ByteReader r{e.value};
                    const auto id = r.u16();
                    if (!id) {
                        return DecodeError::kTruncated;
                    }
                    s.pdr_ids.push_back(*id);
                }
                break;
            case ie::kFarId:
                // FAR IDs also appear inside PDRs as references; count only FAR groups.
                if (is_far_group(parent)) {
                    ByteReader r{e.value};
                    const auto id = r.u32();
                    if (!id) {
                        return DecodeError::kTruncated;
                    }
                    s.far_ids.push_back(*id);
                }
                break;
            case ie::kUserId:
                s.has_user_id = true;
                s.user_id = e.value;  // a view; see Summary
                break;
            default: break;
        }
        if (is_grouped(e.type)) {
            if (auto ok = walk(e.value, depth + 1, e.type, s); !ok) {
                return ok.error();
            }
        }
    }
    return true;
}

}  // namespace

Result<std::vector<Ie>> split_ies(std::span<const std::uint8_t> buf) {
    std::vector<Ie> out;
    ByteReader r{buf};
    while (!r.empty()) {
        const auto type = r.u16();
        const auto len = r.u16();
        if (!type || !len) {
            return DecodeError::kTruncated;
        }
        auto value = r.sub(*len);
        if (!value) {
            return DecodeError::kTruncated;
        }
        Ie e;
        e.type = *type;
        if ((*type & ie::kVendorBit) != 0) {
            const auto ent = value->u16();
            if (!ent) {
                return DecodeError::kMalformed;
            }
            e.enterprise_id = ent;
        }
        const auto rest = value->bytes(value->remaining());
        e.value = rest ? *rest : std::span<const std::uint8_t>{};
        out.push_back(e);
    }
    return out;
}

Result<Summary> summarize(std::span<const std::uint8_t> body) {
    Summary s;
    if (auto ok = walk(body, 0, 0, s); !ok) {
        return ok.error();
    }
    return s;
}

std::optional<std::string> user_id_imsi(std::span<const std::uint8_t> value) {
    ByteReader r{value};
    const auto flags = r.u8();
    if (!flags || (*flags & 0x01U) == 0) {
        return std::nullopt;  // IMSIF not set
    }
    const auto len = r.u8();
    if (!len || *len == 0 || *len > 8) {
        return std::nullopt;
    }
    const auto bytes = r.bytes(*len);
    if (!bytes) {
        return std::nullopt;
    }
    auto digits = decode_bcd(*bytes);
    if (digits.size() < 5 || digits.size() > 15 ||
        digits.find_first_not_of("0123456789") != std::string::npos) {
        return std::nullopt;
    }
    return digits;
}

std::string_view cause_name(std::uint8_t cause) noexcept {
    switch (cause) {
        case 1:  return "RequestAccepted";
        case 2:  return "MoreUsageReportToSend";
        case 64: return "RequestRejected";
        case 65: return "SessionContextNotFound";
        case 66: return "MandatoryIeMissing";
        case 67: return "ConditionalIeMissing";
        case 68: return "InvalidLength";
        case 69: return "MandatoryIeIncorrect";
        case 70: return "InvalidForwardingPolicy";
        case 71: return "InvalidFteidAllocationOption";
        case 72: return "NoEstablishedPfcpAssociation";
        case 73: return "RuleCreationModificationFailure";
        case 74: return "PfcpEntityInCongestion";
        case 75: return "NoResourcesAvailable";
        case 76: return "ServiceNotSupported";
        case 77: return "SystemFailure";
        case 78: return "RedirectionRequested";
        case 79: return "AllDynamicAddressesOccupied";
        default: return "Other";
    }
}

}  // namespace prahari::pfcp
