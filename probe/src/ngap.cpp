// SPDX-License-Identifier: MIT
#include "prahari/ngap.hpp"

#include <array>

#include "prahari/plmn.hpp"

namespace prahari::ngap {

namespace {

constexpr std::uint8_t kExtBit = 0x80;
constexpr std::size_t kMaxIes = 256;  // real messages carry < 20; bound hostile counts
constexpr std::size_t kMaxRanNodeName = 150;

struct Names {
    std::uint8_t code;
    std::string_view initiating;
    std::string_view successful;
    std::string_view unsuccessful;
};

// TS 38.413 section 9.2 / 9.4.6 (procedure codes in ASN.1 order).
constexpr std::array<Names, 55> kNames{{
    {0, "AMFConfigurationUpdate", "AMFConfigurationUpdateAcknowledge",
     "AMFConfigurationUpdateFailure"},
    {1, "AMFStatusIndication", "", ""},
    {2, "CellTrafficTrace", "", ""},
    {3, "DeactivateTrace", "", ""},
    {4, "DownlinkNASTransport", "", ""},
    {5, "DownlinkNonUEAssociatedNRPPaTransport", "", ""},
    {6, "DownlinkRANConfigurationTransfer", "", ""},
    {7, "DownlinkRANStatusTransfer", "", ""},
    {8, "DownlinkUEAssociatedNRPPaTransport", "", ""},
    {9, "ErrorIndication", "", ""},
    {10, "HandoverCancel", "HandoverCancelAcknowledge", ""},
    {11, "HandoverNotify", "", ""},
    {12, "HandoverRequired", "HandoverCommand", "HandoverPreparationFailure"},
    {13, "HandoverRequest", "HandoverRequestAcknowledge", "HandoverFailure"},
    {14, "InitialContextSetupRequest", "InitialContextSetupResponse", "InitialContextSetupFailure"},
    {15, "InitialUEMessage", "", ""},
    {16, "LocationReportingControl", "", ""},
    {17, "LocationReportingFailureIndication", "", ""},
    {18, "LocationReport", "", ""},
    {19, "NASNonDeliveryIndication", "", ""},
    {20, "NGReset", "NGResetAcknowledge", ""},
    {21, "NGSetupRequest", "NGSetupResponse", "NGSetupFailure"},
    {22, "OverloadStart", "", ""},
    {23, "OverloadStop", "", ""},
    {24, "Paging", "", ""},
    {25, "PathSwitchRequest", "PathSwitchRequestAcknowledge", "PathSwitchRequestFailure"},
    {26, "PDUSessionResourceModifyRequest", "PDUSessionResourceModifyResponse", ""},
    {27, "PDUSessionResourceModifyIndication", "PDUSessionResourceModifyConfirm", ""},
    {28, "PDUSessionResourceReleaseCommand", "PDUSessionResourceReleaseResponse", ""},
    {29, "PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse", ""},
    {30, "PDUSessionResourceNotify", "", ""},
    {31, "PrivateMessage", "", ""},
    {32, "PWSCancelRequest", "PWSCancelResponse", ""},
    {33, "PWSFailureIndication", "", ""},
    {34, "PWSRestartIndication", "", ""},
    {35, "RANConfigurationUpdate", "RANConfigurationUpdateAcknowledge",
     "RANConfigurationUpdateFailure"},
    {36, "RerouteNASRequest", "", ""},
    {37, "RRCInactiveTransitionReport", "", ""},
    {38, "TraceFailureIndication", "", ""},
    {39, "TraceStart", "", ""},
    {40, "UEContextModificationRequest", "UEContextModificationResponse",
     "UEContextModificationFailure"},
    {41, "UEContextReleaseCommand", "UEContextReleaseComplete", ""},
    {42, "UEContextReleaseRequest", "", ""},
    {43, "UERadioCapabilityCheckRequest", "UERadioCapabilityCheckResponse", ""},
    {44, "UERadioCapabilityInfoIndication", "", ""},
    {45, "UETNLABindingReleaseRequest", "", ""},
    {46, "UplinkNASTransport", "", ""},
    {47, "UplinkNonUEAssociatedNRPPaTransport", "", ""},
    {48, "UplinkRANConfigurationTransfer", "", ""},
    {49, "UplinkRANStatusTransfer", "", ""},
    {50, "UplinkUEAssociatedNRPPaTransport", "", ""},
    {51, "WriteReplaceWarningRequest", "WriteReplaceWarningResponse", ""},
    {52, "SecondaryRATDataUsageReport", "", ""},
    {53, "UplinkRIMInformationTransfer", "", ""},
    {54, "DownlinkRIMInformationTransfer", "", ""},
}};

Result<GlobalGnbId> decode_global_ran_node_id(std::span<const std::uint8_t> v) {
    // GlobalRANNodeID ::= CHOICE (4 alternatives, no extension marker) -> 2 bits.
    // GlobalGNB-ID ::= SEQUENCE { pLMNIdentity, gNB-ID, iE-Extensions OPTIONAL, ... }
    //   -> extension bit + 1 optional bit, then padding before the 3-octet PLMN.
    ByteReader r{v};
    const auto b0 = r.u8();
    if (!b0) {
        return DecodeError::kTruncated;
    }
    if ((*b0 >> 6U) != 0) {
        return DecodeError::kUnsupported;  // ng-eNB / N3IWF node IDs
    }
    if (((*b0 >> 5U) & 1U) != 0 || ((*b0 >> 4U) & 1U) != 0) {
        return DecodeError::kUnsupported;  // extensions present
    }
    const auto plmn_bytes = r.bytes(3);
    if (!plmn_bytes) {
        return DecodeError::kTruncated;
    }
    // GNB-ID ::= CHOICE { gNB-ID BIT STRING (SIZE(22..32)), choice-Extensions }
    //   -> 1 bit choice index, 4 bits (size - 22), padding, then the bits.
    const auto g = r.u8();
    if (!g) {
        return DecodeError::kTruncated;
    }
    if ((*g >> 7U) != 0) {
        return DecodeError::kUnsupported;
    }
    const auto bits = static_cast<std::uint8_t>(((*g >> 3U) & 0x0FU) + 22U);
    if (bits > 32) {
        return DecodeError::kMalformed;
    }
    const std::size_t nbytes = (std::size_t{bits} + 7) / 8;
    const auto raw = r.bytes(nbytes);
    if (!raw) {
        return DecodeError::kTruncated;
    }
    std::uint64_t acc = 0;
    for (const auto b : *raw) {
        acc = (acc << 8U) | b;
    }
    acc >>= (nbytes * 8 - bits);
    GlobalGnbId id;
    id.plmn = decode_plmn(*plmn_bytes);
    id.gnb_id = static_cast<std::uint32_t>(acc);
    id.gnb_id_bits = bits;
    return id;
}

// UE-NGAP-IDs ::= CHOICE { uE-NGAP-ID-pair, aMF-UE-NGAP-ID, choice-Extensions }
// (UEContextReleaseCommand). Bit-packed in the first octet:
//   pair:     choice(2)=00 | ext(1) | opt(1) | AMF length-1 (3) | pad, AMF octets,
//             then RAN length-1 (2) | pad, RAN octets
//   AMF only: choice(2)=01 | AMF length-1 (3) | pad, AMF octets
Result<bool> decode_ue_ngap_ids(std::span<const std::uint8_t> v, Message& m) {
    ByteReader r{v};
    const auto b0 = r.u8();
    if (!b0) {
        return DecodeError::kTruncated;
    }
    const auto choice = static_cast<std::uint8_t>(*b0 >> 6U);
    auto read_octets = [&r](std::size_t n) -> std::optional<std::uint64_t> {
        const auto raw = r.bytes(n);
        if (!raw) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        for (const auto b : *raw) {
            value = (value << 8U) | b;
        }
        return value;
    };
    if (choice == 0) {
        if (((*b0 >> 4U) & 0x03U) != 0) {
            return DecodeError::kUnsupported;  // extension / iE-Extensions present
        }
        const auto amf = read_octets(((std::size_t{*b0} >> 1U) & 0x07U) + 1);
        const auto rb = r.u8();
        if (!amf || !rb) {
            return DecodeError::kTruncated;
        }
        const auto ran = read_octets((std::size_t{*rb} >> 6U) + 1);
        if (!ran) {
            return DecodeError::kTruncated;
        }
        m.amf_ue_ngap_id = amf;
        m.ran_ue_ngap_id = static_cast<std::uint32_t>(*ran);
        return true;
    }
    if (choice == 1) {
        const auto amf = read_octets(((std::size_t{*b0} >> 3U) & 0x07U) + 1);
        if (!amf) {
            return DecodeError::kTruncated;
        }
        m.amf_ue_ngap_id = amf;
        return true;
    }
    return DecodeError::kUnsupported;
}

Result<std::string> decode_ran_node_name(std::span<const std::uint8_t> v) {
    // PrintableString (SIZE(1..150, ...)): ext bit, 8-bit (length - 1), padding, chars.
    ByteReader r{v};
    const auto b0 = r.u8();
    const auto b1 = r.u8();
    if (!b0 || !b1) {
        return DecodeError::kTruncated;
    }
    if ((*b0 & kExtBit) != 0) {
        return DecodeError::kUnsupported;
    }
    const std::size_t len = ((std::size_t{*b0} & 0x7FU) << 1U | (std::size_t{*b1} >> 7U)) + 1;
    if (len > kMaxRanNodeName) {
        return DecodeError::kMalformed;
    }
    const auto chars = r.bytes(len);
    if (!chars) {
        return DecodeError::kTruncated;
    }
    std::string out;
    out.reserve(len);
    for (const auto c : *chars) {
        const bool printable = c >= 0x20 && c < 0x7F && c != '"' && c != '\\';
        out.push_back(printable ? static_cast<char>(c) : '?');
    }
    return out;
}

}  // namespace

std::string_view to_string(PduType t) noexcept {
    switch (t) {
        case PduType::kInitiating:   return "initiating";
        case PduType::kSuccessful:   return "successful";
        case PduType::kUnsuccessful: return "unsuccessful";
    }
    return "initiating";
}

namespace aper {

Result<std::size_t> length(ByteReader& r) {
    const auto b0 = r.u8();
    if (!b0) {
        return DecodeError::kTruncated;
    }
    if ((*b0 & 0x80U) == 0) {
        return std::size_t{*b0};
    }
    if ((*b0 & 0xC0U) == 0x80U) {
        const auto b1 = r.u8();
        if (!b1) {
            return DecodeError::kTruncated;
        }
        return (std::size_t{*b0} & 0x3FU) << 8U | *b1;
    }
    return DecodeError::kUnsupported;  // fragmented (>= 16K): never seen on N2
}

Result<std::uint64_t> sized_uint(std::span<const std::uint8_t> v, int prefix_bits) {
    ByteReader r{v};
    const auto b0 = r.u8();
    if (!b0) {
        return DecodeError::kTruncated;
    }
    const auto shift = static_cast<unsigned>(8 - prefix_bits);
    const std::size_t nbytes = (std::size_t{*b0} >> shift) + 1;
    const auto raw = r.bytes(nbytes);
    if (!raw) {
        return DecodeError::kTruncated;
    }
    std::uint64_t value = 0;
    for (const auto b : *raw) {
        value = (value << 8U) | b;
    }
    return value;
}

}  // namespace aper

Result<Message> decode(std::span<const std::uint8_t> pdu) {
    ByteReader r{pdu};
    const auto choice = r.u8();
    const auto proc = r.u8();
    const auto crit = r.u8();
    if (!choice || !proc || !crit) {
        return DecodeError::kTruncated;
    }
    if ((*choice & kExtBit) != 0) {
        return DecodeError::kUnsupported;
    }
    const auto type_index = static_cast<std::uint8_t>((*choice >> 5U) & 0x03U);
    if (type_index > 2) {
        return DecodeError::kMalformed;
    }
    Message m;
    m.pdu_type = static_cast<PduType>(type_index);
    m.procedure_code = *proc;
    m.criticality = static_cast<std::uint8_t>(*crit >> 6U);
    m.size_bytes = pdu.size();

    const auto len = aper::length(r);
    if (!len) {
        return len.error();
    }
    auto body = r.sub(len.value());
    if (!body) {
        return DecodeError::kTruncated;
    }
    const auto seq_ext = body->u8();
    const auto count = body->u16();
    if (!seq_ext || !count) {
        return DecodeError::kTruncated;
    }
    if ((*seq_ext & kExtBit) != 0) {
        return DecodeError::kUnsupported;
    }
    if (*count > kMaxIes) {
        return DecodeError::kMalformed;
    }
    m.ies.reserve(*count);
    for (std::size_t i = 0; i < *count; ++i) {
        const auto id = body->u16();
        const auto ie_crit = body->u8();
        if (!id || !ie_crit) {
            return DecodeError::kTruncated;
        }
        const auto vlen = aper::length(*body);
        if (!vlen) {
            return vlen.error();
        }
        const auto value = body->bytes(vlen.value());
        if (!value) {
            return DecodeError::kTruncated;
        }
        m.ies.push_back(Ie{*id, static_cast<std::uint8_t>(*ie_crit >> 6U), *value});

        switch (*id) {
            case ie::kRanUeNgapId: {
                const auto v = aper::sized_uint(*value, 2);
                if (!v) {
                    return v.error();
                }
                m.ran_ue_ngap_id = static_cast<std::uint32_t>(v.value());
                break;
            }
            case ie::kAmfUeNgapId: {
                const auto v = aper::sized_uint(*value, 3);
                if (!v) {
                    return v.error();
                }
                m.amf_ue_ngap_id = v.value();
                break;
            }
            case ie::kNasPdu: {
                ByteReader nr{*value};
                const auto nlen = aper::length(nr);
                if (!nlen) {
                    return nlen.error();
                }
                const auto nas = nr.bytes(nlen.value());
                if (!nas) {
                    return DecodeError::kTruncated;
                }
                m.nas_pdus.push_back(*nas);
                break;
            }
            case ie::kGlobalRanNodeId: {
                auto g = decode_global_ran_node_id(*value);
                if (g) {
                    m.global_gnb_id = std::move(g).value();
                } else if (g.error() != DecodeError::kUnsupported) {
                    return g.error();
                }
                break;
            }
            case ie::kUeNgapIds: {
                const auto ok = decode_ue_ngap_ids(*value, m);
                if (!ok && ok.error() != DecodeError::kUnsupported) {
                    return ok.error();
                }
                break;
            }
            case ie::kRanNodeName: {
                auto n = decode_ran_node_name(*value);
                if (n) {
                    m.ran_node_name = std::move(n).value();
                } else if (n.error() != DecodeError::kUnsupported) {
                    return n.error();
                }
                break;
            }
            default: break;
        }
    }
    return m;
}

std::string message_name(std::uint8_t procedure, PduType type) {
    for (const auto& n : kNames) {
        if (n.code != procedure) {
            continue;
        }
        std::string_view name;
        switch (type) {
            case PduType::kInitiating:   name = n.initiating; break;
            case PduType::kSuccessful:   name = n.successful; break;
            case PduType::kUnsuccessful: name = n.unsuccessful; break;
        }
        if (!name.empty()) {
            return std::string{name};
        }
        // A response to a procedure we list as class 2 is itself an anomaly; name it plainly.
        return std::string{n.initiating} + "/" + std::string{to_string(type)};
    }
    return "Procedure" + std::to_string(procedure) + "/" + std::string{to_string(type)};
}

bool is_class2(std::uint8_t procedure) noexcept {
    for (const auto& n : kNames) {
        if (n.code == procedure) {
            return n.successful.empty();
        }
    }
    return false;
}

}  // namespace prahari::ngap
