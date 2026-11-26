// SPDX-License-Identifier: MIT
#include "prahari/nas.hpp"

#include "prahari/byte_reader.hpp"
#include "prahari/plmn.hpp"

namespace prahari::nas {

namespace {

// 5GMM message types (TS 24.501 9.7).
constexpr std::uint8_t kRegistrationRequest = 0x41;
constexpr std::uint8_t kRegistrationReject = 0x44;
constexpr std::uint8_t kDeregistrationRequestUeOrig = 0x45;
constexpr std::uint8_t kServiceReject = 0x4D;
constexpr std::uint8_t kIdentityResponse = 0x5C;
constexpr std::uint8_t kSecurityModeCommand = 0x5D;
constexpr std::uint8_t kMmStatus = 0x64;
constexpr std::uint8_t kUlNasTransport = 0x67;
constexpr std::uint8_t kDlNasTransport = 0x68;

constexpr std::uint8_t kContainerN1Sm = 1;
constexpr std::uint8_t kIeiPduSessionId = 0x12;
constexpr std::uint8_t kSupiFormatImsi = 0;
constexpr std::uint8_t kSchemeNull = 0;

// 5GS mobile identity (9.11.3.4) inside an LV-E. Fills identity / SUCI fields.
Result<bool> parse_mobile_identity(ByteReader& r, Info& info) {
    const auto len = r.u16();
    if (!len) {
        return DecodeError::kTruncated;
    }
    auto v = r.sub(*len);
    if (!v) {
        return DecodeError::kTruncated;
    }
    const auto first = v->u8();
    if (!first) {
        return DecodeError::kMalformed;
    }
    const auto type = static_cast<std::uint8_t>(*first & 0x07U);
    switch (type) {
        case 0:  info.identity = Identity::kNone; return true;
        case 1:  info.identity = Identity::kSuci; break;
        case 2:  info.identity = Identity::kGuti; return true;
        case 3:  info.identity = Identity::kImei; return true;
        case 4:  info.identity = Identity::kSTmsi; return true;
        case 5:  info.identity = Identity::kImeisv; return true;
        default: info.identity = Identity::kOther; return true;
    }
    // SUCI: SUPI format in bits 5-7 of the first octet.
    const auto supi_format = static_cast<std::uint8_t>((*first >> 4U) & 0x07U);
    if (supi_format != kSupiFormatImsi) {
        return true;  // NAI-format SUPI: not decoded
    }
    const auto plmn = v->bytes(3);
    const auto routing = v->bytes(2);
    const auto scheme = v->u8();
    const auto hn_key = v->u8();
    if (!plmn || !routing || !scheme || !hn_key) {
        return DecodeError::kTruncated;
    }
    const bool null_scheme = (*scheme & 0x0FU) == kSchemeNull;
    info.suci_null_scheme = null_scheme;
    if (null_scheme) {
        const auto msin = v->bytes(v->remaining());
        const auto digits = decode_bcd(msin ? *msin : std::span<const std::uint8_t>{});
        if (digits.empty() || digits.find('?') != std::string::npos) {
            return DecodeError::kMalformed;
        }
        info.supi = "imsi-" + decode_plmn(*plmn) + digits;
    }
    return true;
}

void parse_5gsm_header(ByteReader& r, Info& info) {
    const auto epd = r.u8();
    const auto psi = r.u8();
    const auto pti = r.u8();
    const auto type = r.u8();
    if (!epd || !psi || !pti || !type || *epd != kEpd5gsm) {
        return;
    }
    info.pdu_session_id = psi;
    info.sm_message_type = type;
    info.sm_message = sm_message_name(*type);
}

// Body of a plain 5GMM message, positioned just after the message type.
Result<bool> parse_mm_body(std::uint8_t type, ByteReader& r, Info& info) {
    switch (type) {
        case kRegistrationRequest: {
            const auto b = r.u8();  // ngKSI (high nibble) | registration type (low 3 bits)
            if (!b) {
                return DecodeError::kTruncated;
            }
            info.registration_type = static_cast<std::uint8_t>(*b & 0x07U);
            return parse_mobile_identity(r, info);
        }
        case kDeregistrationRequestUeOrig: {
            if (!r.skip(1)) {  // de-registration type | ngKSI
                return DecodeError::kTruncated;
            }
            return parse_mobile_identity(r, info);
        }
        case kIdentityResponse:    return parse_mobile_identity(r, info);
        case kSecurityModeCommand: {
            const auto algs = r.u8();  // ciphering (high nibble) | integrity (low nibble)
            if (!algs) {
                return DecodeError::kTruncated;
            }
            info.selected_ciphering = static_cast<std::uint8_t>(*algs >> 4U);
            info.selected_integrity = static_cast<std::uint8_t>(*algs & 0x0FU);
            return true;
        }
        case kRegistrationReject:
        case kServiceReject:
        case kMmStatus:           {
            const auto cause = r.u8();
            if (!cause) {
                return DecodeError::kTruncated;
            }
            info.mm_cause = cause;
            return true;
        }
        case kUlNasTransport:
        case kDlNasTransport: {
            const auto ctype = r.u8();
            const auto clen = r.u16();
            if (!ctype || !clen) {
                return DecodeError::kTruncated;
            }
            auto container = r.sub(*clen);
            if (!container) {
                return DecodeError::kTruncated;
            }
            if ((*ctype & 0x0FU) == kContainerN1Sm) {
                parse_5gsm_header(*container, info);
            }
            // UL NAS Transport carries the PDU session ID as the first optional IE.
            if (r.peek_u8() == kIeiPduSessionId) {
                (void)r.skip(1);
                if (const auto psi = r.u8(); psi && !info.pdu_session_id) {
                    info.pdu_session_id = psi;
                }
            }
            return true;
        }
        default: return true;  // name only
    }
}

}  // namespace

std::string_view to_string(Identity i) noexcept {
    switch (i) {
        case Identity::kNone:   return "none";
        case Identity::kSuci:   return "SUCI";
        case Identity::kGuti:   return "5G-GUTI";
        case Identity::kImei:   return "IMEI";
        case Identity::kSTmsi:  return "5G-S-TMSI";
        case Identity::kImeisv: return "IMEISV";
        case Identity::kOther:  return "other";
    }
    return "other";
}

Result<Info> decode(std::span<const std::uint8_t> pdu, std::optional<std::uint8_t> cipher_alg) {
    ByteReader r{pdu};
    const auto epd = r.u8();
    if (!epd) {
        return DecodeError::kTruncated;
    }
    Info info;
    if (*epd == kEpd5gsm) {
        info.is_5gsm = true;
        const auto psi = r.u8();
        const auto pti = r.u8();
        const auto type = r.u8();
        if (!psi || !pti || !type) {
            return DecodeError::kTruncated;
        }
        info.decoded = true;
        info.message_type = *type;
        info.message = sm_message_name(*type);
        info.pdu_session_id = psi;
        return info;
    }
    if (*epd != kEpd5gmm) {
        return DecodeError::kUnsupported;
    }
    const auto sht_byte = r.u8();
    if (!sht_byte) {
        return DecodeError::kTruncated;
    }
    info.security_header = static_cast<std::uint8_t>(*sht_byte & 0x0FU);
    if (info.security_header > 4) {
        return DecodeError::kMalformed;
    }
    if (info.security_header != 0) {
        info.integrity_protected = true;
        info.ciphered = info.security_header == 2 || info.security_header == 4;
        if (!r.skip(5)) {  // MAC + sequence number
            return DecodeError::kTruncated;
        }
        if (info.ciphered && cipher_alg != kNea0) {
            info.decoded = false;
            info.message = "Protected";
            return info;
        }
        // Inner plain 5GMM header.
        const auto inner_epd = r.u8();
        const auto inner_sht = r.u8();
        if (!inner_epd || !inner_sht) {
            return DecodeError::kTruncated;
        }
        if (*inner_epd != kEpd5gmm || (*inner_sht & 0x0FU) != 0) {
            return DecodeError::kMalformed;
        }
    }
    const auto type = r.u8();
    if (!type) {
        return DecodeError::kTruncated;
    }
    info.decoded = true;
    info.message_type = *type;
    info.message = mm_message_name(*type);
    if (auto ok = parse_mm_body(*type, r, info); !ok) {
        return ok.error();
    }
    return info;
}

std::string_view mm_message_name(std::uint8_t type) noexcept {
    switch (type) {
        case 0x41: return "RegistrationRequest";
        case 0x42: return "RegistrationAccept";
        case 0x43: return "RegistrationComplete";
        case 0x44: return "RegistrationReject";
        case 0x45: return "DeregistrationRequestUEOriginating";
        case 0x46: return "DeregistrationAcceptUEOriginating";
        case 0x47: return "DeregistrationRequestUETerminated";
        case 0x48: return "DeregistrationAcceptUETerminated";
        case 0x4C: return "ServiceRequest";
        case 0x4D: return "ServiceReject";
        case 0x4E: return "ServiceAccept";
        case 0x54: return "ConfigurationUpdateCommand";
        case 0x55: return "ConfigurationUpdateComplete";
        case 0x56: return "AuthenticationRequest";
        case 0x57: return "AuthenticationResponse";
        case 0x58: return "AuthenticationReject";
        case 0x59: return "AuthenticationFailure";
        case 0x5A: return "AuthenticationResult";
        case 0x5B: return "IdentityRequest";
        case 0x5C: return "IdentityResponse";
        case 0x5D: return "SecurityModeCommand";
        case 0x5E: return "SecurityModeComplete";
        case 0x5F: return "SecurityModeReject";
        case 0x64: return "5GMMStatus";
        case 0x65: return "Notification";
        case 0x66: return "NotificationResponse";
        case 0x67: return "ULNASTransport";
        case 0x68: return "DLNASTransport";
        default:   return "Unknown5GMM";
    }
}

std::string_view sm_message_name(std::uint8_t type) noexcept {
    switch (type) {
        case 0xC1: return "PDUSessionEstablishmentRequest";
        case 0xC2: return "PDUSessionEstablishmentAccept";
        case 0xC3: return "PDUSessionEstablishmentReject";
        case 0xC5: return "PDUSessionAuthenticationCommand";
        case 0xC6: return "PDUSessionAuthenticationComplete";
        case 0xC7: return "PDUSessionAuthenticationResult";
        case 0xC9: return "PDUSessionModificationRequest";
        case 0xCA: return "PDUSessionModificationReject";
        case 0xCB: return "PDUSessionModificationCommand";
        case 0xCC: return "PDUSessionModificationComplete";
        case 0xCD: return "PDUSessionModificationCommandReject";
        case 0xD1: return "PDUSessionReleaseRequest";
        case 0xD2: return "PDUSessionReleaseReject";
        case 0xD3: return "PDUSessionReleaseCommand";
        case 0xD4: return "PDUSessionReleaseComplete";
        case 0xD6: return "5GSMStatus";
        default:   return "Unknown5GSM";
    }
}

}  // namespace prahari::nas
