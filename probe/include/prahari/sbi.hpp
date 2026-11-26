// SPDX-License-Identifier: MIT
// 5G Service Based Interface (TS 29.500 / 29.501) helpers on top of HTTP/2:
// service and operation naming, path sanitisation, and subscriber-identity
// extraction for pseudonymisation.
//
// Privacy: SBI paths and bodies carry SUPIs ("imsi-…"), SUCIs (null scheme exposes
// the MSIN), GPSIs ("msisdn-…") and NAIs. sanitize_path() replaces every such path
// segment with a placeholder ("{supi}", "{suci}", "{gpsi}", "{nai}") and drops the
// query string; the IMSI it finds is returned separately so the caller can hash it.
// Bodies are never emitted: only the IMSI, PDU session ID and ProblemDetails cause
// are extracted from them.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace prahari::sbi {

struct Target {
    std::string path;                 // sanitised, no query string, at most kMaxPath bytes
    std::string service;              // first segment, e.g. "nudm-sdm" (empty if not an SBI path)
    std::optional<std::string> imsi;  // 5-15 digits, from a SUPI or a null-scheme SUCI
    bool had_identity{};              // some identity segment was replaced
};

inline constexpr std::size_t kMaxPath = 256;
inline constexpr std::size_t kMaxService = 32;

[[nodiscard]] Target parse_target(std::string_view raw_path);

// 3GPP service-operation name for a request, e.g. ("nnrf-disc", GET, "/nnrf-disc/v1/
// nf-instances") -> "NFDiscover". Unknown operations: "<METHOD> <service>".
[[nodiscard]] std::string operation_name(std::string_view method, const Target& t);

// IMSI digits from "imsi-<digits>" or a null-scheme "suci-0-<mcc>-<mnc>-…-0-…-<msin>".
[[nodiscard]] std::optional<std::string> imsi_from_identity(std::string_view id);

// First SUPI / null-scheme SUCI anywhere in a body (JSON or multipart).
[[nodiscard]] std::optional<std::string> find_imsi(std::string_view body);

// "pduSessionId": N in a JSON body.
[[nodiscard]] std::optional<std::uint8_t> find_pdu_session_id(std::string_view body);

// ProblemDetails "cause" (TS 29.571): upper-case letters, digits and '_', <= 64 chars.
[[nodiscard]] std::optional<std::string> find_problem_cause(std::string_view body);

}  // namespace prahari::sbi
