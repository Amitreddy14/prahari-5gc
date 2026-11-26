// SPDX-License-Identifier: MIT
// SignallingEvent v1 (schemas/event.v1.schema.json) and its JSON serialisation.
#pragma once

#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <string_view>

namespace prahari {

struct Endpoint {
    std::string ip;
    std::uint16_t port{};
    std::string_view nf{"unknown"};
};

struct PfcpContext {
    std::optional<std::uint64_t> cp_seid;
    std::optional<std::uint64_t> up_seid;
    std::string_view session_state;  // empty = omit
    std::optional<bool> session_known;
    std::optional<std::string> node_id;
    std::optional<std::uint8_t> cause_code;
    std::optional<std::size_t> ie_count;
    std::optional<std::size_t> pdr_count;
    std::optional<std::size_t> far_count;
};

struct NgapContext {
    std::string_view pdu_type;
    std::uint8_t procedure_code{};
    std::size_t ie_count{};
    std::optional<std::uint32_t> gnb_id;
    std::optional<std::uint8_t> gnb_id_bits;
    std::optional<std::string> plmn;
    std::optional<std::string> ran_node_name;
};

struct NasContext {
    std::string_view epd;  // "5GMM" | "5GSM"
    std::uint8_t security_header{};
    bool integrity_protected{};
    bool ciphered{};
    bool decoded{};
    std::uint8_t message_type{};
    std::string_view message;
    std::string_view registration_type;  // empty = omit
    std::string_view identity_type;      // empty = omit
    std::optional<bool> suci_null_scheme;
    std::optional<std::uint8_t> sm_message_type;
    std::string_view sm_message;  // empty = omit
    std::optional<std::uint8_t> selected_ciphering;
    std::optional<std::uint8_t> selected_integrity;
    std::optional<std::uint8_t> mm_cause;
};

struct SbiContext {
    std::string_view method;  // empty = omit (only the schema's methods are emitted)
    std::string path;         // sanitised by sbi::parse_target
    std::optional<int> status;
    std::string service;       // empty = omit
    std::string content_type;  // empty = omit; media type only, parameters dropped
};

struct UeIds {
    std::optional<std::uint32_t> ran_ue_ngap_id;
    std::optional<std::uint64_t> amf_ue_ngap_id;
    std::optional<std::string> supi_hash;
    std::optional<std::uint64_t> seid;
    std::optional<std::uint8_t> pdu_session_id;
    [[nodiscard]] bool empty() const noexcept {
        return !ran_ue_ngap_id && !amf_ue_ngap_id && !supi_hash && !seid && !pdu_session_id;
    }
};

struct Event {
    std::string event_id;
    std::uint64_t ts_ns{};
    std::string_view interface;  // "N2" | "N4" | "SBI"
    std::string_view protocol;   // "NGAP" | "NAS-5GS" | "PFCP" | "HTTP2"
    std::string_view message;
    std::uint16_t message_code{};
    std::string_view direction{"unknown"};
    Endpoint src;
    Endpoint dst;
    std::size_t size_bytes{};
    std::string_view decode_status{"ok"};
    UeIds ue;
    std::optional<std::uint32_t> sequence;
    std::optional<std::string_view> cause;
    std::optional<PfcpContext> pfcp;
    std::optional<NgapContext> ngap;
    std::optional<NasContext> nas;
    std::optional<SbiContext> sbi;
};

// Appends one JSON object (no trailing newline) to `out`.
void append_json(const Event& e, std::string& out);

// Appends `s` as a JSON string literal (quoted, escaped) to `out`.
void append_json_string(std::string_view s, std::string& out);

// RFC 9562 version-4 UUIDs from a seeded 64-bit PRNG. Not for security purposes:
// event IDs only need to be unique, not unpredictable.
class UuidGenerator {
public:
    UuidGenerator();
    explicit UuidGenerator(std::uint64_t seed) : rng_(seed) {}
    [[nodiscard]] std::string next();

private:
    std::mt19937_64 rng_;
};

}  // namespace prahari
