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
    std::optional<std::uint64_t> ue_seid;
    std::optional<std::uint32_t> sequence;
    std::optional<std::string_view> cause;
    std::optional<PfcpContext> pfcp;
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
