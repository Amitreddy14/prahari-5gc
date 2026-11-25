// SPDX-License-Identifier: MIT
#include "prahari/event.hpp"

#include <array>
#include <charconv>

namespace prahari {

namespace {

void append_uint(std::uint64_t v, std::string& out) {
    std::array<char, 24> buf{};
    const auto res = std::to_chars(buf.data(), buf.data() + buf.size(), v);
    out.append(buf.data(), res.ptr);
}

void key(std::string_view k, std::string& out) {
    out.push_back('"');
    out.append(k);
    out.append("\":");
}

void append_endpoint(const Endpoint& ep, std::string& out) {
    out.append("{\"ip\":");
    append_json_string(ep.ip, out);
    out.append(",\"port\":");
    append_uint(ep.port, out);
    out.append(",\"nf\":");
    append_json_string(ep.nf, out);
    out.push_back('}');
}

void append_seid(std::string_view k, std::uint64_t seid, std::string& out) {
    // SEIDs are u64: emitted as decimal strings because JSON numbers lose
    // precision above 2^53 in most consumers.
    key(k, out);
    out.push_back('"');
    append_uint(seid, out);
    out.push_back('"');
}

}  // namespace

void append_json_string(std::string_view s, std::string& out) {
    static constexpr std::array<char, 16> kHex{'0', '1', '2', '3', '4', '5', '6', '7',
                                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    out.push_back('"');
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
            case '"':  out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (u < 0x20U) {
                    out.append("\\u00");
                    out.push_back(kHex[u >> 4U]);
                    out.push_back(kHex[u & 0x0FU]);
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

void append_json(const Event& e, std::string& out) {
    out.append(R"({"schema_version":1,"event_id":)");
    append_json_string(e.event_id, out);
    out.append(",\"ts_ns\":");
    append_uint(e.ts_ns, out);
    out.append(",\"interface\":");
    append_json_string(e.interface, out);
    out.append(",\"protocol\":");
    append_json_string(e.protocol, out);
    out.append(",\"message\":");
    append_json_string(e.message, out);
    out.append(",\"message_code\":");
    append_uint(e.message_code, out);
    out.append(",\"direction\":");
    append_json_string(e.direction, out);
    out.append(",\"src\":");
    append_endpoint(e.src, out);
    out.append(",\"dst\":");
    append_endpoint(e.dst, out);
    out.append(",\"size_bytes\":");
    append_uint(e.size_bytes, out);
    out.append(",\"decode_status\":");
    append_json_string(e.decode_status, out);
    if (e.ue_seid) {
        out.append(",\"ue\":{");
        append_seid("seid", *e.ue_seid, out);
        out.push_back('}');
    }
    if (e.sequence) {
        out.append(",\"sequence\":");
        append_uint(*e.sequence, out);
    }
    if (e.cause) {
        out.append(",\"cause\":");
        append_json_string(*e.cause, out);
    }
    if (e.pfcp) {
        const auto& p = *e.pfcp;
        out.append(",\"pfcp\":{");
        bool first = true;
        auto sep = [&] {
            if (!first) {
                out.push_back(',');
            }
            first = false;
        };
        if (p.cp_seid) {
            sep();
            append_seid("cp_seid", *p.cp_seid, out);
        }
        if (p.up_seid) {
            sep();
            append_seid("up_seid", *p.up_seid, out);
        }
        if (!p.session_state.empty()) {
            sep();
            key("session_state", out);
            append_json_string(p.session_state, out);
        }
        if (p.session_known) {
            sep();
            key("session_known", out);
            out.append(*p.session_known ? "true" : "false");
        }
        if (p.node_id) {
            sep();
            key("node_id", out);
            append_json_string(*p.node_id, out);
        }
        if (p.cause_code) {
            sep();
            key("cause_code", out);
            append_uint(*p.cause_code, out);
        }
        if (p.ie_count) {
            sep();
            key("ie_count", out);
            append_uint(*p.ie_count, out);
        }
        if (p.pdr_count) {
            sep();
            key("pdr_count", out);
            append_uint(*p.pdr_count, out);
        }
        if (p.far_count) {
            sep();
            key("far_count", out);
            append_uint(*p.far_count, out);
        }
        out.push_back('}');
    }
    out.push_back('}');
}

namespace {
std::uint64_t random_seed() {
    std::random_device rd;
    return (static_cast<std::uint64_t>(rd()) << 32U) ^ rd();
}
}  // namespace

UuidGenerator::UuidGenerator() : rng_(random_seed()) {}

std::string UuidGenerator::next() {
    static constexpr std::array<char, 16> kHex{'0', '1', '2', '3', '4', '5', '6', '7',
                                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::uint64_t hi = rng_();
    std::uint64_t lo = rng_();
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // version 4
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // RFC variant
    std::string s;
    s.reserve(36);
    for (int i = 15; i >= 0; --i) {
        const auto shift = static_cast<unsigned>(i) * 4U;
        s.push_back(kHex[(hi >> shift) & 0xFU]);
        if (i == 8 || i == 4) {
            s.push_back('-');
        }
    }
    s.push_back('-');
    for (int i = 15; i >= 0; --i) {
        const auto shift = static_cast<unsigned>(i) * 4U;
        s.push_back(kHex[(lo >> shift) & 0xFU]);
        if (i == 12) {
            s.push_back('-');
        }
    }
    return s;
}

}  // namespace prahari
