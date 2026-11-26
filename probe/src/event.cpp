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

namespace {

// Writes `"key":value` members of one JSON object, handling the commas.
class Obj {
public:
    explicit Obj(std::string& out) : out_(out) { out_.push_back('{'); }
    Obj(const Obj&) = delete;
    Obj& operator=(const Obj&) = delete;
    Obj(Obj&&) = delete;
    Obj& operator=(Obj&&) = delete;
    ~Obj() { out_.push_back('}'); }

    void str(std::string_view k, std::string_view v) {
        key(k);
        append_json_string(v, out_);
    }
    void num(std::string_view k, std::uint64_t v) {
        key(k);
        append_uint(v, out_);
    }
    void boolean(std::string_view k, bool v) {
        key(k);
        out_.append(v ? "true" : "false");
    }
    // u64 identifiers as decimal strings (JSON numbers lose precision above 2^53).
    void id_str(std::string_view k, std::uint64_t v) {
        key(k);
        out_.push_back('"');
        append_uint(v, out_);
        out_.push_back('"');
    }
    void opt_num(std::string_view k, const auto& v) {
        if (v) {
            num(k, *v);
        }
    }
    void opt_str(std::string_view k, std::string_view v) {
        if (!v.empty()) {
            str(k, v);
        }
    }
    // Start a nested member; the caller builds the nested Obj next.
    void key(std::string_view k) {
        if (!first_) {
            out_.push_back(',');
        }
        first_ = false;
        out_.push_back('"');
        out_.append(k);
        out_.append("\":");
    }

private:
    std::string& out_;
    bool first_{true};
};

void endpoint(Obj& parent, std::string_view k, const Endpoint& ep, std::string& out) {
    parent.key(k);
    Obj o{out};
    o.str("ip", ep.ip);
    o.num("port", ep.port);
    o.str("nf", ep.nf);
}

}  // namespace

void append_json(const Event& e, std::string& out) {
    Obj o{out};
    o.num("schema_version", 1);
    o.str("event_id", e.event_id);
    o.num("ts_ns", e.ts_ns);
    o.str("interface", e.interface);
    o.str("protocol", e.protocol);
    o.str("message", e.message);
    o.num("message_code", e.message_code);
    o.str("direction", e.direction);
    endpoint(o, "src", e.src, out);
    endpoint(o, "dst", e.dst, out);
    o.num("size_bytes", e.size_bytes);
    o.str("decode_status", e.decode_status);
    if (!e.ue.empty()) {
        o.key("ue");
        Obj u{out};
        u.opt_num("ran_ue_ngap_id", e.ue.ran_ue_ngap_id);
        u.opt_num("amf_ue_ngap_id", e.ue.amf_ue_ngap_id);
        if (e.ue.supi_hash) {
            u.str("supi_hash", *e.ue.supi_hash);
        }
        if (e.ue.seid) {
            u.id_str("seid", *e.ue.seid);
        }
        u.opt_num("pdu_session_id", e.ue.pdu_session_id);
    }
    o.opt_num("sequence", e.sequence);
    if (e.cause) {
        o.str("cause", *e.cause);
    }
    if (e.pfcp) {
        const auto& p = *e.pfcp;
        o.key("pfcp");
        Obj c{out};
        if (p.cp_seid) {
            c.id_str("cp_seid", *p.cp_seid);
        }
        if (p.up_seid) {
            c.id_str("up_seid", *p.up_seid);
        }
        c.opt_str("session_state", p.session_state);
        if (p.session_known) {
            c.boolean("session_known", *p.session_known);
        }
        if (p.node_id) {
            c.str("node_id", *p.node_id);
        }
        c.opt_num("cause_code", p.cause_code);
        c.opt_num("ie_count", p.ie_count);
        c.opt_num("pdr_count", p.pdr_count);
        c.opt_num("far_count", p.far_count);
    }
    if (e.ngap) {
        const auto& n = *e.ngap;
        o.key("ngap");
        Obj c{out};
        c.str("pdu_type", n.pdu_type);
        c.num("procedure_code", n.procedure_code);
        c.num("ie_count", n.ie_count);
        c.opt_num("gnb_id", n.gnb_id);
        c.opt_num("gnb_id_bits", n.gnb_id_bits);
        if (n.plmn) {
            c.str("plmn", *n.plmn);
        }
        if (n.ran_node_name) {
            c.str("ran_node_name", *n.ran_node_name);
        }
    }
    if (e.nas) {
        const auto& n = *e.nas;
        o.key("nas");
        Obj c{out};
        c.str("epd", n.epd);
        c.num("security_header", n.security_header);
        c.boolean("integrity_protected", n.integrity_protected);
        c.boolean("ciphered", n.ciphered);
        c.boolean("decoded", n.decoded);
        c.num("message_type", n.message_type);
        c.str("message", n.message);
        c.opt_str("registration_type", n.registration_type);
        c.opt_str("identity_type", n.identity_type);
        if (n.suci_null_scheme) {
            c.boolean("suci_null_scheme", *n.suci_null_scheme);
        }
        c.opt_num("sm_message_type", n.sm_message_type);
        c.opt_str("sm_message", n.sm_message);
        c.opt_num("selected_ciphering", n.selected_ciphering);
        c.opt_num("selected_integrity", n.selected_integrity);
        c.opt_num("mm_cause", n.mm_cause);
    }
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
