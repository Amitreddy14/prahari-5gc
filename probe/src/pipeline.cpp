// SPDX-License-Identifier: MIT
#include "prahari/pipeline.hpp"

#include <array>
#include <fstream>
#include <sstream>

#include "prahari/pfcp.hpp"
#include "prahari/pfcp_ie.hpp"
#include <arpa/inet.h>

namespace prahari {

namespace {

// Allowed NF names: must match the schema's endpoint.nf enum.
constexpr std::array<std::string_view, 13> kNfNames{
    "gNB", "AMF", "SMF", "UPF", "NRF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "BSF", "UE", "unknown"};

std::string_view canonical_nf(std::string_view name) {
    for (const auto n : kNfNames) {
        if (n == name) {
            return n;  // static storage: safe to keep as a view
        }
    }
    return {};
}

std::string_view pfcp_direction(std::uint8_t type) {
    if (type >= 50 && type <= 57) {
        return type % 2 == 0 ? "request" : "response";
    }
    if (type == 11) {
        return "response";  // Version Not Supported Response
    }
    if (type >= 1 && type <= 15) {
        return type % 2 == 1 ? "request" : "response";
    }
    return "unknown";
}

constexpr int kMaxFollowOn = 16;

}  // namespace

// ---------------------------------------------------------------------------- NfMap

NfMap NfMap::testbed_default() {
    NfMap m;
    const std::array<std::pair<std::uint32_t, std::string_view>, 13> entries{{
        {0xAC160005, "AMF"},
        {0xAC160007, "SMF"},
        {0xAC160008, "UPF"},
        {0xAC16000A, "NRF"},
        {0xAC16000B, "AUSF"},
        {0xAC16000C, "UDM"},
        {0xAC16000D, "UDR"},
        {0xAC16000E, "PCF"},
        {0xAC16000F, "NSSF"},
        {0xAC160010, "BSF"},
        {0xAC160014, "gNB"},
        {0xAC160015, "UE"},
        {0xAC16001E, "unknown"},  // MongoDB: not a 3GPP NF
    }};
    for (const auto& [ip, nf] : entries) {
        m.set(net::IpAddress::v4_from(ip), nf);
    }
    return m;
}

void NfMap::set(const net::IpAddress& ip, std::string_view nf) {
    const auto canon = canonical_nf(nf);
    map_[ip] = canon.empty() ? std::string_view{"unknown"} : canon;
}

std::string_view NfMap::lookup(const net::IpAddress& ip) const {
    const auto it = map_.find(ip);
    return it == map_.end() ? std::string_view{"unknown"} : it->second;
}

namespace {
std::string where(const std::string& path, int lineno) {
    std::string w{path};
    w.append(":").append(std::to_string(lineno)).append(": ");
    return w;
}
}  // namespace

bool NfMap::load_file(const std::string& path, std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error.assign("cannot read NF map '").append(path).append("'");
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        if (const auto hash = line.find('#'); hash != std::string::npos) {
            line.erase(hash);
        }
        std::istringstream fields(line);
        std::string ip;
        std::string nf;
        if (!(fields >> ip)) {
            continue;  // blank or comment-only line
        }
        if (!(fields >> nf)) {
            error = where(path, lineno).append("expected 'IP NF'");
            return false;
        }
        if (canonical_nf(nf).empty()) {
            error = where(path, lineno).append("unknown NF '").append(nf).append("'");
            return false;
        }
        net::IpAddress addr;
        if (inet_pton(AF_INET, ip.c_str(), addr.bytes.data()) == 1) {
            addr.v6 = false;
        } else if (inet_pton(AF_INET6, ip.c_str(), addr.bytes.data()) == 1) {
            addr.v6 = true;
        } else {
            error = where(path, lineno).append("bad IP '").append(ip).append("'");
            return false;
        }
        set(addr, nf);
    }
    return true;
}

// ---------------------------------------------------------------------------- sinks

StreamSink::StreamSink(std::FILE* f, std::size_t batch_bytes) : f_(f), batch_bytes_(batch_bytes) {
    // Unbuffered stdio: our buffer decides the write boundaries, always at '\n'.
    (void)std::setvbuf(f_, nullptr, _IONBF, 0);
    buf_.reserve(batch_bytes_ + 4096);
}

StreamSink::~StreamSink() {
    flush();
}

void StreamSink::write(std::string_view json_line) {
    buf_.append(json_line);
    buf_.push_back('\n');
    if (buf_.size() >= batch_bytes_) {
        flush();
    }
}

void StreamSink::flush() {
    if (buf_.empty()) {
        return;
    }
    // One write call per batch of whole lines.
    (void)std::fwrite(buf_.data(), 1, buf_.size(), f_);
    buf_.clear();
}

// ---------------------------------------------------------------------------- stats

std::string stats_json(const Stats& s, const pfcp::SessionTable& t) {
    std::ostringstream o;
    o << "{\"frames\":" << s.frames << ",\"bytes\":" << s.bytes
      << ",\"link_errors\":" << s.link_errors << ",\"not_ip\":" << s.not_ip << ",\"udp\":" << s.udp
      << ",\"tcp\":" << s.tcp << ",\"sctp\":" << s.sctp
      << ",\"sctp_data_chunks\":" << s.sctp_data_chunks << ",\"ngap_chunks\":" << s.ngap_chunks
      << ",\"pfcp_messages\":" << s.pfcp_messages
      << ",\"pfcp_decode_errors\":" << s.pfcp_decode_errors
      << ",\"pfcp_unknown_session\":" << s.pfcp_unknown_session << ",\"events\":" << s.events
      << ",\"sessions_tracked\":" << t.size() << ",\"sessions_active\":" << t.active()
      << ",\"sessions_expired\":" << t.expired_establishing()
      << ",\"sessions_dropped_full\":" << t.dropped_table_full() << "}";
    return o.str();
}

// ---------------------------------------------------------------------------- pipeline

void Pipeline::emit(const Event& e) {
    line_.clear();
    append_json(e, line_);
    sink_.write(line_);
    ++stats_.events;
}

void Pipeline::on_frame(std::uint64_t ts_ns, net::LinkType link,
                        std::span<const std::uint8_t> frame) {
    ++stats_.frames;
    stats_.bytes += frame.size();
    const auto pkt = net::decode_frame(link, frame);
    if (!pkt) {
        if (pkt.error() == DecodeError::kUnsupported) {
            ++stats_.not_ip;
        } else {
            ++stats_.link_errors;
        }
        return;
    }
    const auto& p = pkt.value();
    switch (p.transport) {
        case net::Transport::kUdp:
            ++stats_.udp;
            if (p.src_port == net::kPortPfcp || p.dst_port == net::kPortPfcp) {
                on_pfcp(ts_ns, p);
            }
            break;
        case net::Transport::kTcp: ++stats_.tcp; break;
        case net::Transport::kSctp:
            ++stats_.sctp;
            stats_.sctp_data_chunks += p.sctp_data.size();
            for (const auto& d : p.sctp_data) {
                if (d.ppid == net::kPpidNgap) {
                    ++stats_.ngap_chunks;
                }
            }
            break;
        case net::Transport::kOther: break;
    }
}

void Pipeline::on_pfcp(std::uint64_t ts_ns, const net::Packet& pkt) {
    Event e;
    e.ts_ns = ts_ns;
    e.interface = "N4";
    e.protocol = "PFCP";
    e.src = Endpoint{pkt.src.to_string(), pkt.src_port, nf_map_.lookup(pkt.src)};
    e.dst = Endpoint{pkt.dst.to_string(), pkt.dst_port, nf_map_.lookup(pkt.dst)};

    auto rest = pkt.payload;
    for (int i = 0; i < kMaxFollowOn && !rest.empty(); ++i) {
        ++stats_.pfcp_messages;
        Event ev = e;
        ev.event_id = uuids_.next();
        const auto msg = pfcp::decode(rest);
        if (!msg) {
            ++stats_.pfcp_decode_errors;
            ev.message = "Undecodable";
            ev.message_code = rest.size() >= 2 ? rest[1] : 0;
            ev.size_bytes = rest.size();
            ev.decode_status = to_string(msg.error());
            emit(ev);
            return;  // cannot find the next message boundary
        }
        const auto& h = msg.value().header;
        ev.message = pfcp::message_name(h.message_type);
        ev.message_code = h.message_type;
        ev.direction = pfcp_direction(h.message_type);
        ev.size_bytes = h.total_length();
        ev.sequence = h.sequence;

        PfcpContext ctx;
        const auto summary = pfcp::summarize(msg.value().body);
        if (summary) {
            const auto& s = summary.value();
            ctx.ie_count = s.ie_count;
            if (s.pdr_groups > 0) {
                ctx.pdr_count = s.pdr_groups;
            }
            if (s.far_groups > 0) {
                ctx.far_count = s.far_groups;
            }
            ctx.node_id = s.node_id;
            if (s.cause) {
                ctx.cause_code = s.cause;
                ev.cause = pfcp::cause_name(*s.cause);
            }
        } else {
            ++stats_.pfcp_decode_errors;
            ev.decode_status = to_string(summary.error());
        }

        if (pfcp::is_session_message(h.message_type)) {
            pfcp::SessionMessage sm;
            sm.type = h.message_type;
            sm.src = pkt.src;
            sm.dst = pkt.dst;
            sm.header_seid = h.seid;
            sm.ts_ns = ts_ns;
            if (summary) {
                if (const auto& fs = summary.value().f_seid; fs.has_value()) {
                    sm.f_seid = fs->seid;
                }
                sm.cause = summary.value().cause;
            }
            const auto view = sessions_.apply(sm);
            ctx.cp_seid = view.cp_seid;
            ctx.up_seid = view.up_seid;
            ctx.session_state = pfcp::to_string(view.state);
            ctx.session_known = view.known;
            if (!view.known) {
                ++stats_.pfcp_unknown_session;
            }
            ev.ue_seid = view.up_seid ? view.up_seid : view.cp_seid;
        }
        ev.pfcp = ctx;
        emit(ev);

        if (!h.follow_on) {
            break;
        }
        rest = rest.subspan(h.total_length());
    }
}

}  // namespace prahari
