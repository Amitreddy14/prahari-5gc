// SPDX-License-Identifier: MIT
#include "prahari/pipeline.hpp"

#include <array>
#include <fstream>
#include <sstream>

#include "prahari/nas.hpp"
#include "prahari/ngap.hpp"
#include "prahari/pfcp.hpp"
#include "prahari/pfcp_ie.hpp"
#include "prahari/sbi.hpp"
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
constexpr std::uint16_t kNgapPort = 38412;

std::string_view registration_type_name(std::uint8_t t) {
    switch (t) {
        case 1:  return "initial";
        case 2:  return "mobility";
        case 3:  return "periodic";
        case 4:  return "emergency";
        default: return "other";
    }
}

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

std::string stats_json(const Stats& s, const pfcp::SessionTable& t, const ngap::UeTable& u,
                       std::size_t sbi_flows) {
    std::ostringstream o;
    o << "{\"frames\":" << s.frames << ",\"bytes\":" << s.bytes
      << ",\"link_errors\":" << s.link_errors << ",\"not_ip\":" << s.not_ip << ",\"udp\":" << s.udp
      << ",\"tcp\":" << s.tcp << ",\"sctp\":" << s.sctp
      << ",\"sctp_data_chunks\":" << s.sctp_data_chunks << ",\"ngap_chunks\":" << s.ngap_chunks
      << ",\"ngap_messages\":" << s.ngap_messages
      << ",\"ngap_decode_errors\":" << s.ngap_decode_errors
      << ",\"nas_messages\":" << s.nas_messages << ",\"nas_opaque\":" << s.nas_opaque
      << ",\"nas_decode_errors\":" << s.nas_decode_errors << ",\"supi_hashed\":" << s.supi_hashed
      << ",\"supi_not_hashed\":" << s.supi_not_hashed << ",\"pfcp_messages\":" << s.pfcp_messages
      << ",\"pfcp_decode_errors\":" << s.pfcp_decode_errors
      << ",\"pfcp_unknown_session\":" << s.pfcp_unknown_session
      << ",\"sbi_segments\":" << s.sbi_segments
      << ",\"sbi_midstream_segments\":" << s.sbi_midstream_segments
      << ",\"sbi_flows_opened\":" << s.sbi_flows_opened
      << ",\"sbi_flows_closed\":" << s.sbi_flows_closed
      << ",\"sbi_flows_expired\":" << s.sbi_flows_expired
      << ",\"sbi_flows_dropped_full\":" << s.sbi_flows_dropped_full
      << ",\"sbi_flows_open\":" << sbi_flows << ",\"sbi_tcp_gaps\":" << s.sbi_tcp_gaps
      << ",\"sbi_http2_errors\":" << s.sbi_http2_errors << ",\"sbi_requests\":" << s.sbi_requests
      << ",\"sbi_responses\":" << s.sbi_responses << ",\"events\":" << s.events
      << ",\"sessions_tracked\":" << t.size() << ",\"sessions_active\":" << t.active()
      << ",\"sessions_expired\":" << t.expired_establishing()
      << ",\"sessions_dropped_full\":" << t.dropped_table_full() << ",\"ue_contexts\":" << u.size()
      << ",\"ue_contexts_expired\":" << u.expired()
      << ",\"ue_contexts_dropped_full\":" << u.dropped_full() << "}";
    return o.str();
}

// ---------------------------------------------------------------------------- pipeline

void Pipeline::emit(const Event& e) {
    line_.clear();
    append_json(e, line_);
    if (e.ue.supi_hash) {
        sink_.write_keyed(line_, *e.ue.supi_hash);
    } else {
        sink_.write(line_);
    }
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
        case net::Transport::kTcp:
            ++stats_.tcp;
            if (sbi_ports_.contains(p.src_port) || sbi_ports_.contains(p.dst_port)) {
                on_sbi_segment(ts_ns, p);
            }
            break;
        case net::Transport::kSctp:
            ++stats_.sctp;
            stats_.sctp_data_chunks += p.sctp_data.size();
            for (const auto& d : p.sctp_data) {
                if (d.ppid == net::kPpidNgap) {
                    ++stats_.ngap_chunks;
                    on_ngap(ts_ns, p, d.payload);
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
            if (summary && summary.value().has_user_id) {
                sm.supi_hash = pseudonym(pfcp::user_id_imsi(summary.value().user_id));
            }
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
            ev.ue.seid = view.up_seid ? view.up_seid : view.cp_seid;
            ev.ue.supi_hash = view.supi_hash;
        }
        ev.pfcp = ctx;
        emit(ev);

        if (!h.follow_on) {
            break;
        }
        rest = rest.subspan(h.total_length());
    }
}

void Pipeline::on_ngap(std::uint64_t ts_ns, const net::Packet& pkt,
                       std::span<const std::uint8_t> pdu) {
    ++stats_.ngap_messages;
    Event ev;
    ev.event_id = uuids_.next();
    ev.ts_ns = ts_ns;
    ev.interface = "N2";
    ev.protocol = "NGAP";
    ev.src = Endpoint{pkt.src.to_string(), pkt.src_port, nf_map_.lookup(pkt.src)};
    ev.dst = Endpoint{pkt.dst.to_string(), pkt.dst_port, nf_map_.lookup(pkt.dst)};
    ev.size_bytes = pdu.size();

    // The AMF listens on 38412; the other side is the gNB (or something posing as one).
    const bool uplink = pkt.dst_port == kNgapPort ||
                        (pkt.src_port != kNgapPort && nf_map_.lookup(pkt.src) == "gNB");
    const net::IpAddress& gnb = uplink ? pkt.src : pkt.dst;

    const auto decoded = ngap::decode(pdu);
    if (!decoded) {
        ++stats_.ngap_decode_errors;
        ev.message = "Undecodable";
        ev.message_code = pdu.size() >= 2 ? pdu[1] : 0;
        ev.decode_status = to_string(decoded.error());
        emit(ev);
        return;
    }
    const auto& m = decoded.value();
    const std::string name = ngap::message_name(m.procedure_code, m.pdu_type);
    ev.message = name;
    ev.message_code = m.procedure_code;
    if (m.pdu_type == ngap::PduType::kInitiating) {
        ev.direction = ngap::is_class2(m.procedure_code) ? "indication" : "request";
    } else {
        ev.direction = "response";
    }

    NgapContext nctx;
    nctx.pdu_type = ngap::to_string(m.pdu_type);
    nctx.procedure_code = m.procedure_code;
    nctx.ie_count = m.ies.size();
    if (m.global_gnb_id) {
        nctx.gnb_id = m.global_gnb_id->gnb_id;
        nctx.gnb_id_bits = m.global_gnb_id->gnb_id_bits;
        nctx.plmn = m.global_gnb_id->plmn;
    }
    nctx.ran_node_name = m.ran_node_name;
    ev.ngap = nctx;

    ngap::UeContext* ue = nullptr;
    if (m.ran_ue_ngap_id) {
        ue = ues_.touch(gnb, *m.ran_ue_ngap_id, ts_ns);
        ev.ue.ran_ue_ngap_id = m.ran_ue_ngap_id;
    }
    if (ue != nullptr && m.amf_ue_ngap_id) {
        ue->amf_ue_ngap_id = m.amf_ue_ngap_id;
    }
    ev.ue.amf_ue_ngap_id = m.amf_ue_ngap_id;

    if (!m.nas_pdus.empty()) {
        ++stats_.nas_messages;
        const auto cipher = ue != nullptr ? ue->cipher_alg : std::nullopt;
        const auto info = nas::decode(m.nas_pdus.front(), cipher);
        if (!info) {
            ++stats_.nas_decode_errors;
            ev.decode_status = to_string(info.error());
        } else {
            const auto& n = info.value();
            NasContext c;
            c.epd = n.is_5gsm ? "5GSM" : "5GMM";
            c.security_header = n.security_header;
            c.integrity_protected = n.integrity_protected;
            c.ciphered = n.ciphered;
            c.decoded = n.decoded;
            c.message_type = n.message_type;
            c.message = n.message;
            if (n.registration_type) {
                c.registration_type = registration_type_name(*n.registration_type);
            }
            if (n.identity) {
                c.identity_type = nas::to_string(*n.identity);
            }
            c.suci_null_scheme = n.suci_null_scheme;
            c.sm_message_type = n.sm_message_type;
            c.sm_message = n.sm_message;
            c.selected_ciphering = n.selected_ciphering;
            c.selected_integrity = n.selected_integrity;
            c.mm_cause = n.mm_cause;
            ev.nas = c;
            if (!n.decoded) {
                ++stats_.nas_opaque;
            }
            ev.ue.pdu_session_id = n.pdu_session_id;
            if (ue != nullptr && n.selected_ciphering) {
                ue->cipher_alg = n.selected_ciphering;
            }
            if (n.supi) {
                auto h = pseudonym_of(*n.supi);
                if (h && ue != nullptr) {
                    ue->supi_hash = h;
                }
                ev.ue.supi_hash = std::move(h);
            }
        }
    }
    if (ue != nullptr) {
        if (!ev.ue.amf_ue_ngap_id) {
            ev.ue.amf_ue_ngap_id = ue->amf_ue_ngap_id;
        }
        if (!ev.ue.supi_hash) {
            ev.ue.supi_hash = ue->supi_hash;
        }
    }
    emit(ev);

    if (m.procedure_code == ngap::proc::kUeContextRelease &&
        m.pdu_type == ngap::PduType::kSuccessful && m.ran_ue_ngap_id) {
        ues_.release(gnb, *m.ran_ue_ngap_id);
    }
}

// ---------------------------------------------------------------------------- SBI

std::optional<std::string> Pipeline::pseudonym(const std::optional<std::string>& imsi) {
    if (!imsi) {
        return std::nullopt;
    }
    return pseudonym_of("imsi-" + *imsi);
}

std::optional<std::string> Pipeline::pseudonym_of(std::string_view supi) {
    if (!supi_) {
        ++stats_.supi_not_hashed;
        return std::nullopt;
    }
    auto h = supi_->hash(supi);
    if (h.empty()) {
        ++stats_.supi_not_hashed;  // crypto failure: drop, never emit the raw identity
        return std::nullopt;
    }
    ++stats_.supi_hashed;
    return h;
}

void Pipeline::on_sbi_segment(std::uint64_t ts_ns, const net::Packet& pkt) {
    ++stats_.sbi_segments;
    sweep_sbi(ts_ns);
    const tcp::SocketAddr src{pkt.src, pkt.src_port};
    const tcp::SocketAddr dst{pkt.dst, pkt.dst_port};
    const auto key = tcp::FlowKey::of(src, dst);
    const bool syn = (pkt.tcp_flags & net::tcp_flag::kSyn) != 0;
    const bool ack = (pkt.tcp_flags & net::tcp_flag::kAck) != 0;
    const bool rst = (pkt.tcp_flags & net::tcp_flag::kRst) != 0;

    auto it = sbi_flows_.find(key);
    if (syn && !ack) {
        // A client opening (or re-opening, on port reuse) a connection.
        if (it != sbi_flows_.end() && it->second.client == src &&
            it->second.client_isn == pkt.tcp_seq) {
            // retransmitted SYN: fall through to the normal path
        } else {
            if (it != sbi_flows_.end()) {
                sbi_flows_.erase(it);
            }
            if (sbi_flows_.size() >= kMaxSbiFlows) {
                ++stats_.sbi_flows_dropped_full;
                return;
            }
            SbiFlow f;
            f.client = src;
            f.server = dst;
            f.client_isn = pkt.tcp_seq;
            it = sbi_flows_.emplace(key, std::move(f)).first;
            ++stats_.sbi_flows_opened;
        }
    }
    if (it == sbi_flows_.end()) {
        if (!pkt.payload.empty()) {
            ++stats_.sbi_midstream_segments;
        }
        return;
    }
    SbiFlow& f = it->second;
    f.last_ns = ts_ns;
    if (rst) {
        sbi_flows_.erase(it);
        ++stats_.sbi_flows_closed;
        return;
    }
    const auto dir = src == f.client ? http2::Dir::kClientToServer : http2::Dir::kServerToClient;
    auto& half = dir == http2::Dir::kClientToServer ? f.c2s : f.s2c;
    tcp_buf_.clear();
    const bool was_broken = half.state() == tcp::StreamState::kBroken;
    half.feed(pkt.tcp_seq, pkt.tcp_flags, pkt.payload, tcp_buf_);
    if (!was_broken && half.state() == tcp::StreamState::kBroken) {
        ++stats_.sbi_tcp_gaps;
        f.dead = true;
    }
    if (!f.dead && !tcp_buf_.empty()) {
        h2_msgs_.clear();
        f.h2.feed(dir, tcp_buf_, ts_ns, h2_msgs_);
        for (const auto& m : h2_msgs_) {
            on_sbi_message(f, m);
        }
        if (f.h2.broken()) {
            ++stats_.sbi_http2_errors;
            sbi_error_event(ts_ns, f, dir, f.h2.error());
            f.dead = true;
        }
    }
    const auto done = [](const tcp::HalfStream& h) {
        return h.state() == tcp::StreamState::kClosed || h.state() == tcp::StreamState::kBroken;
    };
    if (done(f.c2s) && done(f.s2c)) {
        sbi_flows_.erase(it);
        ++stats_.sbi_flows_closed;
    }
}

void Pipeline::sweep_sbi(std::uint64_t now_ns) {
    constexpr std::uint64_t kEvery = 10'000'000'000ULL;
    if (now_ns < last_sweep_ns_ + kEvery) {
        return;
    }
    last_sweep_ns_ = now_ns;
    for (auto it = sbi_flows_.begin(); it != sbi_flows_.end();) {
        if (now_ns > it->second.last_ns && now_ns - it->second.last_ns > kSbiIdleNs) {
            it = sbi_flows_.erase(it);
            ++stats_.sbi_flows_expired;
        } else {
            ++it;
        }
    }
}

namespace {

std::string_view schema_method(std::string_view m) {
    static constexpr std::array<std::string_view, 5> kMethods{"GET", "POST", "PUT", "PATCH",
                                                              "DELETE"};
    for (const auto k : kMethods) {
        if (k == m) {
            return k;
        }
    }
    return {};
}

std::string media_type(std::string_view ct) {
    const auto semi = ct.find(';');
    auto v = ct.substr(0, semi);
    while (!v.empty() && v.back() == ' ') {
        v.remove_suffix(1);
    }
    std::string out;
    for (const char c : v.substr(0, 64)) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '+' || c == '.';
        out += ok ? c : '_';
    }
    return out;
}

}  // namespace

void Pipeline::on_sbi_message(const SbiFlow& f, const http2::Message& m) {
    const bool request = m.dir == http2::Dir::kClientToServer;
    if (request) {
        ++stats_.sbi_requests;
    } else {
        ++stats_.sbi_responses;
    }
    Event ev;
    ev.event_id = uuids_.next();
    ev.ts_ns = m.ts_ns;
    ev.interface = "SBI";
    ev.protocol = "HTTP2";
    const auto& from = request ? f.client : f.server;
    const auto& to = request ? f.server : f.client;
    ev.src = Endpoint{from.ip.to_string(), from.port, nf_map_.lookup(from.ip)};
    ev.dst = Endpoint{to.ip.to_string(), to.port, nf_map_.lookup(to.ip)};
    ev.direction = request ? "request" : "response";
    ev.size_bytes = m.header_bytes + m.body_bytes;
    ev.sequence = m.stream_id;

    const auto target = sbi::parse_target(m.path);
    SbiContext ctx;
    ctx.method = schema_method(m.method);
    ctx.path = target.path;
    ctx.service = target.service;
    ctx.content_type = media_type(m.content_type);
    std::string name;
    if (m.method.empty()) {
        name = "Response";  // the request was not seen (stream opened before capture)
    } else {
        name = sbi::operation_name(m.method, target);
    }
    ev.message = name;
    std::optional<std::string> cause;
    if (!request) {
        ctx.status = m.status;
        ev.message_code = static_cast<std::uint16_t>(m.status);
        if (m.status >= 400) {
            cause = sbi::find_problem_cause(m.body);
            if (cause) {
                ev.cause = *cause;
            }
        }
    }
    ev.sbi = std::move(ctx);

    // Identity: path first, then the request body, then this message's own body
    // (e.g. a GenerateAuthData response carries the SUPI de-concealed from a SUCI).
    auto imsi = target.imsi;
    if (!imsi && !m.request_body.empty()) {
        imsi = sbi::find_imsi(m.request_body);
    }
    if (!imsi) {
        imsi = sbi::find_imsi(m.body);
    }
    ev.ue.supi_hash = pseudonym(imsi);
    auto psi = sbi::find_pdu_session_id(request ? m.body : m.request_body);
    if (!psi) {
        psi = sbi::find_pdu_session_id(request ? m.request_body : m.body);
    }
    ev.ue.pdu_session_id = psi;
    emit(ev);
}

void Pipeline::sbi_error_event(std::uint64_t ts_ns, const SbiFlow& f, http2::Dir dir,
                               std::string_view why) {
    Event ev;
    ev.event_id = uuids_.next();
    ev.ts_ns = ts_ns;
    ev.interface = "SBI";
    ev.protocol = "HTTP2";
    const bool c2s = dir == http2::Dir::kClientToServer;
    const auto& from = c2s ? f.client : f.server;
    const auto& to = c2s ? f.server : f.client;
    ev.src = Endpoint{from.ip.to_string(), from.port, nf_map_.lookup(from.ip)};
    ev.dst = Endpoint{to.ip.to_string(), to.port, nf_map_.lookup(to.ip)};
    ev.message = "Undecodable";
    ev.decode_status = "malformed";
    ev.cause = why.substr(0, 64);
    emit(ev);
}

}  // namespace prahari
