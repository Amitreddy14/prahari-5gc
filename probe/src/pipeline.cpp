// SPDX-License-Identifier: MIT
#include "prahari/pipeline.hpp"

#include <array>
#include <fstream>
#include <sstream>

#include "prahari/nas.hpp"
#include "prahari/ngap.hpp"
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

std::string stats_json(const Stats& s, const pfcp::SessionTable& t, const ngap::UeTable& u) {
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
      << ",\"pfcp_unknown_session\":" << s.pfcp_unknown_session << ",\"events\":" << s.events
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
                if (supi_) {
                    ++stats_.supi_hashed;
                    const auto h = supi_->hash(*n.supi);
                    if (ue != nullptr) {
                        ue->supi_hash = h;
                    }
                    ev.ue.supi_hash = h;
                } else {
                    ++stats_.supi_not_hashed;
                }
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

}  // namespace prahari
