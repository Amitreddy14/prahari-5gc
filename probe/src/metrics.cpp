// SPDX-License-Identifier: MIT
#include "prahari/metrics.hpp"

#include <array>
#include <cerrno>
#include <sstream>
#include <string_view>

#include "prahari/kafka_sink.hpp"
#include "prahari/version.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace prahari {
namespace {

class Writer {
public:
    explicit Writer(std::ostringstream& o) : o_(o) {}
    void counter(std::string_view name, std::string_view help, std::uint64_t v) {
        head(name, help, "counter");
        o_ << name << ' ' << v << '\n';
    }
    void gauge(std::string_view name, std::string_view help, std::uint64_t v) {
        head(name, help, "gauge");
        o_ << name << ' ' << v << '\n';
    }
    // One family with a label.
    template <typename Rows>
    void labelled(std::string_view name, std::string_view help, std::string_view type,
                  std::string_view label, const Rows& rows) {
        head(name, help, type);
        for (const auto& [value, v] : rows) {
            o_ << name << '{' << label << "=\"" << value << "\"} " << v << '\n';
        }
    }

private:
    void head(std::string_view name, std::string_view help, std::string_view type) {
        o_ << "# HELP " << name << ' ' << help << "\n# TYPE " << name << ' ' << type << '\n';
    }
    std::ostringstream& o_;
};

using Row = std::pair<std::string_view, std::uint64_t>;

}  // namespace

std::string render_metrics(const Stats& s, const pfcp::SessionTable& sessions,
                           const ngap::UeTable& ues, std::size_t sbi_flows, const KafkaStats* kafka,
                           const CaptureCounters* capture) {
    std::ostringstream o;
    Writer w{o};
    o << "# HELP prahari_probe_build_info Probe version.\n# TYPE prahari_probe_build_info gauge\n"
      << "prahari_probe_build_info{version=\"" << kVersion << "\"} 1\n";
    w.counter("prahari_probe_frames_total", "Captured frames processed.", s.frames);
    w.counter("prahari_probe_bytes_total", "Captured bytes processed.", s.bytes);
    w.counter("prahari_probe_link_errors_total", "Frames with damaged L2-L4 headers.",
              s.link_errors);
    w.labelled("prahari_probe_messages_total", "Signalling messages decoded, by protocol.",
               "counter", "protocol",
               std::array{Row{"PFCP", s.pfcp_messages}, Row{"NGAP", s.ngap_messages},
                          Row{"NAS", s.nas_messages}, Row{"HTTP2_REQUEST", s.sbi_requests},
                          Row{"HTTP2_RESPONSE", s.sbi_responses}});
    w.labelled("prahari_probe_decode_errors_total",
               "Messages that failed to decode (still emitted as events), by protocol.", "counter",
               "protocol",
               std::array{Row{"PFCP", s.pfcp_decode_errors}, Row{"NGAP", s.ngap_decode_errors},
                          Row{"NAS", s.nas_decode_errors}, Row{"HTTP2", s.sbi_http2_errors}});
    w.counter("prahari_probe_nas_opaque_total", "NAS messages ciphered with a non-null algorithm.",
              s.nas_opaque);
    w.counter("prahari_probe_supi_hashed_total", "Subscriber identities pseudonymised.",
              s.supi_hashed);
    w.counter("prahari_probe_supi_dropped_total",
              "Subscriber identities dropped because no SUPI key is configured.",
              s.supi_not_hashed);
    w.counter("prahari_probe_pfcp_unknown_session_total",
              "PFCP session messages for sessions never seen established.", s.pfcp_unknown_session);
    w.counter("prahari_probe_events_total", "Events emitted.", s.events);
    w.gauge("prahari_probe_pfcp_sessions_active", "PFCP sessions currently active.",
            sessions.active());
    w.gauge("prahari_probe_ue_contexts", "UE contexts tracked on N2.", ues.size());
    w.gauge("prahari_probe_sbi_flows_open", "SBI TCP connections tracked.", sbi_flows);
    w.labelled("prahari_probe_sbi_flows_total", "SBI TCP connections, by outcome.", "counter",
               "outcome",
               std::array{Row{"opened", s.sbi_flows_opened}, Row{"closed", s.sbi_flows_closed},
                          Row{"expired", s.sbi_flows_expired},
                          Row{"dropped_full", s.sbi_flows_dropped_full}});
    w.counter("prahari_probe_sbi_midstream_segments_total",
              "SBI segments on connections opened before the probe started (not decodable).",
              s.sbi_midstream_segments);
    w.counter("prahari_probe_sbi_tcp_gaps_total", "Unrecoverable TCP reassembly gaps.",
              s.sbi_tcp_gaps);
    if (capture != nullptr) {
        // Packets lost before the probe saw them: a dataset is only as good as this is low.
        w.labelled("prahari_probe_capture_dropped_total",
                   "Packets dropped before reaching the probe (libpcap counters).", "counter",
                   "where",
                   std::array{Row{"kernel_buffer", capture->dropped_kernel},
                              Row{"interface", capture->dropped_interface}});
        w.counter("prahari_probe_capture_received_total",
                  "Packets that matched the capture filter (libpcap counter).", capture->received);
    }
    if (kafka != nullptr) {
        w.labelled("prahari_probe_kafka_messages_total", "Kafka producer messages, by outcome.",
                   "counter", "outcome",
                   std::array{Row{"produced", kafka->produced}, Row{"delivered", kafka->delivered},
                              Row{"failed", kafka->failed}, Row{"dropped", kafka->dropped}});
    }
    return o.str();
}

std::unique_ptr<MetricsServer> MetricsServer::start(const std::string& listen, std::string& error) {
    const auto colon = listen.rfind(':');
    if (colon == std::string::npos) {
        error = "metrics address must be HOST:PORT";
        return nullptr;
    }
    const auto host = listen.substr(0, colon);
    const auto port_str = listen.substr(colon + 1);
    unsigned long port = 0;
    try {
        port = std::stoul(port_str);
    } catch (...) {
        port = 70000;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (port > 65535 || inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        error = "invalid metrics address '" + listen + "' (IPv4 HOST:PORT)";
        return nullptr;
    }
    addr.sin_port = htons(static_cast<std::uint16_t>(port));

    std::unique_ptr<MetricsServer> srv{new MetricsServer()};
    srv->listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv->listen_fd_ < 0) {
        error = "socket() failed";
        return nullptr;
    }
    const int one = 1;
    (void)::setsockopt(srv->listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): sockets API
    if (::bind(srv->listen_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(srv->listen_fd_, 16) != 0) {
        error = "cannot listen on " + listen;
        return nullptr;
    }
    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): sockets API
    if (::getsockname(srv->listen_fd_, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
        srv->port_ = ntohs(bound.sin_port);
    }
    srv->snapshot_ = "# probe starting\n";
    srv->thread_ = std::thread([s = srv.get()] { s->serve(); });
    return srv;
}

MetricsServer::~MetricsServer() {
    stop_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
    }
}

void MetricsServer::publish(std::string text) {
    const std::lock_guard lock{mu_};
    snapshot_ = std::move(text);
}

void MetricsServer::serve() {
    while (!stop_.load()) {
        pollfd p{listen_fd_, POLLIN, 0};
        const int rc = ::poll(&p, 1, 200);
        if (rc <= 0 || (p.revents & POLLIN) == 0) {
            continue;
        }
        const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        handle(fd);
        ::close(fd);
    }
}

void MetricsServer::handle(int fd) {
    timeval tv{2, 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    std::string req;
    std::array<char, 1024> buf{};
    while (req.size() < 4096 && req.find("\r\n\r\n") == std::string::npos) {
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) {
            break;
        }
        req.append(buf.data(), static_cast<std::size_t>(n));
    }
    std::string body;
    std::string status = "200 OK";
    std::string ctype = "text/plain; version=0.0.4; charset=utf-8";
    if (req.starts_with("GET /metrics ") || req.starts_with("GET /metrics?")) {
        const std::lock_guard lock{mu_};
        body = snapshot_;
        scrapes_.fetch_add(1);
    } else if (req.starts_with("GET ")) {
        status = "404 Not Found";
        body = "not found: try /metrics\n";
        ctype = "text/plain";
    } else {
        status = "405 Method Not Allowed";
        body = "GET only\n";
        ctype = "text/plain";
    }
    std::string resp = "HTTP/1.1 " + status + "\r\nContent-Type: " + ctype +
                       "\r\nContent-Length: " + std::to_string(body.size()) +
                       "\r\nConnection: close\r\n\r\n" + body;
    std::size_t sent = 0;
    while (sent < resp.size()) {
        const auto n = ::send(fd, resp.data() + sent, resp.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            return;
        }
        sent += static_cast<std::size_t>(n);
    }
}

}  // namespace prahari
