// SPDX-License-Identifier: MIT
// Frame -> decode -> correlate -> event pipeline, plus the IP->NF map and output sinks.
#pragma once

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "prahari/event.hpp"
#include "prahari/http2.hpp"
#include "prahari/net.hpp"
#include "prahari/session_table.hpp"
#include "prahari/supi.hpp"
#include "prahari/tcp_stream.hpp"
#include "prahari/ue_table.hpp"

namespace prahari {

// Maps IP addresses to 3GPP network-function names for event endpoints.
class NfMap {
public:
    // The Prahari testbed's fixed addresses (Architecture.md section 6).
    [[nodiscard]] static NfMap testbed_default();
    // Loads "IP NAME" lines ('#' comments). Returns false and sets `error` on bad input.
    bool load_file(const std::string& path, std::string& error);
    void set(const net::IpAddress& ip, std::string_view nf);
    [[nodiscard]] std::string_view lookup(const net::IpAddress& ip) const;

private:
    std::unordered_map<net::IpAddress, std::string_view, net::IpAddressHash> map_;
};

class Sink {
public:
    Sink() = default;
    Sink(const Sink&) = delete;
    Sink& operator=(const Sink&) = delete;
    Sink(Sink&&) = delete;
    Sink& operator=(Sink&&) = delete;
    virtual ~Sink() = default;
    // One complete JSON object, without newline.
    virtual void write(std::string_view json_line) = 0;
    // `key`: the UE pseudonym when known (Kafka partitions by it, keeping each UE's
    // events in order). Sinks without keys ignore it.
    virtual void write_keyed(std::string_view json_line, std::string_view /*key*/) {
        write(json_line);
    }
    virtual void flush() {}
};

// Sends every line to two sinks (e.g. a JSONL file and Kafka).
class TeeSink final : public Sink {
public:
    TeeSink(Sink& a, Sink& b) : a_(a), b_(b) {}
    void write(std::string_view json_line) override {
        a_.write(json_line);
        b_.write(json_line);
    }
    void write_keyed(std::string_view json_line, std::string_view key) override {
        a_.write_keyed(json_line, key);
        b_.write_keyed(json_line, key);
    }
    void flush() override {
        a_.flush();
        b_.flush();
    }

private:
    Sink& a_;  // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
    Sink& b_;  // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
};

// Writes JSON Lines to a stdio stream (stdout or a file opened by the caller).
// Lines are batched in our own buffer and handed to the stream only as whole lines,
// so a reader tailing the file never sees half an event.
class StreamSink final : public Sink {
public:
    explicit StreamSink(std::FILE* f, std::size_t batch_bytes = std::size_t{64} * 1024);
    StreamSink(const StreamSink&) = delete;
    StreamSink& operator=(const StreamSink&) = delete;
    StreamSink(StreamSink&&) = delete;
    StreamSink& operator=(StreamSink&&) = delete;
    ~StreamSink() override;
    void write(std::string_view json_line) override;
    void flush() override;

private:
    std::FILE* f_;
    std::size_t batch_bytes_;
    std::string buf_;
};

// Discards output; counts bytes (benchmarks).
class NullSink final : public Sink {
public:
    void write(std::string_view json_line) override { bytes_ += json_line.size() + 1; }
    [[nodiscard]] std::uint64_t bytes() const noexcept { return bytes_; }

private:
    std::uint64_t bytes_{};
};

// Keeps lines in memory (tests).
class VectorSink final : public Sink {
public:
    void write(std::string_view json_line) override { lines.emplace_back(json_line); }
    std::vector<std::string> lines;
};

struct Stats {
    std::uint64_t frames{};
    std::uint64_t bytes{};
    std::uint64_t link_errors{};  // truncated / malformed below transport
    std::uint64_t not_ip{};       // non-IP or IP fragments (unsupported)
    std::uint64_t udp{};
    std::uint64_t tcp{};
    std::uint64_t sctp{};
    std::uint64_t sctp_data_chunks{};
    std::uint64_t ngap_chunks{};  // SCTP DATA chunks with PPID 60
    std::uint64_t ngap_messages{};
    std::uint64_t ngap_decode_errors{};
    std::uint64_t nas_messages{};
    std::uint64_t nas_opaque{};  // ciphered with a non-null / unknown algorithm
    std::uint64_t nas_decode_errors{};
    std::uint64_t supi_hashed{};
    std::uint64_t supi_not_hashed{};  // SUPI seen but no key configured: omitted
    std::uint64_t pfcp_messages{};
    std::uint64_t pfcp_decode_errors{};
    std::uint64_t pfcp_unknown_session{};
    std::uint64_t sbi_segments{};            // TCP segments to/from an SBI port
    std::uint64_t sbi_midstream_segments{};  // on connections opened before the probe saw them
    std::uint64_t sbi_flows_opened{};
    std::uint64_t sbi_flows_closed{};
    std::uint64_t sbi_flows_expired{};
    std::uint64_t sbi_flows_dropped_full{};
    std::uint64_t sbi_tcp_gaps{};      // unrecoverable reassembly gaps
    std::uint64_t sbi_http2_errors{};  // framing / HPACK errors (connection abandoned)
    std::uint64_t sbi_requests{};
    std::uint64_t sbi_responses{};
    std::uint64_t events{};
};

// Live SBI connections (TCP + HTTP/2 state), bounded and expired when idle.
struct SbiFlow {
    tcp::SocketAddr client;
    tcp::SocketAddr server;
    std::uint32_t client_isn{};  // a SYN with another ISN is a new connection (port reuse)
    tcp::HalfStream c2s;
    tcp::HalfStream s2c;
    http2::Connection h2;
    std::uint64_t last_ns{};
    bool dead{};  // gap or HTTP/2 error: ignore until closed
};

[[nodiscard]] std::string stats_json(const Stats& s, const pfcp::SessionTable& table,
                                     const ngap::UeTable& ues, std::size_t sbi_flows);

class Pipeline {
public:
    Pipeline(NfMap nf_map, Sink& sink) : nf_map_(std::move(nf_map)), sink_(sink) {}
    // Deterministic event IDs (tests, reproducible datasets).
    Pipeline(NfMap nf_map, Sink& sink, std::uint64_t uuid_seed)
        : nf_map_(std::move(nf_map)), sink_(sink), uuids_(uuid_seed) {}

    void on_frame(std::uint64_t ts_ns, net::LinkType link, std::span<const std::uint8_t> frame);

    // Without a hasher, SUPIs are counted and dropped, never emitted.
    void set_supi_hasher(std::optional<SupiHasher> h) { supi_ = std::move(h); }

    // TCP ports carrying cleartext SBI (HTTP/2 prior knowledge). Default: 7777.
    void set_sbi_ports(std::unordered_set<std::uint16_t> ports) { sbi_ports_ = std::move(ports); }

    static constexpr std::size_t kMaxSbiFlows = 4096;
    static constexpr std::uint64_t kSbiIdleNs = 30ULL * 60 * 1'000'000'000;

    [[nodiscard]] const Stats& stats() const noexcept { return stats_; }
    [[nodiscard]] const pfcp::SessionTable& sessions() const noexcept { return sessions_; }
    [[nodiscard]] const ngap::UeTable& ues() const noexcept { return ues_; }
    [[nodiscard]] std::size_t sbi_flows() const noexcept { return sbi_flows_.size(); }
    // Forgets all SBI connections (benchmarks replaying the same capture).
    void reset_sbi_flows() { sbi_flows_.clear(); }

private:
    void on_pfcp(std::uint64_t ts_ns, const net::Packet& pkt);
    void on_ngap(std::uint64_t ts_ns, const net::Packet& pkt, std::span<const std::uint8_t> pdu);
    void on_sbi_segment(std::uint64_t ts_ns, const net::Packet& pkt);
    void on_sbi_message(const SbiFlow& f, const http2::Message& m);
    void sbi_error_event(std::uint64_t ts_ns, const SbiFlow& f, http2::Dir dir,
                         std::string_view why);
    void sweep_sbi(std::uint64_t now_ns);
    // IMSI digits -> pseudonym of "imsi-<digits>"; counts hashed / dropped.
    std::optional<std::string> pseudonym(const std::optional<std::string>& imsi);
    std::optional<std::string> pseudonym_of(std::string_view supi);
    void emit(const Event& e);

    NfMap nf_map_;
    Sink& sink_;
    UuidGenerator uuids_;
    pfcp::SessionTable sessions_;
    ngap::UeTable ues_;
    std::optional<SupiHasher> supi_;
    std::unordered_set<std::uint16_t> sbi_ports_{net::kPortSbi};
    std::unordered_map<tcp::FlowKey, SbiFlow, tcp::FlowKeyHash> sbi_flows_;
    std::uint64_t last_sweep_ns_{};
    std::vector<std::uint8_t> tcp_buf_;    // reused
    std::vector<http2::Message> h2_msgs_;  // reused
    Stats stats_;
    std::string line_;  // reused buffer
};

}  // namespace prahari
