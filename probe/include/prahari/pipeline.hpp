// SPDX-License-Identifier: MIT
// Frame -> decode -> correlate -> event pipeline, plus the IP->NF map and output sinks.
#pragma once

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "prahari/event.hpp"
#include "prahari/net.hpp"
#include "prahari/session_table.hpp"

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
    virtual void flush() {}
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
    std::uint64_t ngap_chunks{};  // PPID 60; decoded in Phase 3
    std::uint64_t pfcp_messages{};
    std::uint64_t pfcp_decode_errors{};
    std::uint64_t pfcp_unknown_session{};
    std::uint64_t events{};
};

[[nodiscard]] std::string stats_json(const Stats& s, const pfcp::SessionTable& table);

class Pipeline {
public:
    Pipeline(NfMap nf_map, Sink& sink) : nf_map_(std::move(nf_map)), sink_(sink) {}
    // Deterministic event IDs (tests, reproducible datasets).
    Pipeline(NfMap nf_map, Sink& sink, std::uint64_t uuid_seed)
        : nf_map_(std::move(nf_map)), sink_(sink), uuids_(uuid_seed) {}

    void on_frame(std::uint64_t ts_ns, net::LinkType link, std::span<const std::uint8_t> frame);

    [[nodiscard]] const Stats& stats() const noexcept { return stats_; }
    [[nodiscard]] const pfcp::SessionTable& sessions() const noexcept { return sessions_; }

private:
    void on_pfcp(std::uint64_t ts_ns, const net::Packet& pkt);
    void emit(const Event& e);

    NfMap nf_map_;
    Sink& sink_;
    UuidGenerator uuids_;
    pfcp::SessionTable sessions_;
    Stats stats_;
    std::string line_;  // reused buffer
};

}  // namespace prahari
