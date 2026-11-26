// SPDX-License-Identifier: MIT
// Prometheus metrics: text exposition format 0.0.4, served over plain HTTP/1.1 on
// GET /metrics by a small background thread.
//
// Threading: the capture thread renders a snapshot (render_metrics) and hands it to
// publish(); the server thread only ever reads the latest snapshot under a mutex.
// No pipeline state is shared across threads.
//
// The server is deliberately minimal: one connection at a time, 2 s read timeout,
// requests capped at 4 KiB, GET only. It is a scrape endpoint, not a web server.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "prahari/pipeline.hpp"

namespace prahari {

struct KafkaStats;

struct CaptureCounters {
    std::uint64_t received{};
    std::uint64_t dropped_kernel{};
    std::uint64_t dropped_interface{};
};

[[nodiscard]] std::string render_metrics(const Stats& s, const pfcp::SessionTable& sessions,
                                         const ngap::UeTable& ues, std::size_t sbi_flows,
                                         const KafkaStats* kafka,
                                         const CaptureCounters* capture = nullptr);

class MetricsServer {
public:
    // `listen`: "HOST:PORT", e.g. "0.0.0.0:9464". Returns nullptr and sets `error`
    // if the address is invalid or cannot be bound.
    [[nodiscard]] static std::unique_ptr<MetricsServer> start(const std::string& listen,
                                                              std::string& error);
    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;
    MetricsServer(MetricsServer&&) = delete;
    MetricsServer& operator=(MetricsServer&&) = delete;
    ~MetricsServer();

    void publish(std::string text);
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] std::uint64_t scrapes() const noexcept { return scrapes_.load(); }

private:
    MetricsServer() = default;
    void serve();
    void handle(int fd);

    int listen_fd_{-1};
    std::uint16_t port_{};
    std::atomic<bool> stop_{false};
    std::atomic<std::uint64_t> scrapes_{0};
    std::mutex mu_;
    std::string snapshot_;
    std::thread thread_;
};

}  // namespace prahari
