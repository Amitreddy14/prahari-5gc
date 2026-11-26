// SPDX-License-Identifier: MIT
// Kafka output (librdkafka): one event per message on topic prahari.events.v1, keyed
// by the UE pseudonym when known so each UE's events stay ordered in one partition.
//
// The capture thread must never block on the network. Produce calls are
// non-blocking; when librdkafka's local queue is full the event is dropped and
// counted (kafka_dropped), and the JSONL file (if configured) still has it.
// Delivery is idempotent (acks=all), so broker retries do not duplicate events.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "prahari/pipeline.hpp"

struct rd_kafka_s;
struct rd_kafka_topic_s;

namespace prahari {

struct KafkaConfig {
    std::string brokers;  // bootstrap.servers, e.g. "172.22.0.40:9092"
    std::string topic{"prahari.events.v1"};
    int queue_max_messages{100'000};
    int linger_ms{20};
    // Extra librdkafka properties "key=value" (tests use test.mock.num.brokers).
    std::vector<std::pair<std::string, std::string>> extra;
};

struct KafkaStats {
    std::uint64_t produced{};   // accepted into the local queue
    std::uint64_t delivered{};  // acknowledged by the broker
    std::uint64_t failed{};     // delivery failed after retries
    std::uint64_t dropped{};    // local queue full: never sent
};

class KafkaSink final : public Sink {
public:
    // Returns nullptr and sets `error` on bad configuration. Connecting is
    // asynchronous: a broker that is not up yet is retried in the background.
    [[nodiscard]] static std::unique_ptr<KafkaSink> create(const KafkaConfig& cfg,
                                                           std::string& error);
    KafkaSink(const KafkaSink&) = delete;
    KafkaSink& operator=(const KafkaSink&) = delete;
    KafkaSink(KafkaSink&&) = delete;
    KafkaSink& operator=(KafkaSink&&) = delete;
    ~KafkaSink() override;  // flushes for up to 5 s

    void write(std::string_view json_line) override { write_keyed(json_line, {}); }
    void write_keyed(std::string_view json_line, std::string_view key) override;
    // Serves delivery reports; called by the pipeline's periodic flush.
    void flush() override;
    // Waits up to `timeout_ms` for every queued message to be delivered.
    bool drain(int timeout_ms);

    [[nodiscard]] const KafkaStats& stats() const noexcept { return stats_; }
    [[nodiscard]] rd_kafka_s* handle() const noexcept { return rk_; }

private:
    KafkaSink() = default;
    static void on_delivery(rd_kafka_s* rk, const void* msg, void* opaque);

    rd_kafka_s* rk_{};
    rd_kafka_topic_s* topic_{};
    KafkaStats stats_;
};

}  // namespace prahari
