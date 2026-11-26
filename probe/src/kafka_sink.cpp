// SPDX-License-Identifier: MIT
#include "prahari/kafka_sink.hpp"

#include <algorithm>
#include <array>

#include <librdkafka/rdkafka.h>

namespace prahari {
namespace {

bool set(rd_kafka_conf_t* conf, const std::string& k, const std::string& v, std::string& error) {
    std::array<char, 512> err{};
    if (rd_kafka_conf_set(conf, k.c_str(), v.c_str(), err.data(), err.size()) != RD_KAFKA_CONF_OK) {
        error = k + ": " + err.data();
        return false;
    }
    return true;
}

}  // namespace

void KafkaSink::on_delivery(rd_kafka_s* /*rk*/, const void* msg, void* opaque) {
    auto* self = static_cast<KafkaSink*>(opaque);
    const auto* m = static_cast<const rd_kafka_message_t*>(msg);
    if (m->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
        ++self->stats_.delivered;
    } else {
        ++self->stats_.failed;
    }
}

std::unique_ptr<KafkaSink> KafkaSink::create(const KafkaConfig& cfg, std::string& error) {
    if (cfg.brokers.empty() && std::none_of(cfg.extra.begin(), cfg.extra.end(), [](const auto& kv) {
            return kv.first == "test.mock.num.brokers";
        })) {
        error = "no Kafka brokers configured";
        return nullptr;
    }
    std::unique_ptr<KafkaSink> sink{new KafkaSink()};
    rd_kafka_conf_t* conf = rd_kafka_conf_new();
    const std::array<std::pair<std::string, std::string>, 7> base{{
        {"client.id", "prahari-probe"},
        {"enable.idempotence", "true"},  // implies acks=all, no duplicates on retry
        {"compression.type", "lz4"},
        {"linger.ms", std::to_string(cfg.linger_ms)},
        {"queue.buffering.max.messages", std::to_string(cfg.queue_max_messages)},
        {"message.timeout.ms", "30000"},
        {"socket.keepalive.enable", "true"},
    }};
    bool ok = true;
    if (!cfg.brokers.empty()) {
        ok = set(conf, "bootstrap.servers", cfg.brokers, error);
    }
    for (const auto& [k, v] : base) {
        ok = ok && set(conf, k, v, error);
    }
    for (const auto& [k, v] : cfg.extra) {
        ok = ok && set(conf, k, v, error);
    }
    if (!ok) {
        rd_kafka_conf_destroy(conf);
        return nullptr;
    }
    rd_kafka_conf_set_opaque(conf, sink.get());
    rd_kafka_conf_set_dr_msg_cb(conf, [](rd_kafka_t* rk, const rd_kafka_message_t* m,
                                         void* opaque) { on_delivery(rk, m, opaque); });
    std::array<char, 512> err{};
    sink->rk_ = rd_kafka_new(RD_KAFKA_PRODUCER, conf, err.data(), err.size());
    if (sink->rk_ == nullptr) {
        rd_kafka_conf_destroy(conf);  // ownership stays with us on failure
        error = err.data();
        return nullptr;
    }
    sink->topic_ = rd_kafka_topic_new(sink->rk_, cfg.topic.c_str(), nullptr);
    if (sink->topic_ == nullptr) {
        error = "cannot create topic handle for " + cfg.topic;
        return nullptr;
    }
    return sink;
}

KafkaSink::~KafkaSink() {
    if (rk_ != nullptr) {
        (void)drain(5000);
    }
    if (topic_ != nullptr) {
        rd_kafka_topic_destroy(topic_);
    }
    if (rk_ != nullptr) {
        rd_kafka_destroy(rk_);
    }
}

void KafkaSink::write_keyed(std::string_view json_line, std::string_view key) {
    // RD_KAFKA_MSG_F_COPY: librdkafka copies the payload, our buffer is reused.
    const int rc = rd_kafka_produce(
        topic_, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
        const_cast<char*>(json_line.data()),  // NOLINT(cppcoreguidelines-pro-type-const-cast)
        json_line.size(), key.empty() ? nullptr : key.data(), key.size(), nullptr);
    if (rc == 0) {
        ++stats_.produced;
    } else {
        ++stats_.dropped;  // queue full (or message too large): never block capture
    }
    rd_kafka_poll(rk_, 0);  // serve delivery reports without waiting
}

void KafkaSink::flush() {
    rd_kafka_poll(rk_, 0);
}

bool KafkaSink::drain(int timeout_ms) {
    return rd_kafka_flush(rk_, timeout_ms) == RD_KAFKA_RESP_ERR_NO_ERROR;
}

}  // namespace prahari
