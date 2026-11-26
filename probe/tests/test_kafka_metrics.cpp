// SPDX-License-Identifier: MIT
// Kafka: librdkafka's in-process mock cluster speaks the real Kafka protocol, so the
// producer path (idempotence, compression, keys, delivery reports) runs for real.
// Metrics: the HTTP endpoint is scraped over a real socket.
#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <set>
#include <string>
#include <thread>

#include "prahari/kafka_sink.hpp"
#include "prahari/metrics.hpp"
#include "prahari/pcap_source.hpp"
#include "prahari/pipeline.hpp"
#include <arpa/inet.h>
#include <librdkafka/rdkafka.h>
#include <librdkafka/rdkafka_mock.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

struct Consumed {
    std::string value;
    std::string key;
    std::int32_t partition{};
};

// Reads up to `want` messages from `topic` on the mock cluster at `bootstraps`.
std::vector<Consumed> consume(const std::string& bootstraps, const std::string& topic,
                              std::size_t want) {
    std::array<char, 512> err{};
    rd_kafka_conf_t* conf = rd_kafka_conf_new();
    (void)rd_kafka_conf_set(conf, "bootstrap.servers", bootstraps.c_str(), err.data(), err.size());
    (void)rd_kafka_conf_set(conf, "group.id", "prahari-test", err.data(), err.size());
    (void)rd_kafka_conf_set(conf, "auto.offset.reset", "earliest", err.data(), err.size());
    rd_kafka_t* c = rd_kafka_new(RD_KAFKA_CONSUMER, conf, err.data(), err.size());
    EXPECT_NE(c, nullptr) << err.data();
    rd_kafka_poll_set_consumer(c);
    rd_kafka_topic_partition_list_t* subs = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(subs, topic.c_str(), RD_KAFKA_PARTITION_UA);
    EXPECT_EQ(rd_kafka_subscribe(c, subs), RD_KAFKA_RESP_ERR_NO_ERROR);
    rd_kafka_topic_partition_list_destroy(subs);

    std::vector<Consumed> out;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
    while (out.size() < want && std::chrono::steady_clock::now() < deadline) {
        rd_kafka_message_t* m = rd_kafka_consumer_poll(c, 200);
        if (m == nullptr) {
            continue;
        }
        if (m->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
            Consumed x;
            x.value.assign(static_cast<const char*>(m->payload), m->len);
            if (m->key != nullptr) {
                x.key.assign(static_cast<const char*>(m->key), m->key_len);
            }
            x.partition = m->partition;
            out.push_back(std::move(x));
        }
        rd_kafka_message_destroy(m);
    }
    rd_kafka_consumer_close(c);
    rd_kafka_destroy(c);
    return out;
}

std::string http_get(std::uint16_t port, const std::string& path) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return {};
    }
    const std::string req = "GET " + path + " HTTP/1.1\r\nHost: x\r\n\r\n";
    (void)::send(fd, req.data(), req.size(), 0);
    std::string resp;
    std::array<char, 4096> buf{};
    for (;;) {
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) {
            break;
        }
        resp.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(fd);
    return resp;
}

}  // namespace

TEST(Kafka, ProducesEveryEventKeyedByUe) {
    prahari::KafkaConfig cfg;
    cfg.topic = "prahari.events.v1";
    cfg.linger_ms = 5;
    cfg.extra = {{"test.mock.num.brokers", "1"}};
    std::string err;
    auto sink = prahari::KafkaSink::create(cfg, err);
    ASSERT_TRUE(sink) << err;

    // Run the real N2 fixture through the pipeline into Kafka.
    auto opened = prahari::PcapSource::open_file(
        std::string{PRAHARI_TEST_DATA_DIR} + "/n2-registration.pcap", "");
    ASSERT_TRUE(opened.source) << opened.error;
    prahari::Pipeline p{prahari::NfMap::testbed_default(), *sink, 1};
    p.set_supi_hasher(prahari::SupiHasher{"prahari-test-key-0123456789abcdef"});
    prahari::Frame f;
    while (opened.source->next(f) == prahari::PcapSource::Next::kFrame) {
        p.on_frame(f.ts_ns, opened.source->link(), f.data);
    }
    ASSERT_TRUE(sink->drain(15'000));
    EXPECT_EQ(sink->stats().produced, 23U);
    EXPECT_EQ(sink->stats().delivered, 23U);
    EXPECT_EQ(sink->stats().dropped, 0U);
    EXPECT_EQ(sink->stats().failed, 0U);

    // Read them back through the mock cluster's bootstrap address.
    const char* boot =
        rd_kafka_mock_cluster_bootstraps(rd_kafka_handle_mock_cluster(sink->handle()));
    ASSERT_NE(boot, nullptr);
    const auto got = consume(boot, cfg.topic, 23);
    ASSERT_EQ(got.size(), 23U);
    std::set<std::int32_t> ue_partitions;
    std::size_t keyed = 0;
    for (const auto& m : got) {
        EXPECT_EQ(m.value.front(), '{');
        EXPECT_EQ(m.value.find("0000000008"), std::string::npos);  // no MSIN
        if (!m.key.empty()) {
            ++keyed;
            EXPECT_EQ(m.key, "1d99cf0c73e73e98");
            ue_partitions.insert(m.partition);
        }
    }
    // 14 events belong to the fixture UE. The other 9: NG Setup (no UE) and chunks of
    // other UEs bundled into the same SCTP packets, whose registrations are not in
    // the fixture, so the probe has no pseudonym for them (and does not guess one).
    EXPECT_EQ(keyed, 14U);
    EXPECT_EQ(ue_partitions.size(), 1U);  // one UE -> one partition -> ordered
}

TEST(Kafka, BadConfigurationIsReported) {
    prahari::KafkaConfig cfg;
    std::string err;
    EXPECT_FALSE(prahari::KafkaSink::create(cfg, err));
    EXPECT_EQ(err, "no Kafka brokers configured");
    cfg.brokers = "127.0.0.1:1";
    cfg.extra = {{"no.such.property", "1"}};
    EXPECT_FALSE(prahari::KafkaSink::create(cfg, err));
    EXPECT_NE(err.find("no.such.property"), std::string::npos);
}

TEST(Kafka, UnreachableBrokerNeverBlocksCapture) {
    prahari::KafkaConfig cfg;
    cfg.brokers = "127.0.0.1:1";  // nothing listens there
    cfg.queue_max_messages = 10;
    std::string err;
    auto sink = prahari::KafkaSink::create(cfg, err);
    ASSERT_TRUE(sink) << err;
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        sink->write_keyed(R"({"x":1})", "k");
    }
    const auto took = std::chrono::steady_clock::now() - start;
    EXPECT_LT(took, std::chrono::milliseconds{500});
    EXPECT_EQ(sink->stats().produced, 10U);  // the queue bound
    EXPECT_EQ(sink->stats().dropped, 990U);  // counted, not blocked on
    (void)sink->drain(10);                   // do not wait 30 s in the destructor
}

TEST(Metrics, ServesPrometheusTextOnSlashMetrics) {
    std::string err;
    auto srv = prahari::MetricsServer::start("127.0.0.1:0", err);  // any free port
    ASSERT_TRUE(srv) << err;
    ASSERT_NE(srv->port(), 0);

    prahari::Stats s;
    s.frames = 42;
    s.pfcp_messages = 7;
    s.sbi_requests = 3;
    prahari::pfcp::SessionTable sessions;
    prahari::ngap::UeTable ues;
    prahari::KafkaStats k;
    k.delivered = 5;
    const prahari::CaptureCounters cap{1000, 3, 0};
    srv->publish(prahari::render_metrics(s, sessions, ues, 2, &k, &cap));

    const auto resp = http_get(srv->port(), "/metrics");
    EXPECT_EQ(resp.rfind("HTTP/1.1 200 OK", 0), 0U) << resp;
    EXPECT_NE(resp.find("text/plain; version=0.0.4"), std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_frames_total 42\n"), std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_messages_total{protocol=\"PFCP\"} 7\n"), std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_messages_total{protocol=\"HTTP2_REQUEST\"} 3\n"),
              std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_sbi_flows_open 2\n"), std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_kafka_messages_total{outcome=\"delivered\"} 5\n"),
              std::string::npos);
    EXPECT_NE(resp.find("# TYPE prahari_probe_frames_total counter"), std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_capture_dropped_total{where=\"kernel_buffer\"} 3\n"),
              std::string::npos);
    EXPECT_NE(resp.find("prahari_probe_capture_received_total 1000\n"), std::string::npos);
    EXPECT_EQ(srv->scrapes(), 1U);

    EXPECT_EQ(http_get(srv->port(), "/").rfind("HTTP/1.1 404", 0), 0U);
    EXPECT_EQ(srv->scrapes(), 1U);
}

TEST(Metrics, BadListenAddressIsRejected) {
    std::string err;
    EXPECT_FALSE(prahari::MetricsServer::start("localhost", err));
    EXPECT_FALSE(prahari::MetricsServer::start("not-an-ip:9464", err));
    EXPECT_FALSE(prahari::MetricsServer::start("127.0.0.1:70000", err));
}

TEST(Metrics, CaptureCountersOnlyWhenLive) {
    // Offline files have no kernel buffer: no capture counters, and none rendered.
    auto opened = prahari::PcapSource::open_file(
        std::string{PRAHARI_TEST_DATA_DIR} + "/n4-lifecycle.pcap", "");
    ASSERT_TRUE(opened.source);
    EXPECT_FALSE(opened.source->capture_stats().available);
    prahari::Stats s;
    prahari::pfcp::SessionTable sessions;
    prahari::ngap::UeTable ues;
    const auto text = prahari::render_metrics(s, sessions, ues, 0, nullptr, nullptr);
    EXPECT_EQ(text.find("capture_dropped"), std::string::npos);
    EXPECT_EQ(text.find("kafka_messages"), std::string::npos);
}
