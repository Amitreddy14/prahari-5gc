// SPDX-License-Identifier: MIT
// prahari-probe: passive 5G core signalling probe.
//
//   prahari-probe run   --iface prahari-core [--out events.jsonl]   live capture
//   prahari-probe run   --pcap capture.pcap  [--out events.jsonl]   offline file
//   prahari-probe bench --pcap capture.pcap  [--repeat 200]         decode throughput
//   prahari-probe decode-pfcp <hex>                                  one PFCP header
//   prahari-probe decode-ngap <hex> | decode-nas <hex>               one N2 PDU / NAS msg
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "prahari/kafka_sink.hpp"
#include "prahari/metrics.hpp"
#include "prahari/nas.hpp"
#include "prahari/ngap.hpp"
#include "prahari/pcap_source.hpp"
#include "prahari/pfcp.hpp"
#include "prahari/pipeline.hpp"
#include "prahari/supi.hpp"
#include "prahari/version.hpp"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 64;    // EX_USAGE
constexpr int kExitDataErr = 65;  // EX_DATAERR
constexpr int kExitNoInput = 66;  // EX_NOINPUT
constexpr int kExitIoErr = 74;    // EX_IOERR
constexpr std::string_view kDefaultFilter =
    "udp port 8805 or sctp or tcp port 7777";  // N4 + N2 + SBI

// The signal handler needs the active source to break the capture loop; a global
// atomic pointer is the only async-signal-safe channel for that.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::atomic<prahari::PcapSource*> g_source{nullptr};

extern "C" void on_signal(int /*sig*/) {
    if (auto* s = g_source.load()) {
        s->stop();
    }
}

void print_usage(std::ostream& out) {
    out << "prahari-probe " << prahari::kVersion << "\n"
        << "Passive 5G core signalling probe: PFCP (N4), NGAP + NAS (N2), HTTP/2 SBI.\n\n"
        << "Usage:\n"
        << "  prahari-probe run (--iface IF | --pcap FILE) [options]\n"
        << "      --filter BPF     capture filter (default: \"" << kDefaultFilter << "\")\n"
        << "      --out FILE       JSON Lines output, appended (default: stdout)\n"
        << "      --nf-map FILE    'IP NF' lines mapping addresses to NF names\n"
        << "                       (default: the Prahari testbed addresses)\n"
        << "      --seed N         deterministic event IDs (tests, reproducible datasets)\n"
        << "      --supi-key-env V environment variable holding the SUPI HMAC key\n"
        << "                       (default PRAHARI_SUPI_KEY; unset = SUPIs omitted)\n"
        << "      --sbi-ports LIST cleartext SBI (h2c) TCP ports, comma-separated (default 7777)\n"
        << "      --kafka-brokers B  also produce events to Kafka (bootstrap servers);\n"
        << "                       without --out, Kafka is the only output\n"
        << "      --kafka-topic T  Kafka topic (default prahari.events.v1)\n"
        << "      --metrics-listen HOST:PORT  serve Prometheus metrics on /metrics\n"
        << "      --stats          print pipeline statistics as JSON to stderr at exit\n"
        << "  prahari-probe bench --pcap FILE [--repeat N]   decode throughput, no output\n"
        << "  prahari-probe decode-pfcp <hex>                decode one PFCP header\n"
        << "  prahari-probe decode-ngap <hex>                decode one NGAP PDU\n"
        << "  prahari-probe decode-nas <hex>                 decode one NAS 5GS message\n"
        << "  prahari-probe --version | --help\n";
}

struct Options {
    std::string iface;
    std::string pcap;
    std::string filter{kDefaultFilter};
    std::string out;
    std::string nf_map;
    std::string supi_key_env{"PRAHARI_SUPI_KEY"};
    std::string kafka_brokers;
    std::string kafka_topic{"prahari.events.v1"};
    std::string metrics_listen;
    std::unordered_set<std::uint16_t> sbi_ports{prahari::net::kPortSbi};
    std::optional<std::uint64_t> seed;
    bool stats{};
    std::uint64_t repeat{200};
};

std::optional<std::uint64_t> parse_u64(std::string_view s) {
    if (s.empty() || s.size() > 19) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        v = v * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return v;
}

// Parses "--flag value" pairs after the subcommand. Returns an error message or empty.
std::string parse_options(const std::vector<std::string_view>& args, Options& o) {
    for (std::size_t i = 1; i < args.size(); ++i) {
        const auto a = args[i];
        auto value = [&]() -> std::optional<std::string_view> {
            if (i + 1 >= args.size()) {
                return std::nullopt;
            }
            return args[++i];
        };
        if (a == "--stats") {
            o.stats = true;
            continue;
        }
        const auto v = value();
        if (!v) {
            return std::string{"missing value for "} + std::string{a};
        }
        if (a == "--iface") {
            o.iface = *v;
        } else if (a == "--pcap") {
            o.pcap = *v;
        } else if (a == "--filter") {
            o.filter = *v;
        } else if (a == "--out") {
            o.out = *v;
        } else if (a == "--nf-map") {
            o.nf_map = *v;
        } else if (a == "--supi-key-env") {
            o.supi_key_env = *v;
        } else if (a == "--kafka-brokers") {
            o.kafka_brokers = *v;
        } else if (a == "--kafka-topic") {
            o.kafka_topic = *v;
        } else if (a == "--metrics-listen") {
            o.metrics_listen = *v;
        } else if (a == "--sbi-ports") {
            o.sbi_ports.clear();
            std::string_view rest = *v;
            while (!rest.empty()) {
                const auto comma = rest.find(',');
                const auto port = parse_u64(rest.substr(0, comma));
                if (!port || *port == 0 || *port > 65535) {
                    return "--sbi-ports needs comma-separated ports 1-65535";
                }
                o.sbi_ports.insert(static_cast<std::uint16_t>(*port));
                rest =
                    comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            }
            if (o.sbi_ports.empty()) {
                return "--sbi-ports needs at least one port";
            }
        } else if (a == "--seed") {
            o.seed = parse_u64(*v);
            if (!o.seed) {
                return "--seed needs a non-negative integer";
            }
        } else if (a == "--repeat") {
            const auto r = parse_u64(*v);
            if (!r || *r == 0) {
                return "--repeat needs a positive integer";
            }
            o.repeat = *r;
        } else {
            return std::string{"unknown option "} + std::string{a};
        }
    }
    return {};
}

int cmd_run(const Options& o) {
    if (o.iface.empty() == o.pcap.empty()) {
        std::cerr << "error: give exactly one of --iface or --pcap\n";
        return kExitUsage;
    }
    prahari::NfMap nf_map = prahari::NfMap::testbed_default();
    if (!o.nf_map.empty()) {
        std::string err;
        if (!nf_map.load_file(o.nf_map, err)) {
            std::cerr << "error: " << err << "\n";
            return kExitDataErr;
        }
    }
    auto opened = o.pcap.empty() ? prahari::PcapSource::open_live(o.iface, o.filter)
                                 : prahari::PcapSource::open_file(o.pcap, o.filter);
    if (!opened.source) {
        std::cerr << "error: " << opened.error << "\n";
        return kExitNoInput;
    }
    auto& src = *opened.source;
    if (!src.link_supported()) {
        std::cerr << "error: unsupported link type " << src.raw_link() << "\n";
        return kExitDataErr;
    }

    // Outputs: JSONL (stdout or --out) unless Kafka alone was asked for; Kafka if
    // brokers are given; both through a tee.
    const bool want_kafka = !o.kafka_brokers.empty();
    const bool want_stream = !want_kafka || !o.out.empty();
    std::FILE* out = stdout;
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> owned{nullptr, &std::fclose};
    if (!o.out.empty() && o.out != "-") {
        owned.reset(std::fopen(o.out.c_str(), "ae"));
        if (!owned) {
            std::cerr << "error: cannot open output '" << o.out << "'\n";
            return kExitIoErr;
        }
        out = owned.get();
    }
    std::unique_ptr<prahari::StreamSink> stream_sink;
    if (want_stream) {
        stream_sink = std::make_unique<prahari::StreamSink>(out);
    }
    std::unique_ptr<prahari::KafkaSink> kafka;
    if (want_kafka) {
        std::string err;
        prahari::KafkaConfig kc;
        kc.brokers = o.kafka_brokers;
        kc.topic = o.kafka_topic;
        kafka = prahari::KafkaSink::create(kc, err);
        if (!kafka) {
            std::cerr << "error: Kafka: " << err << "\n";
            return kExitUsage;
        }
        std::cerr << "prahari-probe: producing to Kafka " << o.kafka_brokers << " topic "
                  << o.kafka_topic << "\n";
    }
    std::unique_ptr<prahari::TeeSink> tee;
    prahari::Sink* sink = nullptr;
    if (stream_sink && kafka) {
        tee = std::make_unique<prahari::TeeSink>(*stream_sink, *kafka);
        sink = tee.get();
    } else if (kafka) {
        sink = kafka.get();
    } else {
        sink = stream_sink.get();
    }
    std::optional<prahari::Pipeline> pipeline;
    if (o.seed) {
        pipeline.emplace(std::move(nf_map), *sink, *o.seed);
    } else {
        pipeline.emplace(std::move(nf_map), *sink);
    }
    pipeline->set_sbi_ports(o.sbi_ports);

    std::unique_ptr<prahari::MetricsServer> metrics;
    if (!o.metrics_listen.empty()) {
        std::string err;
        metrics = prahari::MetricsServer::start(o.metrics_listen, err);
        if (!metrics) {
            std::cerr << "error: metrics: " << err << "\n";
            return kExitUsage;
        }
        std::cerr << "prahari-probe: metrics on http://" << o.metrics_listen << "/metrics\n";
    }
    const auto capture_counters = [&src]() -> std::optional<prahari::CaptureCounters> {
        const auto c = src.capture_stats();
        if (!c.available) {
            return std::nullopt;
        }
        return prahari::CaptureCounters{c.received, c.dropped_kernel, c.dropped_interface};
    };
    const auto publish_metrics = [&] {
        if (metrics) {
            const auto cap = capture_counters();
            metrics->publish(prahari::render_metrics(
                pipeline->stats(), pipeline->sessions(), pipeline->ues(), pipeline->sbi_flows(),
                kafka ? &kafka->stats() : nullptr, cap ? &*cap : nullptr));
        }
    };

    {
        std::string err;
        auto hasher = prahari::SupiHasher::from_env(o.supi_key_env.c_str(), err);
        if (!hasher) {
            std::cerr << "prahari-probe: warning: " << err << "\n";
        }
        pipeline->set_supi_hasher(std::move(hasher));
    }

    g_source.store(&src);
    (void)std::signal(SIGINT, on_signal);
    (void)std::signal(SIGTERM, on_signal);
    if (!o.iface.empty()) {
        std::cerr << "prahari-probe: capturing on " << o.iface << " (filter: " << o.filter
                  << "); Ctrl+C to stop\n";
    }

    // Live mode: hand complete lines to the file at least this often, so consumers
    // tailing events.jsonl stay current even under constant traffic.
    constexpr auto kLiveFlushEvery = std::chrono::milliseconds{200};
    constexpr auto kMetricsEvery = std::chrono::seconds{1};
    const bool live = !o.iface.empty();
    auto last_flush = std::chrono::steady_clock::now();
    auto last_metrics = last_flush;
    publish_metrics();
    int rc = kExitOk;
    prahari::Frame f;
    for (;;) {
        const auto n = src.next(f);
        if (n == prahari::PcapSource::Next::kFrame) {
            pipeline->on_frame(f.ts_ns, src.link(), f.data);
            if (live) {
                const auto now = std::chrono::steady_clock::now();
                if (now - last_flush >= kLiveFlushEvery) {
                    sink->flush();
                    last_flush = now;
                }
                if (now - last_metrics >= kMetricsEvery) {
                    publish_metrics();
                    last_metrics = now;
                }
            }
            continue;
        }
        if (n == prahari::PcapSource::Next::kTimeout) {
            sink->flush();  // idle: keep the output file current
            publish_metrics();
            last_flush = std::chrono::steady_clock::now();
            last_metrics = last_flush;
            continue;
        }
        if (n == prahari::PcapSource::Next::kError) {
            std::cerr << "error: capture failed: " << src.last_error() << "\n";
            rc = kExitIoErr;
        }
        break;
    }
    g_source.store(nullptr);
    sink->flush();
    publish_metrics();
    if (kafka && !kafka->drain(10'000)) {
        std::cerr << "prahari-probe: warning: Kafka did not acknowledge every event in 10 s\n";
    }
    if (o.stats) {
        std::cerr << prahari::stats_json(pipeline->stats(), pipeline->sessions(), pipeline->ues(),
                                         pipeline->sbi_flows())
                  << "\n";
        if (const auto cap = capture_counters()) {
            std::cerr << "{\"capture_received\":" << cap->received
                      << ",\"capture_dropped_kernel\":" << cap->dropped_kernel
                      << ",\"capture_dropped_interface\":" << cap->dropped_interface << "}\n";
        }
        if (kafka) {
            const auto& k = kafka->stats();
            std::cerr << "{\"kafka_produced\":" << k.produced
                      << ",\"kafka_delivered\":" << k.delivered << ",\"kafka_failed\":" << k.failed
                      << ",\"kafka_dropped\":" << k.dropped << "}\n";
        }
    }
    return rc;
}

int cmd_bench(const Options& o) {
    if (o.pcap.empty()) {
        std::cerr << "error: bench needs --pcap FILE\n";
        return kExitUsage;
    }
    auto opened = prahari::PcapSource::open_file(o.pcap, o.filter);
    if (!opened.source) {
        std::cerr << "error: " << opened.error << "\n";
        return kExitNoInput;
    }
    auto& src = *opened.source;
    struct Owned {
        std::uint64_t ts;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<Owned> frames;
    prahari::Frame f;
    while (src.next(f) == prahari::PcapSource::Next::kFrame) {
        frames.push_back({f.ts_ns, {f.data.begin(), f.data.end()}});
    }
    if (frames.empty()) {
        std::cerr << "error: no frames matched the filter\n";
        return kExitDataErr;
    }
    prahari::NullSink sink;
    prahari::Pipeline pipeline{prahari::NfMap::testbed_default(), sink, 1};
    pipeline.set_supi_hasher(prahari::SupiHasher{"bench-key-not-secret-0123456789"});
    const auto start = std::chrono::steady_clock::now();
    for (std::uint64_t r = 0; r < o.repeat; ++r) {
        // Replaying the same TCP sequence numbers would look like retransmissions:
        // forget SBI connections so each pass is decoded as new traffic.
        pipeline.reset_sbi_flows();
        for (const auto& fr : frames) {
            pipeline.on_frame(fr.ts, src.link(), fr.bytes);
        }
    }
    const auto secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    const auto& s = pipeline.stats();
    const auto sbi = s.sbi_requests + s.sbi_responses;
    const auto all = static_cast<double>(s.pfcp_messages + s.ngap_messages + sbi);
    // Every rate is per signalling message (PFCP + NGAP + SBI request/response), so it
    // stays finite and comparable whichever interfaces the capture carries.
    const auto ns_per_msg = all > 0 ? secs * 1e9 / all : 0.0;
    std::cout << "{\"frames\":" << s.frames << ",\"pfcp_messages\":" << s.pfcp_messages
              << ",\"ngap_messages\":" << s.ngap_messages << ",\"sbi_messages\":" << sbi
              << ",\"events\":" << s.events << ",\"json_bytes\":" << sink.bytes()
              << ",\"seconds\":" << secs << ",\"signalling_msgs_per_sec\":" << (all / secs)
              << ",\"ns_per_signalling_msg\":" << ns_per_msg
              << ",\"frames_per_sec\":" << (static_cast<double>(s.frames) / secs) << "}\n";
    return kExitOk;
}

std::optional<std::uint8_t> hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> parse_hex(std::string_view text) {
    std::vector<std::uint8_t> out;
    std::optional<std::uint8_t> high;
    for (const char c : text) {
        if (c == ' ' || c == ':') {
            continue;
        }
        const auto n = hex_nibble(c);
        if (!n) {
            return std::nullopt;
        }
        if (high) {
            out.push_back(static_cast<std::uint8_t>((*high << 4U) | *n));
            high.reset();
        } else {
            high = n;
        }
    }
    if (high) {
        return std::nullopt;
    }
    return out;
}

int cmd_decode_pfcp(std::string_view hex) {
    const auto bytes = parse_hex(hex);
    if (!bytes) {
        std::cerr << "error: input is not valid hex\n";
        return kExitUsage;
    }
    const auto result = prahari::pfcp::decode(std::span<const std::uint8_t>{*bytes});
    if (!result) {
        std::cout << R"({"ok":false,"error":")" << prahari::to_string(result.error()) << "\"}\n";
        return kExitDataErr;
    }
    const auto& h = result.value().header;
    std::cout << R"({"ok":true,"protocol":"pfcp","message_type":)" << unsigned{h.message_type}
              << R"(,"message":")" << prahari::pfcp::message_name(h.message_type) << '"'
              << R"(,"sequence":)" << h.sequence;
    if (h.seid) {
        std::cout << R"(,"seid":")" << *h.seid << '"';
    }
    if (h.priority) {
        std::cout << R"(,"priority":)" << unsigned{*h.priority};
    }
    std::cout << R"(,"body_len":)" << result.value().body.size() << "}\n";
    return kExitOk;
}

int cmd_decode_ngap(std::string_view hex) {
    const auto bytes = parse_hex(hex);
    if (!bytes) {
        std::cerr << "error: input is not valid hex\n";
        return kExitUsage;
    }
    const auto result = prahari::ngap::decode(std::span<const std::uint8_t>{*bytes});
    if (!result) {
        std::cout << R"({"ok":false,"error":")" << prahari::to_string(result.error()) << "\"}\n";
        return kExitDataErr;
    }
    const auto& m = result.value();
    std::cout << R"({"ok":true,"protocol":"ngap","pdu_type":")"
              << prahari::ngap::to_string(m.pdu_type) << R"(","procedure_code":)"
              << unsigned{m.procedure_code} << R"(,"message":")"
              << prahari::ngap::message_name(m.procedure_code, m.pdu_type) << '"'
              << R"(,"ie_count":)" << m.ies.size();
    if (m.ran_ue_ngap_id) {
        std::cout << R"(,"ran_ue_ngap_id":)" << *m.ran_ue_ngap_id;
    }
    if (m.amf_ue_ngap_id) {
        std::cout << R"(,"amf_ue_ngap_id":)" << *m.amf_ue_ngap_id;
    }
    if (m.global_gnb_id) {
        std::cout << R"(,"gnb_id":)" << m.global_gnb_id->gnb_id << R"(,"gnb_id_bits":)"
                  << unsigned{m.global_gnb_id->gnb_id_bits} << R"(,"plmn":")"
                  << m.global_gnb_id->plmn << '"';
    }
    if (m.ran_node_name) {
        std::cout << R"(,"ran_node_name":")" << *m.ran_node_name << '"';
    }
    std::cout << R"(,"nas_pdu_count":)" << m.nas_pdus.size() << R"(,"size_bytes":)"
              << m.size_bytes << "}\n";
    return kExitOk;
}

int cmd_decode_nas(std::string_view hex) {
    const auto bytes = parse_hex(hex);
    if (!bytes) {
        std::cerr << "error: input is not valid hex\n";
        return kExitUsage;
    }
    const auto result = prahari::nas::decode(std::span<const std::uint8_t>{*bytes}, std::nullopt);
    if (!result) {
        std::cout << R"({"ok":false,"error":")" << prahari::to_string(result.error()) << "\"}\n";
        return kExitDataErr;
    }
    const auto& info = result.value();
    std::cout << R"({"ok":true,"protocol":"nas","message_type":)" << unsigned{info.message_type}
              << R"(,"message":")" << info.message << R"(","is_5gsm":)"
              << (info.is_5gsm ? "true" : "false");
    if (info.registration_type) {
        std::cout << R"(,"registration_type":)" << unsigned{*info.registration_type};
    }
    std::cout << R"(,"has_supi":)" << (info.supi ? "true" : "false") << "}\n";
    return kExitOk;
}

int run(const std::vector<std::string_view>& args) {
    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        print_usage(std::cout);
        return args.empty() ? kExitUsage : kExitOk;
    }
    if (args[0] == "--version") {
        std::cout << "prahari-probe " << prahari::kVersion << '\n';
        return kExitOk;
    }
    if (args[0] == "decode-pfcp" && args.size() == 2) {
        return cmd_decode_pfcp(args[1]);
    }
    if (args[0] == "decode-ngap" && args.size() == 2) {
        return cmd_decode_ngap(args[1]);
    }
    if (args[0] == "decode-nas" && args.size() == 2) {
        return cmd_decode_nas(args[1]);
    }
    if (args[0] == "run" || args[0] == "bench") {
        Options o;
        if (const auto err = parse_options(args, o); !err.empty()) {
            std::cerr << "error: " << err << "\n\n";
            print_usage(std::cerr);
            return kExitUsage;
        }
        return args[0] == "run" ? cmd_run(o) : cmd_bench(o);
    }
    print_usage(std::cerr);
    return kExitUsage;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(std::vector<std::string_view>(argv + 1, argv + argc));
    } catch (const std::exception& e) {
        (void)std::fputs("fatal: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("fatal: unknown exception\n", stderr);
    }
    return 70;  // EX_SOFTWARE
}
