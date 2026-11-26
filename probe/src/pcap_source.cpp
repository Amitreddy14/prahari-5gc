// SPDX-License-Identifier: MIT
#include "prahari/pcap_source.hpp"

#include <array>

#include <pcap/pcap.h>

namespace prahari {

namespace {

constexpr int kSnapLen = 65535;
constexpr int kReadTimeoutMs = 200;
// Kernel ring buffer for live capture. libpcap's default (2 MiB) leaves little room for
// a burst while the probe is busy; 32 MiB holds ~200k small signalling packets.
constexpr int kBufferBytes = 32 * 1024 * 1024;
constexpr std::uint64_t kNsPerSec = 1'000'000'000ULL;
constexpr std::uint64_t kNsPerUs = 1'000ULL;

std::string apply_filter(pcap* handle, const std::string& bpf) {
    if (bpf.empty()) {
        return {};
    }
    bpf_program prog{};
    if (pcap_compile(handle, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        return "invalid BPF filter '" + bpf + "': " + pcap_geterr(handle);
    }
    const int rc = pcap_setfilter(handle, &prog);
    pcap_freecode(&prog);
    if (rc != 0) {
        return std::string{"cannot set filter: "} + pcap_geterr(handle);
    }
    return {};
}

}  // namespace

PcapSource::PcapSource(pcap* handle, bool nanosecond, bool live)
    : handle_(handle), nanosecond_(nanosecond), live_(live), raw_link_(pcap_datalink(handle)) {
    switch (raw_link_) {
        case DLT_EN10MB:
            link_ = net::LinkType::kEthernet;
            link_supported_ = true;
            break;
        case DLT_RAW:  // libpcap maps LINKTYPE_RAW (101) in files to this
            link_ = net::LinkType::kRaw;
            link_supported_ = true;
            break;
        case DLT_LINUX_SLL:
            link_ = net::LinkType::kLinuxSll;
            link_supported_ = true;
            break;
        case 276:  // DLT_LINUX_SLL2
            link_ = net::LinkType::kLinuxSll2;
            link_supported_ = true;
            break;
        default: link_supported_ = false; break;
    }
}

PcapSource::~PcapSource() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
    }
}

PcapSource::Opened PcapSource::open_file(const std::string& path, const std::string& bpf) {
    std::array<char, PCAP_ERRBUF_SIZE> err{};
    pcap* h = pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_NANO,
                                                      err.data());
    if (h == nullptr) {
        return {nullptr, std::string{"cannot open '"} + path + "': " + err.data()};
    }
    std::unique_ptr<PcapSource> src{new PcapSource(h, true, false)};
    if (auto e = apply_filter(h, bpf); !e.empty()) {
        return {nullptr, e};
    }
    return {std::move(src), {}};
}

PcapSource::Opened PcapSource::open_live(const std::string& iface, const std::string& bpf) {
    std::array<char, PCAP_ERRBUF_SIZE> err{};
    pcap* h = pcap_create(iface.c_str(), err.data());
    if (h == nullptr) {
        return {nullptr, std::string{"cannot open interface '"} + iface + "': " + err.data()};
    }
    std::unique_ptr<PcapSource> guard;  // set once we know precision
    (void)pcap_set_snaplen(h, kSnapLen);
    (void)pcap_set_promisc(h, 1);
    (void)pcap_set_timeout(h, kReadTimeoutMs);
    (void)pcap_set_immediate_mode(h, 1);
    (void)pcap_set_buffer_size(h, kBufferBytes);
    const bool nano = pcap_set_tstamp_precision(h, PCAP_TSTAMP_PRECISION_NANO) == 0;
    if (const int rc = pcap_activate(h); rc < 0) {
        const std::string msg = std::string{"cannot activate '"} + iface + "': " + pcap_geterr(h);
        pcap_close(h);
        return {nullptr, msg};
    }
    guard.reset(new PcapSource(h, nano, true));
    if (auto e = apply_filter(h, bpf); !e.empty()) {
        return {nullptr, e};
    }
    return {std::move(guard), {}};
}

PcapSource::CaptureStats PcapSource::capture_stats() const {
    CaptureStats c;
    if (!live_) {
        return c;
    }
    pcap_stat st{};
    if (pcap_stats(handle_, &st) != 0) {
        return c;
    }
    c.available = true;
    c.received = st.ps_recv;
    c.dropped_kernel = st.ps_drop;
    c.dropped_interface = st.ps_ifdrop;
    return c;
}

PcapSource::Next PcapSource::next(Frame& out) {
    pcap_pkthdr* hdr = nullptr;
    const std::uint8_t* data = nullptr;
    const int rc = pcap_next_ex(handle_, &hdr, &data);
    if (rc == 1) {
        const auto sec = static_cast<std::uint64_t>(hdr->ts.tv_sec);
        const auto frac = static_cast<std::uint64_t>(hdr->ts.tv_usec);
        out.ts_ns = sec * kNsPerSec + (nanosecond_ ? frac : frac * kNsPerUs);
        out.data = std::span<const std::uint8_t>{data, hdr->caplen};
        out.wire_len = hdr->len;
        return Next::kFrame;
    }
    if (rc == 0) {
        return Next::kTimeout;
    }
    if (rc == PCAP_ERROR_BREAK) {
        return Next::kEnd;
    }
    return Next::kError;
}

std::string PcapSource::last_error() const {
    return pcap_geterr(handle_);
}

void PcapSource::stop() noexcept {
    pcap_breakloop(handle_);
}

}  // namespace prahari
