// SPDX-License-Identifier: MIT
// Thin RAII wrapper over libpcap: read frames from a live interface or a pcap file.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "prahari/net.hpp"

struct pcap;  // from <pcap/pcap.h>; kept out of this header

namespace prahari {

struct Frame {
    std::uint64_t ts_ns{};
    std::span<const std::uint8_t> data;  // captured bytes (may be < wire length)
    std::uint32_t wire_len{};
};

class PcapSource {
public:
    struct Opened;

    // Open a capture file. `bpf` may be empty (no filter).
    [[nodiscard]] static Opened open_file(const std::string& path, const std::string& bpf);
    // Open a live interface in promiscuous mode with nanosecond timestamps if available.
    [[nodiscard]] static Opened open_live(const std::string& iface, const std::string& bpf);

    PcapSource(const PcapSource&) = delete;
    PcapSource& operator=(const PcapSource&) = delete;
    PcapSource(PcapSource&&) = delete;
    PcapSource& operator=(PcapSource&&) = delete;
    ~PcapSource();

    // Link type of the capture, or nullopt-like false if libpcap reports one we do not decode.
    [[nodiscard]] bool link_supported() const noexcept { return link_supported_; }
    [[nodiscard]] net::LinkType link() const noexcept { return link_; }
    [[nodiscard]] int raw_link() const noexcept { return raw_link_; }

    enum class Next : std::uint8_t { kFrame, kTimeout, kEnd, kError };
    // Fetch the next frame. The returned span is valid until the next call.
    [[nodiscard]] Next next(Frame& out);
    [[nodiscard]] std::string last_error() const;

    // libpcap's counters (live capture only): packets the kernel dropped because the
    // capture buffer was full, and drops reported by the interface/driver.
    struct CaptureStats {
        bool available{};
        std::uint64_t received{};
        std::uint64_t dropped_kernel{};
        std::uint64_t dropped_interface{};
    };
    [[nodiscard]] CaptureStats capture_stats() const;

    // Make a blocking next() return kEnd (safe from a signal handler).
    void stop() noexcept;

private:
    PcapSource(pcap* handle, bool nanosecond, bool live);

    pcap* handle_{};
    bool nanosecond_{};
    bool live_{};
    int raw_link_{};
    net::LinkType link_{net::LinkType::kEthernet};
    bool link_supported_{};
};

struct PcapSource::Opened {
    std::unique_ptr<PcapSource> source;
    std::string error;
};

}  // namespace prahari
