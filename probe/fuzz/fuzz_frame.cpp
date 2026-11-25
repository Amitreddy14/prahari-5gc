// SPDX-License-Identifier: MIT
// libFuzzer target: whole pipeline on arbitrary frames. The first byte picks the
// link type, the rest is the frame. Exercises L2-L4, SCTP chunks, PFCP, IEs, the
// session table and JSON output together.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "prahari/pipeline.hpp"

namespace {
prahari::NullSink g_sink;
prahari::Pipeline g_pipeline{prahari::NfMap::testbed_default(), g_sink, 1};
constexpr std::array<prahari::net::LinkType, 4> kLinks{
    prahari::net::LinkType::kEthernet, prahari::net::LinkType::kRaw,
    prahari::net::LinkType::kLinuxSll, prahari::net::LinkType::kLinuxSll2};
std::uint64_t g_ts = 0;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) {
        return 0;
    }
    const auto link = kLinks[data[0] % kLinks.size()];
    g_pipeline.on_frame(++g_ts, link, std::span<const std::uint8_t>{data + 1, size - 1});
    return 0;
}
