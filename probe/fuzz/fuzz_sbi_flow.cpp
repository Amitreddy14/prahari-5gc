// SPDX-License-Identifier: MIT
// libFuzzer target: the whole SBI path through Pipeline::on_frame: Ethernet/IPv4/TCP
// framing, TCP reassembly (reordering, retransmission, gaps, FIN/RST), HTTP/2, HPACK,
// SBI naming and identity extraction, event JSON.
//
// Input: records "<flags><seq offset: 2 bytes BE><len><payload>". Bit 0x80 of flags
// picks the direction; the low TCP flag bits are used as-is. Both directions start
// with a SYN so data is decodable. Sequence numbers are offsets from each side's ISN.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "prahari/pipeline.hpp"

namespace {

std::vector<std::uint8_t> tcp_frame(bool from_client, std::uint32_t seq, std::uint8_t flags,
                                    std::span<const std::uint8_t> payload) {
    const std::array<std::uint8_t, 4> client{172, 22, 0, 5};
    const std::array<std::uint8_t, 4> server{172, 22, 0, 10};
    const std::uint16_t cport = 40000;
    const std::uint16_t sport = 7777;
    const auto& src = from_client ? client : server;
    const auto& dst = from_client ? server : client;
    const std::uint16_t sp = from_client ? cport : sport;
    const std::uint16_t dp = from_client ? sport : cport;
    const auto total = static_cast<std::uint16_t>(20 + 20 + payload.size());
    std::vector<std::uint8_t> f{
        // Ethernet: dst, src, IPv4
        0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x08, 0x00,
        // IPv4 header (no options, checksum not verified by the probe)
        0x45, 0, static_cast<std::uint8_t>(total >> 8U), static_cast<std::uint8_t>(total), 0, 0,
        0x40, 0, 64, 6, 0, 0, src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
        // TCP header
        static_cast<std::uint8_t>(sp >> 8U), static_cast<std::uint8_t>(sp),
        static_cast<std::uint8_t>(dp >> 8U), static_cast<std::uint8_t>(dp),
        static_cast<std::uint8_t>(seq >> 24U), static_cast<std::uint8_t>(seq >> 16U),
        static_cast<std::uint8_t>(seq >> 8U), static_cast<std::uint8_t>(seq), 0, 0, 0, 0, 0x50,
        flags, 0xFF, 0xFF, 0, 0, 0, 0};
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    prahari::NullSink sink;
    prahari::Pipeline p{prahari::NfMap::testbed_default(), sink, 1};
    p.set_supi_hasher(prahari::SupiHasher{"fuzz-key-0123456789abcdef"});
    constexpr std::uint32_t kClientIsn = 0xFFFFFF00U;  // wraps early: exercise serial math
    constexpr std::uint32_t kServerIsn = 1000;
    std::uint64_t ts = 1'000'000'000;
    const auto link = prahari::net::LinkType::kEthernet;
    p.on_frame(ts, link, tcp_frame(true, kClientIsn, 0x02, {}));
    p.on_frame(ts, link, tcp_frame(false, kServerIsn, 0x12, {}));

    std::span<const std::uint8_t> in{data, size};
    while (in.size() >= 4) {
        const bool from_client = (in[0] & 0x80U) == 0;
        const auto flags = static_cast<std::uint8_t>((in[0] & 0x1FU) | 0x10U);  // keep ACK
        const std::uint32_t off = (std::uint32_t{in[1]} << 8U) | in[2];
        const std::size_t len = std::min<std::size_t>(in[3], in.size() - 4);
        const auto payload = in.subspan(4, len);
        const auto isn = from_client ? kClientIsn : kServerIsn;
        p.on_frame(ts += 1000, link, tcp_frame(from_client, isn + 1 + off, flags, payload));
        in = in.subspan(4 + len);
    }
    return 0;
}
