// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "prahari/net.hpp"

using prahari::DecodeError;
using prahari::net::decode_frame;
using prahari::net::LinkType;
using prahari::net::Transport;

namespace {

using Bytes = std::vector<std::uint8_t>;

void append(Bytes& b, std::initializer_list<std::uint8_t> v) {
    b.insert(b.end(), v);
}

void u16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8U));
    b.push_back(static_cast<std::uint8_t>(v));
}

Bytes ethernet(std::uint16_t ethertype) {
    Bytes b(12, 0xAA);
    u16(b, ethertype);
    return b;
}

// Minimal IPv4 header (no options) for `payload_len` bytes of `proto`.
void ipv4(Bytes& b, std::uint8_t proto, std::size_t payload_len, std::uint16_t frag = 0) {
    append(b, {0x45, 0x00});
    u16(b, static_cast<std::uint16_t>(20 + payload_len));
    append(b, {0x00, 0x01});
    u16(b, frag);
    append(b, {64, proto, 0x00, 0x00, 172, 22, 0, 7, 172, 22, 0, 8});
}

void udp(Bytes& b, std::uint16_t sport, std::uint16_t dport, const Bytes& payload) {
    u16(b, sport);
    u16(b, dport);
    u16(b, static_cast<std::uint16_t>(8 + payload.size()));
    append(b, {0x00, 0x00});
    b.insert(b.end(), payload.begin(), payload.end());
}

Bytes udp_frame(const Bytes& payload) {
    Bytes f = ethernet(0x0800);
    ipv4(f, 17, 8 + payload.size());
    udp(f, 8805, 8805, payload);
    return f;
}

}  // namespace

TEST(Net, EthernetIpv4Udp) {
    const Bytes payload{1, 2, 3, 4};
    const auto frame = udp_frame(payload);  // must outlive r: Packet holds spans into it
    const auto r = decode_frame(LinkType::kEthernet, frame);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& p = r.value();
    EXPECT_EQ(p.transport, Transport::kUdp);
    EXPECT_EQ(p.src.to_string(), "172.22.0.7");
    EXPECT_EQ(p.dst.to_string(), "172.22.0.8");
    EXPECT_EQ(p.src_port, 8805);
    ASSERT_EQ(p.payload.size(), 4U);
    EXPECT_EQ(p.payload[3], 4);
}

TEST(Net, EthernetPaddingIsTrimmedByIpLength) {
    auto f = udp_frame(Bytes{9});
    f.insert(f.end(), 20, 0x00);  // minimum-size Ethernet padding
    const auto r = decode_frame(LinkType::kEthernet, f);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().payload.size(), 1U);
}

TEST(Net, VlanTaggedFrame) {
    Bytes f = ethernet(0x8100);
    append(f, {0x00, 0x64});  // VLAN 100
    u16(f, 0x0800);
    ipv4(f, 17, 9);
    udp(f, 1, 8805, Bytes{7});
    const auto r = decode_frame(LinkType::kEthernet, f);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_EQ(r.value().dst_port, 8805);
}

TEST(Net, LinuxCookedV2) {
    Bytes f;
    u16(f, 0x0800);               // protocol
    f.insert(f.end(), 18, 0x00);  // rest of SLL2 header
    ipv4(f, 17, 9);
    udp(f, 8805, 2, Bytes{1});
    const auto r = decode_frame(LinkType::kLinuxSll2, f);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_EQ(r.value().src_port, 8805);
}

TEST(Net, RawIpv6Udp) {
    Bytes f{0x60, 0, 0, 0};
    u16(f, 9);            // payload length: UDP header + 1
    append(f, {17, 64});  // next header UDP, hop limit
    for (int i = 0; i < 32; ++i) {
        f.push_back(static_cast<std::uint8_t>(i));
    }
    udp(f, 8805, 8805, Bytes{0x42});
    const auto r = decode_frame(LinkType::kRaw, f);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_TRUE(r.value().src.v6);
    EXPECT_EQ(r.value().src.to_string(), "1:203:405:607:809:a0b:c0d:e0f");
    EXPECT_EQ(r.value().payload[0], 0x42);
}

TEST(Net, IpFragmentsAreUnsupported) {
    Bytes f = ethernet(0x0800);
    ipv4(f, 17, 9, 0x2000);  // More Fragments set
    udp(f, 8805, 8805, Bytes{1});
    EXPECT_EQ(decode_frame(LinkType::kEthernet, f).error(), DecodeError::kUnsupported);
}

TEST(Net, NonIpIsUnsupported) {
    Bytes f = ethernet(0x0806);  // ARP
    f.insert(f.end(), 28, 0);
    EXPECT_EQ(decode_frame(LinkType::kEthernet, f).error(), DecodeError::kUnsupported);
}

TEST(Net, SctpBundledDataChunks) {
    // Two complete DATA chunks (NGAP, PPID 60) plus a SACK, as Open5GS/UERANSIM bundle them.
    Bytes sctp;
    append(sctp, {0x96, 0x4C, 0x96, 0x4C, 0, 0, 0, 1, 0, 0, 0, 0});  // ports 38476, vtag, csum
    for (std::uint8_t i = 0; i < 2; ++i) {
        append(sctp, {0x00, 0x03});  // DATA, B+E
        u16(sctp, 16 + 3);           // length (3 bytes of user data)
        append(sctp, {0, 0, 0, i, 0, 1, 0, i, 0, 0, 0, 60, 0xAB, 0xCD, i, 0x00});  // + 1 pad
    }
    append(sctp, {0x03, 0x00});  // SACK
    u16(sctp, 16);
    sctp.insert(sctp.end(), 12, 0);

    Bytes f = ethernet(0x0800);
    ipv4(f, 132, sctp.size());
    f.insert(f.end(), sctp.begin(), sctp.end());
    const auto r = decode_frame(LinkType::kEthernet, f);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& p = r.value();
    EXPECT_EQ(p.transport, Transport::kSctp);
    ASSERT_EQ(p.sctp_data.size(), 2U);
    EXPECT_EQ(p.sctp_data[0].ppid, prahari::net::kPpidNgap);
    EXPECT_EQ(p.sctp_data[1].stream_id, 1);
    ASSERT_EQ(p.sctp_data[1].payload.size(), 3U);
    EXPECT_EQ(p.sctp_data[1].payload[2], 1);
}

TEST(Net, SctpFragmentedDataIsSkipped) {
    Bytes sctp;
    append(sctp, {0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0});
    append(sctp, {0x00, 0x02});  // DATA, B only: first fragment of a larger message
    u16(sctp, 20);
    append(sctp, {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, 1, 2, 3, 4});
    Bytes f = ethernet(0x0800);
    ipv4(f, 132, sctp.size());
    f.insert(f.end(), sctp.begin(), sctp.end());
    const auto r = decode_frame(LinkType::kEthernet, f);
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(r.value().sctp_data.empty());
}

TEST(Net, EveryTruncationFailsCleanly) {
    const auto f = udp_frame(Bytes{1, 2, 3, 4, 5, 6, 7, 8});
    for (std::size_t n = 0; n < f.size(); ++n) {
        const auto r =
            decode_frame(LinkType::kEthernet, std::span<const std::uint8_t>{f.data(), n});
        EXPECT_FALSE(r.ok()) << "prefix " << n;
    }
}
