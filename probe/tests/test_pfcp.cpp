// SPDX-License-Identifier: MIT
// Test vectors are hand-built from 3GPP TS 29.244 section 7.2.2. Phase 2 adds
// vectors cut from real testbed captures and cross-checks them with tshark.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "prahari/pfcp.hpp"

namespace pfcp = prahari::pfcp;
using prahari::DecodeError;

namespace {

// Heartbeat Request (node message, S = 0) carrying a Recovery Time Stamp IE.
constexpr std::array<std::uint8_t, 16> kHeartbeat{
    0x20, 0x01, 0x00, 0x0c,  // v1, type 1, length 12
    0x00, 0x00, 0x01, 0x00,  // seq 1, spare
    0x00, 0x60, 0x00, 0x04,  // IE 96 Recovery Time Stamp, len 4
    0xe5, 0x4d, 0x2a, 0x10};

// Session Establishment Request (S = 1, MP = 1, priority 5) with a Node ID IE.
constexpr std::array<std::uint8_t, 25> kSessionEstablishment{
    0x23, 0x32, 0x00, 0x15,                                 // v1, MP, S, type 50, len 21
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,         // SEID 42
    0x00, 0x00, 0x07, 0x50,                                 // seq 7, priority 5
    0x00, 0x3c, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x01};  // Node ID IPv4 10.0.0.1

}  // namespace

TEST(Pfcp, DecodesNodeMessage) {
    const auto r = pfcp::decode(kHeartbeat);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& h = r.value().header;
    EXPECT_EQ(h.version, 1U);
    EXPECT_FALSE(h.has_seid);
    EXPECT_FALSE(h.seid.has_value());
    EXPECT_EQ(h.message_type, 1U);
    EXPECT_EQ(h.sequence, 1U);
    EXPECT_EQ(h.header_length(), pfcp::kNodeHeaderLen);
    EXPECT_EQ(r.value().body.size(), 8U);
    EXPECT_EQ(pfcp::message_name(h.message_type), "HeartbeatRequest");
}

TEST(Pfcp, DecodesSessionMessageWithSeidAndPriority) {
    const auto r = pfcp::decode(kSessionEstablishment);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& h = r.value().header;
    EXPECT_TRUE(h.has_seid);
    ASSERT_TRUE(h.seid.has_value());
    EXPECT_EQ(*h.seid, 42U);
    EXPECT_EQ(h.sequence, 7U);
    ASSERT_TRUE(h.priority.has_value());
    EXPECT_EQ(*h.priority, 5U);
    EXPECT_TRUE(pfcp::is_session_message(h.message_type));
    EXPECT_EQ(r.value().body.size(), 9U);
    EXPECT_EQ(r.value().body[0], 0x00);
    EXPECT_EQ(r.value().body[1], 0x3c);
}

TEST(Pfcp, RejectsWrongVersion) {
    auto bytes = std::vector<std::uint8_t>(kHeartbeat.begin(), kHeartbeat.end());
    bytes[0] = 0x40;  // version 2
    EXPECT_EQ(pfcp::decode(bytes).error(), DecodeError::kBadVersion);
}

TEST(Pfcp, RejectsEveryTruncation) {
    // Every proper prefix of a valid message must fail cleanly (never crash).
    for (std::size_t n = 0; n < kSessionEstablishment.size(); ++n) {
        const auto r = pfcp::decode(std::span<const std::uint8_t>{kSessionEstablishment.data(), n});
        EXPECT_FALSE(r.ok()) << "prefix length " << n;
    }
}

TEST(Pfcp, RejectsLengthShorterThanHeader) {
    auto bytes =
        std::vector<std::uint8_t>(kSessionEstablishment.begin(), kSessionEstablishment.end());
    bytes[3] = 0x04;  // claims 4 bytes, but S = 1 needs at least 12 after octet 4
    EXPECT_EQ(pfcp::decode(bytes).error(), DecodeError::kBadLength);
}

TEST(Pfcp, RejectsTrailingBytesWithoutFollowOn) {
    auto bytes = std::vector<std::uint8_t>(kHeartbeat.begin(), kHeartbeat.end());
    bytes.push_back(0xff);
    EXPECT_EQ(pfcp::decode(bytes).error(), DecodeError::kBadLength);
}

TEST(Pfcp, AllowsTrailingBytesWithFollowOn) {
    auto bytes = std::vector<std::uint8_t>(kHeartbeat.begin(), kHeartbeat.end());
    bytes[0] = 0x24;  // FO = 1
    bytes.insert(bytes.end(), kHeartbeat.begin(), kHeartbeat.end());
    const auto first = pfcp::decode(bytes);
    ASSERT_TRUE(first.ok());
    EXPECT_TRUE(first.value().header.follow_on);
    const auto next_offset = first.value().header.total_length();
    const auto second = pfcp::decode(std::span<const std::uint8_t>{bytes}.subspan(next_offset));
    ASSERT_TRUE(second.ok());
    EXPECT_EQ(second.value().header.message_type, 1U);
}

TEST(Pfcp, UnknownTypeStillDecodes) {
    auto bytes = std::vector<std::uint8_t>(kHeartbeat.begin(), kHeartbeat.end());
    bytes[1] = 0xc8;  // 200: not assigned; the detector, not the decoder, judges this
    const auto r = pfcp::decode(bytes);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(pfcp::message_name(r.value().header.message_type), "Unknown");
}
