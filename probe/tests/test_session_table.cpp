// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include "prahari/session_table.hpp"

namespace pfcp = prahari::pfcp;
using pfcp::SessionState;
using prahari::net::IpAddress;

namespace {

const IpAddress kSmf = IpAddress::v4_from(0xAC160007);
const IpAddress kUpf = IpAddress::v4_from(0xAC160008);
const IpAddress kRogue = IpAddress::v4_from(0xAC160028);

pfcp::SessionMessage msg(std::uint8_t type, const IpAddress& src, const IpAddress& dst,
                         std::optional<std::uint64_t> header, std::optional<std::uint64_t> fseid,
                         std::optional<std::uint8_t> cause = std::nullopt, std::uint64_t ts = 1) {
    pfcp::SessionMessage m;
    m.type = type;
    m.src = src;
    m.dst = dst;
    m.header_seid = header;
    m.f_seid = fseid;
    m.cause = cause;
    m.ts_ns = ts;
    return m;
}

}  // namespace

// The exact SEID flow observed on Open5GS v2.7.7 (session 0x75e <-> 0x91c).
TEST(SessionTable, FullLifecycleFromRealCapture) {
    pfcp::SessionTable t;
    auto v = t.apply(msg(50, kSmf, kUpf, 0, 0x75e));
    EXPECT_EQ(v.state, SessionState::kEstablishing);
    EXPECT_EQ(v.cp_seid, 0x75eU);
    EXPECT_FALSE(v.up_seid.has_value());

    v = t.apply(msg(51, kUpf, kSmf, 0x75e, 0x91c, 1));
    EXPECT_EQ(v.state, SessionState::kActive);
    EXPECT_EQ(v.up_seid, 0x91cU);
    EXPECT_EQ(t.active(), 1U);

    v = t.apply(msg(52, kSmf, kUpf, 0x91c, std::nullopt));
    EXPECT_TRUE(v.known);
    EXPECT_EQ(v.cp_seid, 0x75eU);  // resolved from the UP SEID alone

    v = t.apply(msg(53, kUpf, kSmf, 0x75e, std::nullopt, 1));
    EXPECT_EQ(v.up_seid, 0x91cU);  // resolved from the CP SEID alone

    v = t.apply(msg(54, kSmf, kUpf, 0x91c, std::nullopt));
    EXPECT_EQ(v.state, SessionState::kActive);
    v = t.apply(msg(55, kUpf, kSmf, 0x75e, std::nullopt, 1));
    EXPECT_EQ(v.state, SessionState::kDeleted);
    EXPECT_EQ(t.size(), 0U);
    EXPECT_EQ(t.active(), 0U);
}

// N4-01 in the threat model: a deletion for a SEID that was never established.
TEST(SessionTable, DeletionOfUnknownSessionIsFlagged) {
    pfcp::SessionTable t;
    const auto v = t.apply(msg(54, kRogue, kUpf, 0xDEAD, std::nullopt));
    EXPECT_FALSE(v.known);
    EXPECT_EQ(v.state, SessionState::kUnknown);
    EXPECT_EQ(v.up_seid, 0xDEADU);
}

TEST(SessionTable, SeidIsScopedToTheReceivingNode) {
    pfcp::SessionTable t;
    (void)t.apply(msg(50, kSmf, kUpf, 0, 0x75e));
    (void)t.apply(msg(51, kUpf, kSmf, 0x75e, 0x91c, 1));
    // Same UP SEID, but addressed to a different UPF: not the same session.
    const auto v = t.apply(msg(54, kSmf, kRogue, 0x91c, std::nullopt));
    EXPECT_FALSE(v.known);
}

TEST(SessionTable, RejectedEstablishmentDoesNotCreateSession) {
    pfcp::SessionTable t;
    (void)t.apply(msg(50, kSmf, kUpf, 0, 0x10));
    const auto v = t.apply(msg(51, kUpf, kSmf, 0x10, std::nullopt, 75));  // no resources
    EXPECT_TRUE(v.known);
    EXPECT_EQ(t.size(), 0U);
    EXPECT_EQ(t.active(), 0U);
}

TEST(SessionTable, RetransmittedRequestDoesNotDuplicate) {
    pfcp::SessionTable t;
    (void)t.apply(msg(50, kSmf, kUpf, 0, 0x10));
    (void)t.apply(msg(50, kSmf, kUpf, 0, 0x10));
    EXPECT_EQ(t.size(), 1U);
}

TEST(SessionTable, CapacityIsBounded) {
    pfcp::SessionTable t{2};
    (void)t.apply(msg(50, kSmf, kUpf, 0, 1));
    (void)t.apply(msg(50, kSmf, kUpf, 0, 2));
    const auto v = t.apply(msg(50, kSmf, kUpf, 0, 3));
    EXPECT_FALSE(v.known);
    EXPECT_EQ(t.size(), 2U);
    EXPECT_EQ(t.dropped_table_full(), 1U);
}

TEST(SessionTable, UnansweredEstablishmentsExpire) {
    constexpr std::uint64_t kTimeout = 1000;
    pfcp::SessionTable t{100, kTimeout};
    (void)t.apply(msg(50, kSmf, kUpf, 0, 1, std::nullopt, 1));
    // The sweep runs every 4096 operations; drive it with unrelated lookups.
    for (int i = 0; i < 4096; ++i) {
        (void)t.apply(msg(54, kSmf, kUpf, 0xFFFF, std::nullopt, std::nullopt, 10'000));
    }
    EXPECT_EQ(t.size(), 0U);
    EXPECT_EQ(t.expired_establishing(), 1U);
}
