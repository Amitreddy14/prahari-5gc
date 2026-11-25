// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "prahari/pfcp.hpp"
#include "prahari/pfcp_ie.hpp"

namespace pfcp = prahari::pfcp;

namespace {

// Real Open5GS v2.7.7 Association Setup Response body (UPF 172.22.0.8).
constexpr std::array<std::uint8_t, 38> kAssocResp{
    0x20, 0x06, 0x00, 0x22, 0x00, 0x00, 0x01, 0x00, 0x00, 0x3c, 0x00, 0x05, 0x00,
    0xac, 0x16, 0x00, 0x08, 0x00, 0x13, 0x00, 0x01, 0x01, 0x00, 0x60, 0x00, 0x04,
    0xee, 0xb1, 0x3d, 0xcf, 0x00, 0x2b, 0x00, 0x04, 0x10, 0x21, 0x10, 0x04};

using Bytes = std::vector<std::uint8_t>;

void ie(Bytes& b, std::uint16_t type, const Bytes& value) {
    b.push_back(static_cast<std::uint8_t>(type >> 8U));
    b.push_back(static_cast<std::uint8_t>(type));
    b.push_back(static_cast<std::uint8_t>(value.size() >> 8U));
    b.push_back(static_cast<std::uint8_t>(value.size()));
    b.insert(b.end(), value.begin(), value.end());
}

}  // namespace

TEST(PfcpIe, RealAssociationResponse) {
    const auto msg = pfcp::decode(kAssocResp);
    ASSERT_TRUE(msg.ok());
    const auto s = pfcp::summarize(msg.value().body);
    ASSERT_TRUE(s.ok()) << prahari::to_string(s.error());
    EXPECT_EQ(s.value().ie_count, 4U);  // Node ID, Cause, Recovery TS, UP Features
    ASSERT_TRUE(s.value().node_id.has_value());
    EXPECT_EQ(*s.value().node_id, "172.22.0.8");
    ASSERT_TRUE(s.value().cause.has_value());
    EXPECT_EQ(*s.value().cause, 1);
    EXPECT_EQ(pfcp::cause_name(1), "RequestAccepted");
}

TEST(PfcpIe, FSeidWithIpv4) {
    Bytes body;
    ie(body, pfcp::ie::kFSeid, {0x02, 0, 0, 0, 0, 0, 0, 0x07, 0x5e, 172, 22, 0, 7});
    const auto s = pfcp::summarize(body);
    ASSERT_TRUE(s.ok());
    ASSERT_TRUE(s.value().f_seid.has_value());
    EXPECT_EQ(s.value().f_seid->seid, 0x75eU);
    ASSERT_TRUE(s.value().f_seid->ipv4.has_value());
    EXPECT_EQ(s.value().f_seid->ipv4->to_string(), "172.22.0.7");
    EXPECT_FALSE(s.value().f_seid->ipv6.has_value());
}

TEST(PfcpIe, GroupedPdrAndFarIdsCountedOnlyInTheirOwnGroups) {
    // Create PDR { PDR ID 1, FAR ID 9 (reference) }, Create FAR { FAR ID 9 }.
    Bytes pdr;
    ie(pdr, pfcp::ie::kPdrId, {0x00, 0x01});
    ie(pdr, pfcp::ie::kFarId, {0, 0, 0, 9});
    Bytes far;
    ie(far, pfcp::ie::kFarId, {0, 0, 0, 9});
    Bytes body;
    ie(body, pfcp::ie::kCreatePdr, pdr);
    ie(body, pfcp::ie::kCreateFar, far);
    const auto s = pfcp::summarize(body);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s.value().pdr_groups, 1U);
    EXPECT_EQ(s.value().far_groups, 1U);
    ASSERT_EQ(s.value().pdr_ids.size(), 1U);
    EXPECT_EQ(s.value().pdr_ids[0], 1);
    ASSERT_EQ(s.value().far_ids.size(), 1U);  // the reference inside the PDR is not a FAR
    EXPECT_EQ(s.value().far_ids[0], 9U);
}

TEST(PfcpIe, FqdnNodeIdIsDottedAndSanitised) {
    Bytes body;
    ie(body, pfcp::ie::kNodeId, {0x02, 3, 'u', 'p', 'f', 4, 'c', 'o', '\n', 'e'});
    const auto s = pfcp::summarize(body);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(*s.value().node_id, "upf.co?e");
}

TEST(PfcpIe, UserIdIsFlaggedNotCopied) {
    Bytes body;
    ie(body, pfcp::ie::kUserId, {0x01, 8, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf1});
    const auto s = pfcp::summarize(body);
    ASSERT_TRUE(s.ok());
    EXPECT_TRUE(s.value().has_user_id);
}

TEST(PfcpIe, VendorIeCarriesEnterpriseId) {
    Bytes body;
    ie(body, 0x8001, {0x12, 0x34, 0xde, 0xad});
    const auto ies = pfcp::split_ies(body);
    ASSERT_TRUE(ies.ok());
    ASSERT_EQ(ies.value().size(), 1U);
    EXPECT_EQ(ies.value()[0].enterprise_id, 0x1234);
    EXPECT_EQ(ies.value()[0].value.size(), 2U);
    EXPECT_TRUE(pfcp::summarize(body).value().has_vendor_ie);
}

TEST(PfcpIe, OverlongIeLengthIsRejected) {
    Bytes body{0x00, 0x13, 0x00, 0x09, 0x01};  // Cause claims 9 bytes, has 1
    EXPECT_EQ(pfcp::summarize(body).error(), prahari::DecodeError::kTruncated);
}

TEST(PfcpIe, DeepNestingIsBounded) {
    Bytes inner;
    ie(inner, pfcp::ie::kPdrId, {0, 1});
    for (int i = 0; i < 10; ++i) {  // 10 levels of Create PDR inside Create PDR
        Bytes wrapped;
        ie(wrapped, pfcp::ie::kCreatePdr, inner);
        inner = wrapped;
    }
    EXPECT_EQ(pfcp::summarize(inner).error(), prahari::DecodeError::kMalformed);
}
