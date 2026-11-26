// SPDX-License-Identifier: MIT
// Vectors: real NGAP PDUs from the Prahari testbed (UERANSIM v3.2.8 gNB <-> Open5GS
// v2.7.7 AMF), cross-checked against tshark 4.2.
#include <gtest/gtest.h>

#include "hex.hpp"
#include "prahari/ngap.hpp"

namespace ngap = prahari::ngap;
using prahari::test::hex;

namespace {
const auto kNgSetupRequest =
    hex("0015003e000004001b00090000f1105000000001005240140880554552414e53494d2d676e622d312d312d"
        "310066000d00000000010000f110000000080015400140");
const auto kInitialUeMessage =
    hex("000f40480000050055000200010026001a197e004179000d0100f11000000000000000008"
        "02e04f0f0f0f0007900135000f110000000010000f110000001eeb17933005a4001180070400100");
const auto kUeContextReleaseCommand = hex("002900100000020072000400030003000f400140");
const auto kPduSessionResourceSetupResponse =
    hex("201d003b000004000a40020001005540020001004b40110000010d0003e0ac16001400000001000100"
        "7940135000f110000000010000f110000001eeb17933");
}  // namespace

TEST(Ngap, NgSetupRequestGlobalGnbIdAndName) {
    const auto r = ngap::decode(kNgSetupRequest);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& m = r.value();
    EXPECT_EQ(m.pdu_type, ngap::PduType::kInitiating);
    EXPECT_EQ(m.procedure_code, ngap::proc::kNgSetup);
    EXPECT_EQ(m.ies.size(), 4U);
    ASSERT_TRUE(m.global_gnb_id.has_value());
    EXPECT_EQ(m.global_gnb_id->plmn, "00101");
    EXPECT_EQ(m.global_gnb_id->gnb_id, 1U);
    EXPECT_EQ(m.global_gnb_id->gnb_id_bits, 32);
    EXPECT_EQ(m.ran_node_name, "UERANSIM-gnb-1-1-1");
    EXPECT_EQ(ngap::message_name(m.procedure_code, m.pdu_type), "NGSetupRequest");
}

TEST(Ngap, InitialUeMessageCarriesRanIdAndNas) {
    const auto r = ngap::decode(kInitialUeMessage);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& m = r.value();
    EXPECT_EQ(m.procedure_code, ngap::proc::kInitialUeMessage);
    EXPECT_EQ(m.ran_ue_ngap_id, 1U);
    EXPECT_FALSE(m.amf_ue_ngap_id.has_value());
    ASSERT_EQ(m.nas_pdus.size(), 1U);
    EXPECT_EQ(m.nas_pdus[0].size(), 25U);
    EXPECT_EQ(m.nas_pdus[0][0], 0x7E);  // 5GMM
    EXPECT_TRUE(ngap::is_class2(m.procedure_code));
}

TEST(Ngap, UeContextReleaseCommandNestedIdPair) {
    const auto r = ngap::decode(kUeContextReleaseCommand);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_EQ(r.value().amf_ue_ngap_id, 3U);
    EXPECT_EQ(r.value().ran_ue_ngap_id, 3U);
    EXPECT_EQ(ngap::message_name(41, ngap::PduType::kInitiating), "UEContextReleaseCommand");
}

TEST(Ngap, SuccessfulOutcomeIdsAndName) {
    const auto r = ngap::decode(kPduSessionResourceSetupResponse);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_EQ(r.value().pdu_type, ngap::PduType::kSuccessful);
    EXPECT_EQ(r.value().amf_ue_ngap_id, 1U);
    EXPECT_EQ(r.value().ran_ue_ngap_id, 1U);
    EXPECT_EQ(ngap::message_name(29, ngap::PduType::kSuccessful),
              "PDUSessionResourceSetupResponse");
}

TEST(Ngap, EveryTruncationFailsCleanly) {
    for (const auto* v : {&kNgSetupRequest, &kInitialUeMessage, &kUeContextReleaseCommand}) {
        for (std::size_t n = 0; n < v->size(); ++n) {
            const auto r = ngap::decode(std::span<const std::uint8_t>{v->data(), n});
            EXPECT_FALSE(r.ok()) << "prefix " << n;
        }
    }
}

TEST(Ngap, AperLengthDeterminants) {
    const auto one = hex("7f");
    prahari::ByteReader r1{one};
    EXPECT_EQ(ngap::aper::length(r1).value(), 127U);
    const auto two = hex("8090");  // 10 + 14-bit length
    prahari::ByteReader r2{two};
    EXPECT_EQ(ngap::aper::length(r2).value(), 0x90U);
    const auto frag = hex("c1");
    prahari::ByteReader r3{frag};
    EXPECT_EQ(ngap::aper::length(r3).error(), prahari::DecodeError::kUnsupported);
}

TEST(Ngap, SizedUintPrefixes) {
    EXPECT_EQ(ngap::aper::sized_uint(hex("000b"), 2).value(), 11U);  // RAN id, 1 octet
    EXPECT_EQ(ngap::aper::sized_uint(hex("c0ffffffff"), 2).value(), 0xFFFFFFFFU);
    EXPECT_EQ(ngap::aper::sized_uint(hex("80ffffffffff"), 3).value(), 0xFFFFFFFFFFULL);
}

TEST(Ngap, HostileIeCountIsBounded) {
    // initiating, proc 15, length 3, ext 0, IE count 0xFFFF
    EXPECT_EQ(ngap::decode(hex("000f400300ffff")).error(), prahari::DecodeError::kMalformed);
}

TEST(Ngap, UnknownProcedureGetsAStableName) {
    EXPECT_EQ(ngap::message_name(200, ngap::PduType::kInitiating), "Procedure200/initiating");
    EXPECT_EQ(ngap::message_name(15, ngap::PduType::kSuccessful), "InitialUEMessage/successful");
}
