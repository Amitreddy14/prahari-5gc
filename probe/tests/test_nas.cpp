// SPDX-License-Identifier: MIT
// Vectors: NAS-PDUs from real NGAP messages on the Prahari testbed.
#include <gtest/gtest.h>

#include "hex.hpp"
#include "prahari/nas.hpp"
#include "prahari/ngap.hpp"
#include "prahari/supi.hpp"

namespace nas = prahari::nas;
using prahari::test::hex;

namespace {
// Plain Registration Request, SUCI with null scheme: MCC 001 MNC 01 MSIN 0000000002.
const auto kRegistrationRequest =
    hex("7e004179000d0100f110000000000000000020"
        "2e04f0f0f0f0");
// Security Mode Command (SHT 3) selecting NEA0 + NIA2.
const auto kSecurityModeCommand = hex("7e034f5f9b5c007e005d020104f0f0f0f0e1360102");
// UL NAS Transport, SHT 2 ("ciphered" with NEA0), carrying a 5GSM PDU Session
// Establishment Request for PDU session 1.
const auto kUlNasTransport =
    hex("7e0246a0d81e027e00670100152e0101c1ffff91a12801007b000780000a00000d00120181"
        "220101250908696e7465726e6574");
}  // namespace

TEST(Nas, RegistrationRequestNullSchemeRecoversImsi) {
    const auto r = nas::decode(kRegistrationRequest, std::nullopt);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& n = r.value();
    EXPECT_FALSE(n.is_5gsm);
    EXPECT_TRUE(n.decoded);
    EXPECT_EQ(n.message, "RegistrationRequest");
    EXPECT_EQ(n.registration_type, 1);  // initial
    EXPECT_EQ(n.identity, nas::Identity::kSuci);
    EXPECT_EQ(n.suci_null_scheme, true);
    EXPECT_EQ(n.supi, "imsi-001010000000002");
}

TEST(Nas, SecurityModeCommandSelectsAlgorithms) {
    const auto r = nas::decode(kSecurityModeCommand, std::nullopt);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    EXPECT_EQ(r.value().security_header, 3);
    EXPECT_TRUE(r.value().integrity_protected);
    EXPECT_FALSE(r.value().ciphered);
    EXPECT_EQ(r.value().message, "SecurityModeCommand");
    EXPECT_EQ(r.value().selected_ciphering, nas::kNea0);
    EXPECT_EQ(r.value().selected_integrity, 2);
}

TEST(Nas, CipheredMessageIsOpaqueWithoutKnownNullCipher) {
    for (const auto alg : {std::optional<std::uint8_t>{}, std::optional<std::uint8_t>{2}}) {
        const auto r = nas::decode(kUlNasTransport, alg);
        ASSERT_TRUE(r.ok());
        EXPECT_TRUE(r.value().ciphered);
        EXPECT_FALSE(r.value().decoded);
        EXPECT_EQ(r.value().message, "Protected");
    }
}

TEST(Nas, Nea0CipheredMessageIsDecodedWithInner5gsm) {
    const auto r = nas::decode(kUlNasTransport, nas::kNea0);
    ASSERT_TRUE(r.ok()) << prahari::to_string(r.error());
    const auto& n = r.value();
    EXPECT_TRUE(n.decoded);
    EXPECT_EQ(n.message, "ULNASTransport");
    EXPECT_EQ(n.sm_message, "PDUSessionEstablishmentRequest");
    EXPECT_EQ(n.sm_message_type, 0xC1);
    EXPECT_EQ(n.pdu_session_id, 1);
}

TEST(Nas, EveryTruncationIsSafeAndNeverYieldsAPartialImsi) {
    // The 5GS mobile identity ends at byte 19 of kRegistrationRequest; an optional IE follows.
    constexpr std::size_t kIdentityEnd = 19;
    for (const auto* v : {&kRegistrationRequest, &kSecurityModeCommand, &kUlNasTransport}) {
        for (std::size_t n = 0; n < v->size(); ++n) {
            const auto r = nas::decode(std::span<const std::uint8_t>{v->data(), n}, nas::kNea0);
            if (v != &kRegistrationRequest || !r.ok() || !r.value().supi) {
                continue;
            }
            // A SUPI is only ever the complete, correct one.
            EXPECT_GE(n, kIdentityEnd) << "prefix " << n;
            EXPECT_EQ(*r.value().supi, "imsi-001010000000002") << "prefix " << n;
        }
    }
}

TEST(Nas, UnknownEpdIsUnsupported) {
    EXPECT_EQ(nas::decode(hex("07410000"), std::nullopt).error(),
              prahari::DecodeError::kUnsupported);  // EPS (4G) NAS
}

// Pinned against prahari_analytics.events.supi_hash in Python.
TEST(Supi, MatchesPythonImplementation) {
    const prahari::SupiHasher h{"prahari-test-key-0123456789abcdef"};
    EXPECT_EQ(h.hash("imsi-001010000000002"), "538769f54627ac41");
    EXPECT_EQ(h.hash("imsi-001010000000011"), "b4dd0f263567a5ef");
}

TEST(Supi, KeyFromEnvironmentMustBeLongEnough) {
    std::string err;
    EXPECT_FALSE(prahari::SupiHasher::from_env("PRAHARI_TEST_SURELY_UNSET_VAR", err));
    EXPECT_NE(err.find("not set"), std::string::npos);
}
