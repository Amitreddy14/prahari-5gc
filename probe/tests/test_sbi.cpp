// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <string>

#include "prahari/sbi.hpp"

using namespace prahari::sbi;  // NOLINT(google-build-using-namespace)

TEST(Sbi, SupiInPathIsReplacedAndReturned) {
    const auto t = parse_target("/nudm-sdm/v2/imsi-001010000000008/am-data?plmn-id=%7B%7D");
    EXPECT_EQ(t.path, "/nudm-sdm/v2/{supi}/am-data");
    EXPECT_EQ(t.service, "nudm-sdm");
    ASSERT_TRUE(t.imsi);
    EXPECT_EQ(*t.imsi, "001010000000008");
    EXPECT_TRUE(t.had_identity);
}

TEST(Sbi, NullSchemeSuciResolvesToImsi) {
    const auto t = parse_target(
        "/nudm-ueau/v1/suci-0-001-01-0000-0-0-0000000008/security-information/"
        "generate-auth-data");
    EXPECT_EQ(t.path, "/nudm-ueau/v1/{suci}/security-information/generate-auth-data");
    ASSERT_TRUE(t.imsi);
    EXPECT_EQ(*t.imsi, "001010000000008");
}

TEST(Sbi, ProtectedSuciIsReplacedButNotResolved) {
    const auto t = parse_target("/nudm-ueau/v1/suci-0-001-01-0000-1-1-4f2a9c/x");
    EXPECT_EQ(t.path, "/nudm-ueau/v1/{suci}/x");
    EXPECT_FALSE(t.imsi);
    EXPECT_TRUE(t.had_identity);
}

TEST(Sbi, ThreeDigitMncSuci) {
    EXPECT_EQ(imsi_from_identity("suci-0-404-123-0-0-0-456789012").value_or("none"),
              "404123456789012");
    // MCC + MNC + MSIN longer than 15 digits is not an IMSI.
    EXPECT_FALSE(imsi_from_identity("suci-0-404-123-0-0-0-4567890123"));
    // Non-IMSI SUPI type (1 = NAI) is never resolved.
    EXPECT_FALSE(imsi_from_identity("suci-1-001-01-0000-0-0-0000000001"));
}

TEST(Sbi, OtherIdentitiesAreReplaced) {
    EXPECT_EQ(parse_target("/nudm-sdm/v2/msisdn-919876543210/am-data").path,
              "/nudm-sdm/v2/{gpsi}/am-data");
    EXPECT_EQ(parse_target("/nudm-sdm/v2/nai-user@example.org/am-data").path,
              "/nudm-sdm/v2/{nai}/am-data");
    EXPECT_EQ(parse_target("/nudm-sdm/v2/extid-a@b/am-data").path, "/nudm-sdm/v2/{gpsi}/am-data");
}

TEST(Sbi, MalformedImsiSegmentIsStillReplaced) {
    const auto t = parse_target("/nudr-dr/v1/subscription-data/imsi-12ab/am-data");
    EXPECT_EQ(t.path, "/nudr-dr/v1/subscription-data/{supi}/am-data");
    EXPECT_FALSE(t.imsi);
}

TEST(Sbi, NonSbiPathHasNoService) {
    EXPECT_EQ(parse_target("/").service, "");
    EXPECT_EQ(parse_target("/index.html").service, "");
    EXPECT_EQ(parse_target("/NUDM/v1/x").service, "");
    EXPECT_EQ(parse_target("").path, "");
}

TEST(Sbi, LongPathsAreTruncatedAtASegment) {
    std::string p = "/nnrf-nfm/v1";
    while (p.size() < 400) {
        p += "/abcdefghij";
    }
    const auto t = parse_target(p);
    EXPECT_LE(t.path.size(), kMaxPath);
    EXPECT_NE(t.path.back(), '/');
}

TEST(Sbi, OperationNames) {
    const auto op = [](std::string_view m, std::string_view p) {
        return operation_name(m, parse_target(p));
    };
    EXPECT_EQ(op("GET", "/nnrf-disc/v1/nf-instances?target-nf-type=AUSF"), "NFDiscover");
    EXPECT_EQ(op("PATCH", "/nnrf-nfm/v1/nf-instances/6a1b"), "NFUpdate");
    EXPECT_EQ(op("PUT", "/nnrf-nfm/v1/nf-instances/6a1b"), "NFRegister");
    EXPECT_EQ(op("POST", "/nausf-auth/v1/ue-authentications"), "Authenticate");
    EXPECT_EQ(op("PUT", "/nausf-auth/v1/ue-authentications/3/5g-aka-confirmation"),
              "AuthenticateConfirm");
    EXPECT_EQ(op("POST", "/nsmf-pdusession/v1/sm-contexts/7/modify"), "UpdateSMContext");
    EXPECT_EQ(op("POST", "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"),
              "N1N2MessageTransfer");
    EXPECT_EQ(op("GET", "/nudm-sdm/v2/imsi-001010000000001/sm-data"), "GetSmData");
    EXPECT_EQ(op("GET", "/nudr-dr/v1/policy-data/ues/imsi-001010000000001/am-data"), "DRQuery");
    EXPECT_EQ(op("OPTIONS", "/nudm-sdm/v2/x"), "OPTIONS nudm-sdm");
    EXPECT_EQ(op("GET", "/metrics"), "GET non-sbi");
    EXPECT_EQ(op("", "/x"), "UNKNOWN non-sbi");
}

TEST(Sbi, FindsImsiInJsonAndMultipartBodies) {
    EXPECT_EQ(find_imsi(R"({"supi":"imsi-001010000000003","pei":"imeisv-1"})").value_or(""),
              "001010000000003");
    EXPECT_EQ(find_imsi(R"({"supiOrSuci":"suci-0-001-01-0000-0-0-0000000004"})").value_or(""),
              "001010000000004");
    const std::string multipart =
        "--b\r\nContent-Type: application/json\r\n\r\n{\"ueId\":\"imsi-001010000000005\"}\r\n"
        "--b\r\nContent-Type: application/vnd.3gpp.ngap\r\n\r\n\x00\x0e\r\n--b--";
    EXPECT_EQ(find_imsi(multipart).value_or(""), "001010000000005");
    EXPECT_FALSE(find_imsi(R"({"supi":"imsi-12"})"));             // too short
    EXPECT_FALSE(find_imsi(R"({"x":"imsi-1234567890123456"})"));  // too long
    EXPECT_FALSE(find_imsi("no identities here"));
    // The first *valid* identity wins.
    EXPECT_EQ(find_imsi(R"(imsi-1 then imsi-001010000000006)").value_or(""), "001010000000006");
}

TEST(Sbi, FindsPduSessionId) {
    EXPECT_EQ(find_pdu_session_id(R"({"pduSessionId": 5,"dnn":"internet"})").value_or(0), 5);
    EXPECT_EQ(find_pdu_session_id(R"({"pduSessionId":255})").value_or(0), 255);
    EXPECT_FALSE(find_pdu_session_id(R"({"pduSessionId":256})"));
    EXPECT_FALSE(find_pdu_session_id(R"({"pduSessionId":"5"})"));
    EXPECT_FALSE(find_pdu_session_id(R"({"other":1})"));
}

TEST(Sbi, FindsProblemDetailsCause) {
    EXPECT_EQ(find_problem_cause(R"({"status":404,"cause":"USER_NOT_FOUND"})").value_or(""),
              "USER_NOT_FOUND");
    EXPECT_FALSE(find_problem_cause(R"({"cause":"lower case is not a cause code"})"));
    EXPECT_FALSE(find_problem_cause(R"({"cause":5})"));
    EXPECT_FALSE(find_problem_cause(R"({"cause":"UNTERMINATED)"));
}
