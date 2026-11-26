// SPDX-License-Identifier: MIT
// End-to-end over a real capture: Open5GS v2.7.7 + UERANSIM v3.2.8 testbed, N4 only.
// tests/data/n4-lifecycle.pcap: association, heartbeats and 3 full PDU sessions.
#include <gtest/gtest.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "prahari/pcap_source.hpp"
#include "prahari/pipeline.hpp"
#include "prahari/supi.hpp"

namespace {

const std::string kFixture = std::string{PRAHARI_TEST_DATA_DIR} + "/n4-lifecycle.pcap";

std::vector<std::string> run_fixture(prahari::Stats& stats) {
    auto opened = prahari::PcapSource::open_file(kFixture, "");
    EXPECT_TRUE(opened.source) << opened.error;
    prahari::VectorSink sink;
    if (!opened.source) {
        return {};
    }
    prahari::Pipeline p{prahari::NfMap::testbed_default(), sink, 1};
    prahari::Frame f;
    while (opened.source->next(f) == prahari::PcapSource::Next::kFrame) {
        p.on_frame(f.ts_ns, opened.source->link(), f.data);
    }
    stats = p.stats();
    EXPECT_EQ(p.sessions().size(), 0U);  // every session was deleted
    return sink.lines;
}

bool contains(const std::string& s, const std::string& needle) {
    return s.find(needle) != std::string::npos;
}

}  // namespace

TEST(PipelineCapture, EveryMessageBecomesOneEvent) {
    prahari::Stats st;
    const auto lines = run_fixture(st);
    EXPECT_EQ(st.frames, 24U);
    EXPECT_EQ(st.pfcp_messages, 24U);
    EXPECT_EQ(st.pfcp_decode_errors, 0U);
    EXPECT_EQ(st.pfcp_unknown_session, 0U);
    ASSERT_EQ(lines.size(), 24U);

    std::map<std::string, int> by_message;
    for (const auto& l : lines) {
        const auto start = l.find(R"("message":")") + 11;
        by_message[l.substr(start, l.find('"', start) - start)]++;
    }
    EXPECT_EQ(by_message["SessionEstablishmentRequest"], 3);
    EXPECT_EQ(by_message["SessionDeletionResponse"], 3);
    EXPECT_EQ(by_message["HeartbeatRequest"], 2);
}

TEST(PipelineCapture, SessionIdsResolvedAcrossTheLifecycle) {
    prahari::Stats st;
    const auto lines = run_fixture(st);
    // Session CP 0x75e (1886) <-> UP 0x91c (2332): the deletion request carries only
    // the UP SEID in its header, yet the event names both.
    bool deletion_seen = false;
    for (const auto& l : lines) {
        if (contains(l, R"("message":"SessionDeletionRequest")") &&
            contains(l, R"("up_seid":"2332")")) {
            deletion_seen = true;
            EXPECT_TRUE(contains(l, R"("cp_seid":"1886")")) << l;
            EXPECT_TRUE(contains(l, R"("session_known":true)")) << l;
            EXPECT_TRUE(contains(l, R"("src":{"ip":"172.22.0.7","port":8805,"nf":"SMF"})")) << l;
        }
    }
    EXPECT_TRUE(deletion_seen);
}

TEST(PipelineCapture, UserIdentityNeverAppearsInEvents) {
    prahari::Stats st;
    const auto lines = run_fixture(st);
    for (const auto& l : lines) {
        EXPECT_FALSE(contains(l, "imsi")) << l;
        EXPECT_FALSE(contains(l, "001010000")) << l;  // test-PLMN IMSI prefix
    }
}

// N2: NG Setup, one UE's registration (with a failed first authentication), PDU
// session setup, and a UE context release, from the live testbed.
TEST(PipelineCapture, N2RegistrationFixture) {
    const std::string fixture = std::string{PRAHARI_TEST_DATA_DIR} + "/n2-registration.pcap";
    auto opened = prahari::PcapSource::open_file(fixture, "");
    ASSERT_TRUE(opened.source) << opened.error;
    prahari::VectorSink sink;
    prahari::Pipeline p{prahari::NfMap::testbed_default(), sink, 1};
    p.set_supi_hasher(prahari::SupiHasher{"prahari-test-key-0123456789abcdef"});
    prahari::Frame f;
    while (opened.source->next(f) == prahari::PcapSource::Next::kFrame) {
        p.on_frame(f.ts_ns, opened.source->link(), f.data);
    }
    const auto& st = p.stats();
    EXPECT_EQ(st.ngap_messages, 23U);
    EXPECT_EQ(st.ngap_decode_errors, 0U);
    EXPECT_EQ(st.nas_decode_errors, 0U);
    EXPECT_EQ(st.nas_opaque, 0U);  // NEA0 learned from the Security Mode Command
    EXPECT_EQ(st.supi_hashed, 1U);

    int with_hash = 0;
    for (const auto& l : sink.lines) {
        EXPECT_FALSE(contains(l, "0000000008")) << "MSIN leaked (fixture UE): " << l;
        EXPECT_FALSE(contains(l, "imsi")) << l;
        if (contains(l, R"("ran_ue_ngap_id":1,)") &&
            contains(l, R"("supi_hash":"1d99cf0c73e73e98")")) {
            ++with_hash;
        }
    }
    // Every later message of UE 1 inherits the hash from its Registration Request.
    EXPECT_GE(with_hash, 10);
}

// SBI: the second registration wave of the same testbed (10 UEs deregister and
// register again) on HTTP/2 connections opened inside the capture, so HPACK state
// is complete. Pure-ACK segments were removed; everything else is untouched.
TEST(PipelineCapture, SbiRegistrationFixture) {
    auto opened = prahari::PcapSource::open_file(
        std::string{PRAHARI_TEST_DATA_DIR} + "/sbi-registration.pcap", "");
    ASSERT_TRUE(opened.source) << opened.error;
    prahari::VectorSink sink;
    prahari::Pipeline p{prahari::NfMap::testbed_default(), sink, 1};
    p.set_supi_hasher(prahari::SupiHasher{"prahari-test-key-0123456789abcdef"});
    prahari::Frame f;
    while (opened.source->next(f) == prahari::PcapSource::Next::kFrame) {
        p.on_frame(f.ts_ns, opened.source->link(), f.data);
    }
    const auto& st = p.stats();
    EXPECT_EQ(st.sbi_flows_opened, 11U);
    EXPECT_EQ(st.sbi_midstream_segments, 0U);
    EXPECT_EQ(st.sbi_tcp_gaps, 0U);
    EXPECT_EQ(st.sbi_http2_errors, 0U);
    EXPECT_EQ(st.sbi_requests, 320U);
    EXPECT_EQ(st.sbi_responses, 320U);
    ASSERT_EQ(sink.lines.size(), 640U);

    std::map<std::string, int> requests;
    std::set<std::string> hashes;
    for (const auto& l : sink.lines) {
        EXPECT_TRUE(contains(l, R"("decode_status":"ok")")) << l;
        // Every operation in the capture has a 3GPP name: no "METHOD service" fallbacks.
        EXPECT_FALSE(contains(l, R"( nn)")) << l;
        // No identity in any form: SUPI, null-scheme SUCI MSIN, or bare IMSI digits.
        EXPECT_FALSE(contains(l, "imsi-")) << l;
        EXPECT_FALSE(contains(l, "suci-")) << l;
        EXPECT_FALSE(contains(l, "001010000")) << l;
        if (contains(l, R"("direction":"request")")) {
            const auto start = l.find(R"("message":")") + 11;
            requests[l.substr(start, l.find('"', start) - start)]++;
        }
        const auto h = l.find(R"("supi_hash":")");
        if (h != std::string::npos) {
            hashes.insert(l.substr(h + 13, 16));
        }
    }
    EXPECT_EQ(requests["Authenticate"], 10);
    EXPECT_EQ(requests["CreateSMContext"], 10);
    EXPECT_EQ(requests["N1N2MessageTransfer"], 10);
    EXPECT_EQ(requests["ReleaseSMContext"], 10);
    EXPECT_EQ(hashes.size(), 10U);  // one pseudonym per UE
    // The fixture UE of n2-registration.pcap appears here under the same pseudonym.
    EXPECT_EQ(hashes.count("1d99cf0c73e73e98"), 1U);
}

// N4 now carries the pseudonym too, taken from the PFCP User ID IE at establishment
// and kept for the session's later messages.
TEST(PipelineCapture, N4SessionsCarryTheSupiPseudonym) {
    auto opened = prahari::PcapSource::open_file(kFixture, "");
    ASSERT_TRUE(opened.source) << opened.error;
    prahari::VectorSink sink;
    prahari::Pipeline p{prahari::NfMap::testbed_default(), sink, 1};
    p.set_supi_hasher(prahari::SupiHasher{"prahari-test-key-0123456789abcdef"});
    prahari::Frame f;
    while (opened.source->next(f) == prahari::PcapSource::Next::kFrame) {
        p.on_frame(f.ts_ns, opened.source->link(), f.data);
    }
    std::map<std::string, int> per_hash;
    for (const auto& l : sink.lines) {
        EXPECT_FALSE(contains(l, "001010000")) << l;
        const auto h = l.find(R"("supi_hash":")");
        if (h != std::string::npos) {
            per_hash[l.substr(h + 13, 16)]++;
        }
    }
    // IMSIs ...010, ...002, ...008 (read from the capture with tshark): six session
    // messages each (establishment, modification, deletion x request/response).
    ASSERT_EQ(per_hash.size(), 3U);
    EXPECT_EQ(per_hash["572654851848a73a"], 6);
    EXPECT_EQ(per_hash["538769f54627ac41"], 6);
    // ...008 is also the UE of n2-registration.pcap: same pseudonym on N2 and N4.
    EXPECT_EQ(per_hash["1d99cf0c73e73e98"], 6);
}
