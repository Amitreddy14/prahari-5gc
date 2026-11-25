// SPDX-License-Identifier: MIT
// End-to-end over a real capture: Open5GS v2.7.7 + UERANSIM v3.2.8 testbed, N4 only.
// tests/data/n4-lifecycle.pcap: association, heartbeats and 3 full PDU sessions.
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "prahari/pcap_source.hpp"
#include "prahari/pipeline.hpp"

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
