// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <cstdio>
#include <regex>
#include <set>
#include <string>

#include "prahari/event.hpp"
#include "prahari/pipeline.hpp"

using prahari::append_json;
using prahari::append_json_string;
using prahari::Event;
using prahari::UuidGenerator;

TEST(Event, JsonStringEscaping) {
    std::string out;
    append_json_string("a\"b\\c\nd\x01", out);
    EXPECT_EQ(out, R"("a\"b\\c\nd\u0001")");
}

TEST(Event, UuidV4FormatAndUniqueness) {
    UuidGenerator g{42};
    const std::regex re{"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"};
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        const auto id = g.next();
        EXPECT_TRUE(std::regex_match(id, re)) << id;
        seen.insert(id);
    }
    EXPECT_EQ(seen.size(), 1000U);
}

TEST(Event, SeededGeneratorIsReproducible) {
    UuidGenerator a{7};
    UuidGenerator b{7};
    EXPECT_EQ(a.next(), b.next());
}

TEST(Event, LargeSeidIsAString) {
    Event e;
    e.event_id = "x";
    e.interface = "N4";
    e.protocol = "PFCP";
    e.message = "SessionDeletionRequest";
    e.ue_seid = 18446744073709551615ULL;  // 2^64 - 1
    std::string out;
    append_json(e, out);
    EXPECT_NE(out.find(R"("ue":{"seid":"18446744073709551615"})"), std::string::npos) << out;
}

TEST(NfMap, TestbedDefaultsAndUnknown) {
    const auto m = prahari::NfMap::testbed_default();
    EXPECT_EQ(m.lookup(prahari::net::IpAddress::v4_from(0xAC160005)), "AMF");
    EXPECT_EQ(m.lookup(prahari::net::IpAddress::v4_from(0xAC160008)), "UPF");
    EXPECT_EQ(m.lookup(prahari::net::IpAddress::v4_from(0x08080808)), "unknown");
}

TEST(NfMap, RejectsUnknownNfName) {
    auto m = prahari::NfMap::testbed_default();
    std::string err;
    EXPECT_FALSE(m.load_file("/nonexistent/nf-map.txt", err));
    EXPECT_NE(err.find("cannot read"), std::string::npos);
}

// A reader must never observe half an event: the sink writes whole lines only.
TEST(StreamSink, OnlyWholeLinesReachTheFile) {
    std::FILE* f = std::tmpfile();
    ASSERT_NE(f, nullptr);
    {
        prahari::StreamSink sink{f, 100};  // tiny batch to force many writes
        const std::string line(37, 'x');
        for (int i = 0; i < 50; ++i) {
            sink.write(line);
            // Whatever is in the file right now must end on a line boundary.
            const long size = std::ftell(f);
            if (size > 0) {
                std::rewind(f);
                std::string content(static_cast<std::size_t>(size), '\0');
                ASSERT_EQ(std::fread(content.data(), 1, content.size(), f), content.size());
                ASSERT_EQ(content.back(), '\n') << "partial line visible after write " << i;
                ASSERT_EQ(content.size() % (line.size() + 1), 0U);
                (void)std::fseek(f, 0, SEEK_END);
            }
        }
    }  // destructor flushes the rest
    EXPECT_EQ(std::ftell(f), 50L * 38L);
    (void)std::fclose(f);
}
