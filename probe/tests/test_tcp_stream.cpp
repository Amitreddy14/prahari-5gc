// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "prahari/tcp_stream.hpp"

using prahari::tcp::HalfStream;
using prahari::tcp::StreamState;
namespace flag = prahari::net::tcp_flag;

namespace {

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

std::string str(const std::vector<std::uint8_t>& v) {
    return {v.begin(), v.end()};
}

struct Fixture {
    HalfStream h;
    std::vector<std::uint8_t> out;
    std::uint32_t isn{1000};
    void syn() { h.feed(isn, flag::kSyn, {}, out); }
    // Segment at stream offset `off` (0 = first byte after the SYN).
    void seg(std::uint32_t off, std::string_view data, std::uint8_t flags = flag::kAck) {
        const auto b = bytes(data);
        h.feed(isn + 1 + off, flags, b, out);
    }
};

}  // namespace

TEST(TcpStream, InOrderAfterSyn) {
    Fixture f;
    f.syn();
    f.seg(0, "hello ");
    f.seg(6, "world");
    EXPECT_EQ(str(f.out), "hello world");
    EXPECT_EQ(f.h.state(), StreamState::kOpen);
    EXPECT_EQ(f.h.delivered(), 11U);
}

TEST(TcpStream, MidstreamBytesAreIgnored) {
    Fixture f;
    f.seg(0, "no syn seen");
    EXPECT_TRUE(f.out.empty());
    EXPECT_EQ(f.h.state(), StreamState::kUnsynced);
}

TEST(TcpStream, OutOfOrderIsHeldThenDeliveredInOrder) {
    Fixture f;
    f.syn();
    f.seg(6, "world");
    EXPECT_TRUE(f.out.empty());
    EXPECT_EQ(f.h.pending_bytes(), 5U);
    f.seg(0, "hello ");
    EXPECT_EQ(str(f.out), "hello world");
    EXPECT_EQ(f.h.pending_bytes(), 0U);
}

TEST(TcpStream, RetransmissionsAndOverlapsAreDeliveredOnce) {
    Fixture f;
    f.syn();
    f.seg(0, "abcdef");
    f.seg(0, "abcdef");  // full retransmission
    f.seg(3, "defghi");  // overlaps 3 old bytes
    f.seg(9, "jk");
    f.seg(8, "ijk");  // overlap ending inside new data... all old here
    EXPECT_EQ(str(f.out), "abcdefghijk");
    EXPECT_GE(f.h.retransmitted_bytes(), 9U);
}

TEST(TcpStream, OverlappingPendingSegmentsMerge) {
    Fixture f;
    f.syn();
    f.seg(4, "efgh");
    f.seg(2, "cdef");  // overlaps the pending one
    f.seg(0, "ab");
    EXPECT_EQ(str(f.out), "abcdefgh");
}

TEST(TcpStream, SequenceNumbersWrapAround) {
    Fixture f;
    f.isn = 0xFFFFFFFAU;
    f.syn();
    f.seg(0, "0123456789");  // crosses 2^32
    f.seg(10, "abc");
    EXPECT_EQ(str(f.out), "0123456789abc");
}

TEST(TcpStream, GapTooFarAheadBreaksTheStream) {
    Fixture f;
    f.syn();
    f.seg(static_cast<std::uint32_t>(HalfStream::kMaxAhead) + 10, "x");
    EXPECT_EQ(f.h.state(), StreamState::kBroken);
    f.seg(0, "late");
    EXPECT_TRUE(f.out.empty());
}

TEST(TcpStream, TooManyPendingSegmentsBreaksTheStream) {
    Fixture f;
    f.syn();
    for (std::uint32_t i = 0; i <= HalfStream::kMaxPendingSegments; ++i) {
        f.seg(10 + i * 2, "x");  // every other byte: no segment is ever in order
    }
    EXPECT_EQ(f.h.state(), StreamState::kBroken);
    EXPECT_EQ(f.h.pending_bytes(), 0U);  // memory released
}

TEST(TcpStream, FinClosesOnlyOnceAllBytesArrived) {
    Fixture f;
    f.syn();
    f.seg(5, "world", flag::kAck | flag::kFin);
    EXPECT_EQ(f.h.state(), StreamState::kOpen);  // hole before the FIN
    f.seg(0, "hello");
    EXPECT_EQ(str(f.out), "helloworld");
    EXPECT_EQ(f.h.state(), StreamState::kClosed);
}

TEST(TcpStream, FlowKeyIgnoresDirection) {
    using prahari::tcp::FlowKey;
    using prahari::tcp::SocketAddr;
    const SocketAddr a{prahari::net::IpAddress::v4_from(0xAC160005), 40000};
    const SocketAddr b{prahari::net::IpAddress::v4_from(0xAC16000A), 7777};
    EXPECT_EQ(FlowKey::of(a, b), FlowKey::of(b, a));
    EXPECT_EQ(prahari::tcp::FlowKeyHash{}(FlowKey::of(a, b)),
              prahari::tcp::FlowKeyHash{}(FlowKey::of(b, a)));
}
