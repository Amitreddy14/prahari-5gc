// SPDX-License-Identifier: MIT
// HTTP/2 frames are built by hand; header blocks by nghttp2's HPACK *deflater*, so the
// decoder is tested against an independent encoder with real dynamic-table use.
#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "prahari/http2.hpp"
#include <nghttp2/nghttp2.h>

using prahari::http2::Connection;
using prahari::http2::Dir;
using prahari::http2::Message;

namespace {

using Bytes = std::vector<std::uint8_t>;
using Headers = std::vector<std::pair<std::string, std::string>>;

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

class Encoder {
public:
    Encoder() { EXPECT_EQ(nghttp2_hd_deflate_new(&d_, 4096), 0); }
    Encoder(const Encoder&) = delete;
    Encoder& operator=(const Encoder&) = delete;
    Encoder(Encoder&&) = delete;
    Encoder& operator=(Encoder&&) = delete;
    ~Encoder() { nghttp2_hd_deflate_del(d_); }
    Bytes block(const Headers& h) {
        std::vector<nghttp2_nv> nv;
        for (const auto& [k, v] : h) {
            nv.push_back(nghttp2_nv{const_cast<std::uint8_t*>(
                                        reinterpret_cast<const std::uint8_t*>(k.data())),  // NOLINT
                                    const_cast<std::uint8_t*>(
                                        reinterpret_cast<const std::uint8_t*>(v.data())),  // NOLINT
                                    k.size(), v.size(), NGHTTP2_NV_FLAG_NONE});
        }
        Bytes out(nghttp2_hd_deflate_bound(d_, nv.data(), nv.size()));
#if NGHTTP2_VERSION_NUM >= 0x013d00
        const auto n = nghttp2_hd_deflate_hd2(d_, out.data(), out.size(), nv.data(), nv.size());
#else
        const auto n = nghttp2_hd_deflate_hd(d_, out.data(), out.size(), nv.data(), nv.size());
#endif
        EXPECT_GE(n, 0);
        out.resize(static_cast<std::size_t>(n));
        return out;
    }

private:
    nghttp2_hd_deflater* d_{};
};

Bytes frame(std::uint8_t type, std::uint8_t flags, std::uint32_t sid, const Bytes& payload) {
    Bytes f{static_cast<std::uint8_t>(payload.size() >> 16U),
            static_cast<std::uint8_t>(payload.size() >> 8U),
            static_cast<std::uint8_t>(payload.size()),
            type,
            flags,
            static_cast<std::uint8_t>(sid >> 24U),
            static_cast<std::uint8_t>(sid >> 16U),
            static_cast<std::uint8_t>(sid >> 8U),
            static_cast<std::uint8_t>(sid)};
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

Bytes text(std::string_view s) {
    return {s.begin(), s.end()};
}

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

constexpr std::uint8_t kData = 0;
constexpr std::uint8_t kHeaders = 1;
constexpr std::uint8_t kRst = 3;
constexpr std::uint8_t kSettings = 4;
constexpr std::uint8_t kContinuation = 9;
constexpr std::uint8_t kEndStream = 0x1;
constexpr std::uint8_t kEndHeaders = 0x4;
constexpr std::uint8_t kPadded = 0x8;

struct Wire {
    Encoder client;
    Encoder server;
    Bytes c2s{text(kPreface)};
    Bytes s2c{frame(kSettings, 0, 0, {})};
    void request(std::uint32_t sid, const std::string& method, const std::string& path,
                 const std::string& body = {}) {
        const auto block = client.block({{":method", method},
                                         {":scheme", "http"},
                                         {":path", path},
                                         {":authority", "172.22.0.10:7777"},
                                         {"content-type", "application/json"}});
        const std::uint8_t f = kEndHeaders | (body.empty() ? kEndStream : 0);
        c2s = cat({c2s, frame(kHeaders, f, sid, block)});
        if (!body.empty()) {
            c2s = cat({c2s, frame(kData, kEndStream, sid, text(body))});
        }
    }
    void response(std::uint32_t sid, const std::string& status, const std::string& body = {}) {
        const auto block =
            server.block({{":status", status}, {"content-type", "application/json"}});
        const std::uint8_t f = kEndHeaders | (body.empty() ? kEndStream : 0);
        s2c = cat({s2c, frame(kHeaders, f, sid, block)});
        if (!body.empty()) {
            s2c = cat({s2c, frame(kData, kEndStream, sid, text(body))});
        }
    }
};

std::vector<Message> run(Connection& c, const Bytes& c2s, const Bytes& s2c) {
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, c2s, 1, out);
    c.feed(Dir::kServerToClient, s2c, 2, out);
    return out;
}

}  // namespace

TEST(Http2, RequestAndResponseWithBodies) {
    Wire w;
    w.request(1, "POST", "/nausf-auth/v1/ue-authentications", R"({"supiOrSuci":"suci-0"})");
    w.response(1, "201", R"({"authType":"5G_AKA"})");
    Connection c;
    const auto msgs = run(c, w.c2s, w.s2c);
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(msgs.size(), 2U);
    EXPECT_EQ(msgs[0].dir, Dir::kClientToServer);
    EXPECT_EQ(msgs[0].method, "POST");
    EXPECT_EQ(msgs[0].path, "/nausf-auth/v1/ue-authentications");
    EXPECT_EQ(msgs[0].body, R"({"supiOrSuci":"suci-0"})");
    EXPECT_EQ(msgs[0].content_type, "application/json");
    EXPECT_EQ(msgs[1].dir, Dir::kServerToClient);
    EXPECT_EQ(msgs[1].status, 201);
    EXPECT_EQ(msgs[1].stream_id, 1U);
    // Responses carry their request's context.
    EXPECT_EQ(msgs[1].method, "POST");
    EXPECT_EQ(msgs[1].path, "/nausf-auth/v1/ue-authentications");
    EXPECT_EQ(msgs[1].request_body, R"({"supiOrSuci":"suci-0"})");
    EXPECT_EQ(c.open_streams(), 0U);
}

TEST(Http2, DynamicTableAcrossManyRequests) {
    // Repeated headers are encoded as dynamic-table references after the first use.
    Wire w;
    for (std::uint32_t i = 0; i < 50; ++i) {
        const auto sid = 1 + 2 * i;
        w.request(sid, "PATCH", "/nnrf-nfm/v1/nf-instances/aaaa-" + std::to_string(i % 3));
        w.response(sid, "204");
    }
    Connection c;
    const auto msgs = run(c, w.c2s, w.s2c);
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(msgs.size(), 100U);  // 50 requests (fed first), then 50 responses
    EXPECT_EQ(msgs[49].path, "/nnrf-nfm/v1/nf-instances/aaaa-1");  // request 49
    EXPECT_EQ(msgs[99].path, "/nnrf-nfm/v1/nf-instances/aaaa-1");  // its response
    EXPECT_EQ(msgs[99].status, 204);
}

TEST(Http2, ByteAtATimeGivesTheSameResult) {
    Wire w;
    w.request(1, "GET", "/nudm-sdm/v2/imsi-001010000000001/am-data");
    w.response(1, "200", R"({"gpsis":[]})");
    Connection c;
    std::vector<Message> out;
    for (const auto b : w.c2s) {
        c.feed(Dir::kClientToServer, Bytes{b}, 1, out);
    }
    for (const auto b : w.s2c) {
        c.feed(Dir::kServerToClient, Bytes{b}, 2, out);
    }
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(out.size(), 2U);
    EXPECT_EQ(out[1].body, R"({"gpsis":[]})");
}

TEST(Http2, HeaderBlockSplitAcrossContinuation) {
    Encoder e;
    const auto block = e.block({{":method", "GET"}, {":path", "/nnrf-disc/v1/nf-instances"}});
    const Bytes first(block.begin(), block.begin() + 3);
    const Bytes rest(block.begin() + 3, block.end());
    const auto c2s = cat({text(kPreface), frame(kHeaders, kEndStream, 1, first),
                          frame(kContinuation, kEndHeaders, 1, rest)});
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, c2s, 1, out);
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].path, "/nnrf-disc/v1/nf-instances");
}

TEST(Http2, InterruptedHeaderBlockIsAProtocolError) {
    Encoder e;
    const auto block = e.block({{":method", "GET"}, {":path", "/x"}});
    const auto c2s =
        cat({text(kPreface), frame(kHeaders, 0, 1, block), frame(kData, kEndStream, 1, text("x"))});
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, c2s, 1, out);
    EXPECT_TRUE(c.broken());
    EXPECT_TRUE(out.empty());
}

TEST(Http2, PaddingIsStrippedAndValidated) {
    Encoder e;
    const auto block = e.block({{":method", "POST"}, {":path", "/x"}});
    Bytes padded_headers{2};
    padded_headers.insert(padded_headers.end(), block.begin(), block.end());
    padded_headers.insert(padded_headers.end(), {0, 0});
    const Bytes padded_data{3, 'a', 'b', 0, 0, 0};
    const auto c2s = cat({text(kPreface), frame(kHeaders, kEndHeaders | kPadded, 1, padded_headers),
                          frame(kData, kEndStream | kPadded, 1, padded_data)});
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, c2s, 1, out);
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].body, "ab");

    Connection bad;
    std::vector<Message> none;
    bad.feed(Dir::kClientToServer, cat({text(kPreface), frame(kData, kPadded, 1, Bytes{9, 'a'})}),
             1, none);
    EXPECT_TRUE(bad.broken());
}

TEST(Http2, MissingPrefaceIsRejected) {
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, text("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 1, out);
    EXPECT_TRUE(c.broken());
    EXPECT_EQ(c.error(), "no HTTP/2 connection preface");
}

TEST(Http2, OversizedFrameIsRejected) {
    const Bytes hdr{0x7F, 0xFF, 0xFF, kData, 0, 0, 0, 0, 1};
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, cat({text(kPreface), hdr}), 1, out);
    EXPECT_TRUE(c.broken());
}

TEST(Http2, GarbageHeaderBlockBreaksTheConnection) {
    // 0xFF... : indexed field with a huge index -> not in any table.
    const auto c2s = cat(
        {text(kPreface), frame(kHeaders, kEndHeaders | kEndStream, 1, Bytes{0xFF, 0xFF, 0x7F})});
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, c2s, 1, out);
    EXPECT_TRUE(c.broken());
    EXPECT_EQ(c.error(), "HPACK decode error");
}

TEST(Http2, InformationalResponsesAreSkipped) {
    Wire w;
    w.request(1, "POST", "/x", "{}");
    w.s2c = cat({w.s2c, frame(kHeaders, kEndHeaders, 1, w.server.block({{":status", "100"}}))});
    w.response(1, "200");
    Connection c;
    const auto msgs = run(c, w.c2s, w.s2c);
    ASSERT_EQ(msgs.size(), 2U);
    EXPECT_EQ(msgs[1].status, 200);
}

TEST(Http2, ResetStreamDropsItsResponse) {
    Wire w;
    w.request(1, "GET", "/x");
    w.s2c = cat({w.s2c, frame(kRst, 0, 1, Bytes{0, 0, 0, 8})});
    Connection c;
    const auto msgs = run(c, w.c2s, w.s2c);
    ASSERT_EQ(msgs.size(), 1U);  // the request only
    EXPECT_EQ(c.open_streams(), 0U);
}

TEST(Http2, BodyIsCappedButCounted) {
    Wire w;
    const std::string big(Connection::kMaxBody + 100, 'x');
    w.request(1, "PUT", "/x", big);
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, w.c2s, 1, out);
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].body.size(), Connection::kMaxBody);
    EXPECT_EQ(out[0].body_bytes, big.size());
    EXPECT_TRUE(out[0].body_truncated);
}

TEST(Http2, StreamTableIsBounded) {
    Wire w;
    for (std::uint32_t i = 0; i <= Connection::kMaxStreams; ++i) {
        w.request(1 + 2 * i, "GET", "/x");  // never answered
    }
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kClientToServer, w.c2s, 1, out);
    ASSERT_FALSE(c.broken());
    EXPECT_EQ(c.open_streams(), Connection::kMaxStreams);
    EXPECT_EQ(c.streams_dropped(), 1U);
}

TEST(Http2, TableSizeSettingAppliesToTheOtherDirection) {
    // Server allows the client's encoder a 64 KiB table; the client encoder then
    // signals that size. Without applying the setting the decoder would reject it.
    nghttp2_hd_deflater* d = nullptr;
    ASSERT_EQ(nghttp2_hd_deflate_new(&d, 65536), 0);
    ASSERT_EQ(nghttp2_hd_deflate_change_table_size(d, 65536), 0);
    std::string k = ":path";
    std::string v = "/big";
    nghttp2_nv nv{reinterpret_cast<std::uint8_t*>(k.data()),                      // NOLINT
                  reinterpret_cast<std::uint8_t*>(v.data()), k.size(), v.size(),  // NOLINT
                  NGHTTP2_NV_FLAG_NONE};
    Bytes block(nghttp2_hd_deflate_bound(d, &nv, 1));
#if NGHTTP2_VERSION_NUM >= 0x013d00
    const auto n = nghttp2_hd_deflate_hd2(d, block.data(), block.size(), &nv, 1);
#else
    const auto n = nghttp2_hd_deflate_hd(d, block.data(), block.size(), &nv, 1);
#endif
    nghttp2_hd_deflate_del(d);
    ASSERT_GT(n, 0);
    block.resize(static_cast<std::size_t>(n));

    const Bytes setting{0, 1, 0, 1, 0, 0};  // HEADER_TABLE_SIZE = 65536
    Connection c;
    std::vector<Message> out;
    c.feed(Dir::kServerToClient, frame(kSettings, 0, 0, setting), 1, out);
    c.feed(Dir::kClientToServer,
           cat({text(kPreface), frame(kHeaders, kEndHeaders | kEndStream, 1, block)}), 2, out);
    ASSERT_FALSE(c.broken()) << c.error();
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].path, "/big");
}
