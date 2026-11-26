// SPDX-License-Identifier: MIT
#include "prahari/http2.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include <nghttp2/nghttp2.h>

namespace prahari::http2 {
namespace {

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kFrameHeader = 9;

namespace type {
constexpr std::uint8_t kData = 0;
constexpr std::uint8_t kHeaders = 1;
constexpr std::uint8_t kPriority = 2;
constexpr std::uint8_t kRstStream = 3;
constexpr std::uint8_t kSettings = 4;
constexpr std::uint8_t kPushPromise = 5;
constexpr std::uint8_t kPing = 6;
constexpr std::uint8_t kGoaway = 7;
constexpr std::uint8_t kWindowUpdate = 8;
constexpr std::uint8_t kContinuation = 9;
}  // namespace type

namespace flag {
constexpr std::uint8_t kEndStream = 0x01;
constexpr std::uint8_t kAck = 0x01;
constexpr std::uint8_t kEndHeaders = 0x04;
constexpr std::uint8_t kPadded = 0x08;
constexpr std::uint8_t kPriority = 0x20;
}  // namespace flag

constexpr std::uint16_t kSettingsHeaderTableSize = 1;

std::uint32_t be24(std::span<const std::uint8_t> b) {
    return (std::uint32_t{b[0]} << 16U) | (std::uint32_t{b[1]} << 8U) | b[2];
}
std::uint32_t be32(std::span<const std::uint8_t> b) {
    return (std::uint32_t{b[0]} << 24U) | (std::uint32_t{b[1]} << 16U) |
           (std::uint32_t{b[2]} << 8U) | b[3];
}

// Removes the padding of a PADDED frame. False if the padding is impossible.
bool strip_padding(std::uint8_t flags, std::span<const std::uint8_t>& p) {
    if ((flags & flag::kPadded) == 0) {
        return true;
    }
    if (p.empty()) {
        return false;
    }
    const std::size_t pad = p[0];
    if (pad >= p.size()) {
        return false;
    }
    p = p.subspan(1, p.size() - 1 - pad);
    return true;
}

void delete_inflater(nghttp2_hd_inflater* p) {
    if (p != nullptr) {  // nghttp2_hd_inflate_del does not accept nullptr
        nghttp2_hd_inflate_del(p);
    }
}

nghttp2_hd_inflater* new_inflater() {
    nghttp2_hd_inflater* p = nullptr;
    if (nghttp2_hd_inflate_new(&p) != 0) {
        return nullptr;
    }
    return p;
}

int parse_status(std::string_view v) {
    if (v.size() != 3) {
        return 0;
    }
    int n = 0;
    for (const char c : v) {
        if (c < '0' || c > '9') {
            return 0;
        }
        n = n * 10 + (c - '0');
    }
    return n;
}

}  // namespace

Connection::Connection() {
    c2s_.preface_left = kPreface.size();
    c2s_.hpack = new_inflater();
    s2c_.hpack = new_inflater();
    if (c2s_.hpack == nullptr || s2c_.hpack == nullptr) {
        fail("HPACK inflater allocation failed");
    }
}

Connection::Connection(Connection&& other) noexcept
    : c2s_(std::move(other.c2s_)),
      s2c_(std::move(other.s2c_)),
      streams_(std::move(other.streams_)),
      error_(std::move(other.error_)),
      frames_(other.frames_),
      streams_dropped_(other.streams_dropped_) {
    other.c2s_.hpack = nullptr;
    other.s2c_.hpack = nullptr;
}

Connection& Connection::operator=(Connection&& other) noexcept {
    if (this != &other) {
        delete_inflater(c2s_.hpack);
        delete_inflater(s2c_.hpack);
        c2s_ = std::move(other.c2s_);
        s2c_ = std::move(other.s2c_);
        streams_ = std::move(other.streams_);
        error_ = std::move(other.error_);
        frames_ = other.frames_;
        streams_dropped_ = other.streams_dropped_;
        other.c2s_.hpack = nullptr;
        other.s2c_.hpack = nullptr;
    }
    return *this;
}

Connection::~Connection() {
    delete_inflater(c2s_.hpack);
    delete_inflater(s2c_.hpack);
}

Connection::HalfState& Connection::half(Dir d) noexcept {
    return d == Dir::kClientToServer ? c2s_ : s2c_;
}

void Connection::fail(std::string_view why) {
    if (error_.empty()) {
        error_ = why;
    }
    c2s_.buf.clear();
    s2c_.buf.clear();
    streams_.clear();
}

void Connection::feed(Dir dir, std::span<const std::uint8_t> bytes, std::uint64_t ts_ns,
                      std::vector<Message>& out) {
    if (broken()) {
        return;
    }
    auto& h = half(dir);
    h.buf.insert(h.buf.end(), bytes.begin(), bytes.end());

    if (h.preface_left > 0) {
        const auto have = std::min(h.preface_left, h.buf.size() - h.pos);
        const auto done = kPreface.size() - h.preface_left;
        for (std::size_t i = 0; i < have; ++i) {
            if (static_cast<char>(h.buf[h.pos + i]) != kPreface[done + i]) {
                fail("no HTTP/2 connection preface");
                return;
            }
        }
        h.pos += have;
        h.preface_left -= have;
    }

    while (!broken() && h.preface_left == 0 && h.buf.size() - h.pos >= kFrameHeader) {
        const std::span<const std::uint8_t> hdr{h.buf.data() + h.pos, kFrameHeader};
        const std::size_t len = be24(hdr);
        if (len > kMaxFrame) {
            fail("frame larger than limit");
            return;
        }
        if (h.buf.size() - h.pos < kFrameHeader + len) {
            break;  // wait for the rest of the frame
        }
        const auto ftype = hdr[3];
        const auto fflags = hdr[4];
        const auto sid = be32(hdr.subspan(5)) & 0x7FFFFFFFU;
        // Copy the payload: frame() may not grow h.buf, but keep the span independent.
        const std::span<const std::uint8_t> payload{h.buf.data() + h.pos + kFrameHeader, len};
        ++frames_;
        frame(dir, ftype, fflags, sid, payload, ts_ns, out);
        h.pos += kFrameHeader + len;
    }
    if (broken()) {
        return;
    }
    // Compact consumed bytes.
    if (h.pos > 0 && (h.pos == h.buf.size() || h.pos > std::size_t{64} * 1024)) {
        h.buf.erase(h.buf.begin(), h.buf.begin() + static_cast<std::ptrdiff_t>(h.pos));
        h.pos = 0;
    }
}

void Connection::frame(Dir dir, std::uint8_t ftype, std::uint8_t fflags, std::uint32_t sid,
                       std::span<const std::uint8_t> payload, std::uint64_t ts_ns,
                       std::vector<Message>& out) {
    auto& h = half(dir);
    if (h.block_active && ftype != type::kContinuation) {
        fail("header block interrupted");
        return;
    }
    switch (ftype) {
        case type::kHeaders:
        case type::kPushPromise: {
            if (sid == 0) {
                fail("HEADERS on stream 0");
                return;
            }
            const auto wire = payload.size();
            if (!strip_padding(fflags, payload)) {
                fail("bad padding");
                return;
            }
            if (ftype == type::kHeaders && (fflags & flag::kPriority) != 0) {
                if (payload.size() < 5) {
                    fail("truncated priority");
                    return;
                }
                payload = payload.subspan(5);
            }
            if (ftype == type::kPushPromise) {
                if (payload.size() < 4) {
                    fail("truncated PUSH_PROMISE");
                    return;
                }
                payload = payload.subspan(4);
            }
            h.block_active = true;
            h.block_stream = sid;
            h.block_is_push = ftype == type::kPushPromise;
            h.block_end_stream = ftype == type::kHeaders && (fflags & flag::kEndStream) != 0;
            h.block.assign(payload.begin(), payload.end());
            h.block_wire_bytes = kFrameHeader + wire;
            if ((fflags & flag::kEndHeaders) != 0) {
                header_block_done(dir, ts_ns, out);
            }
            return;
        }
        case type::kContinuation:
            if (!h.block_active || sid != h.block_stream) {
                fail("unexpected CONTINUATION");
                return;
            }
            if (h.block.size() + payload.size() > kMaxHeaderBlock) {
                fail("header block larger than limit");
                return;
            }
            h.block.insert(h.block.end(), payload.begin(), payload.end());
            h.block_wire_bytes += kFrameHeader + payload.size();
            if ((fflags & flag::kEndHeaders) != 0) {
                header_block_done(dir, ts_ns, out);
            }
            return;
        case type::kData: {
            if (sid == 0) {
                fail("DATA on stream 0");
                return;
            }
            if (!strip_padding(fflags, payload)) {
                fail("bad padding");
                return;
            }
            data(dir, sid, payload, (fflags & flag::kEndStream) != 0, out);
            return;
        }
        case type::kSettings:
            if ((fflags & flag::kAck) == 0) {
                if (payload.size() % 6 != 0) {
                    fail("bad SETTINGS length");
                    return;
                }
                settings(dir, payload);
            }
            return;
        case type::kRstStream:    streams_.erase(sid); return;
        case type::kPriority:
        case type::kPing:
        case type::kGoaway:
        case type::kWindowUpdate:
        default:                  return;  // no effect on message content; unknown types must be ignored
    }
}

void Connection::settings(Dir dir, std::span<const std::uint8_t> payload) {
    for (std::size_t i = 0; i + 6 <= payload.size(); i += 6) {
        const auto id = static_cast<std::uint16_t>((payload[i] << 8U) | payload[i + 1]);
        const auto value = be32(payload.subspan(i + 2, 4));
        if (id == kSettingsHeaderTableSize) {
            // A peer's limit bounds what the *other* side's encoder may use, so it
            // applies to the decoder of the opposite direction.
            auto& other =
                half(dir == Dir::kClientToServer ? Dir::kServerToClient : Dir::kClientToServer);
            if (nghttp2_hd_inflate_change_table_size(other.hpack, value) != 0) {
                fail("HPACK table size change rejected");
                return;
            }
        }
    }
}

Connection::Stream* Connection::stream_for(std::uint32_t sid, bool create) {
    const auto it = streams_.find(sid);
    if (it != streams_.end()) {
        return &it->second;
    }
    if (!create) {
        return nullptr;
    }
    if (streams_.size() >= kMaxStreams) {
        ++streams_dropped_;
        return nullptr;
    }
    return &streams_[sid];
}

void Connection::header_block_done(Dir dir, std::uint64_t ts_ns, std::vector<Message>& out) {
    auto& h = half(dir);
    h.block_active = false;
    const auto sid = h.block_stream;
    const bool is_push = h.block_is_push;
    const bool end_stream = h.block_end_stream;

    // Decode the whole block even if the stream is not tracked: HPACK state must advance.
    std::string method;
    std::string path;
    std::string status;
    std::string ctype;
    const std::uint8_t* in = h.block.data();
    std::size_t inlen = h.block.size();
    for (;;) {
        nghttp2_nv nv{};
        int iflags = 0;
#if NGHTTP2_VERSION_NUM >= 0x013d00
        const nghttp2_ssize rv = nghttp2_hd_inflate_hd3(h.hpack, &nv, &iflags, in, inlen, 1);
#else
        const ssize_t rv = nghttp2_hd_inflate_hd2(h.hpack, &nv, &iflags, in, inlen, 1);
#endif
        if (rv < 0) {
            fail("HPACK decode error");
            return;
        }
        const auto used = static_cast<std::size_t>(rv);
        in += used;
        inlen -= used;
        if ((iflags & NGHTTP2_HD_INFLATE_EMIT) != 0) {
            const std::string_view name{reinterpret_cast<const char*>(nv.name),  // NOLINT
                                        nv.namelen};
            const std::string_view value{reinterpret_cast<const char*>(nv.value),  // NOLINT
                                         nv.valuelen};
            if (name == ":method") {
                method.assign(value.substr(0, 16));
            } else if (name == ":path") {
                path.assign(value.substr(0, kMaxPathBytes));
            } else if (name == ":status") {
                status.assign(value.substr(0, 3));
            } else if (name == "content-type") {
                ctype.assign(value.substr(0, 128));
            }
        }
        if ((iflags & NGHTTP2_HD_INFLATE_FINAL) != 0) {
            nghttp2_hd_inflate_end_headers(h.hpack);
            break;
        }
        if (inlen == 0 && (iflags & NGHTTP2_HD_INFLATE_EMIT) == 0) {
            fail("HPACK block incomplete");
            return;
        }
    }
    if (is_push) {
        return;  // decoded to keep HPACK in sync; SBI does not use server push
    }

    if (dir == Dir::kClientToServer) {
        auto* s = stream_for(sid, true);
        if (s == nullptr) {
            return;
        }
        if (!s->req_headers_seen) {
            s->req_headers_seen = true;
            s->req.dir = dir;
            s->req.stream_id = sid;
            s->req.ts_ns = ts_ns;
            s->req.method = std::move(method);
            s->req.path = std::move(path);
            s->req.content_type = std::move(ctype);
        }  // else: trailers
        s->req.header_bytes += h.block_wire_bytes;
    } else {
        const int code = parse_status(status);
        auto* s = stream_for(sid, true);
        if (s == nullptr) {
            return;
        }
        if (code >= 100 && code < 200) {
            return;  // informational; the final response follows
        }
        if (!s->resp_headers_seen) {
            s->resp_headers_seen = true;
            s->resp.dir = dir;
            s->resp.stream_id = sid;
            s->resp.ts_ns = ts_ns;
            s->resp.status = code;
            s->resp.content_type = std::move(ctype);
        }
        s->resp.header_bytes += h.block_wire_bytes;
    }
    if (end_stream) {
        end_of_stream(dir, sid, out);
    }
}

void Connection::data(Dir dir, std::uint32_t sid, std::span<const std::uint8_t> payload,
                      bool end_stream, std::vector<Message>& out) {
    auto* s = stream_for(sid, false);
    if (s == nullptr) {
        return;
    }
    auto& m = dir == Dir::kClientToServer ? s->req : s->resp;
    m.body_bytes += payload.size();
    const auto room = kMaxBody - std::min(kMaxBody, m.body.size());
    const auto take = std::min(room, payload.size());
    m.body.append(reinterpret_cast<const char*>(payload.data()), take);  // NOLINT
    if (take < payload.size()) {
        m.body_truncated = true;
    }
    if (end_stream) {
        end_of_stream(dir, sid, out);
    }
}

void Connection::end_of_stream(Dir dir, std::uint32_t sid, std::vector<Message>& out) {
    const auto it = streams_.find(sid);
    if (it == streams_.end()) {
        return;
    }
    auto& s = it->second;
    if (dir == Dir::kClientToServer) {
        if (s.req_headers_seen && !s.req_done) {
            s.req_done = true;
            out.push_back(s.req);  // keep a copy for the response
        }
        return;
    }
    if (s.resp_headers_seen) {
        Message m = std::move(s.resp);
        m.method = std::move(s.req.method);
        m.path = std::move(s.req.path);
        m.request_body = std::move(s.req.body);
        out.push_back(std::move(m));
    }
    streams_.erase(it);
}

std::string_view frame_type_name(std::uint8_t t) noexcept {
    static constexpr std::array<std::string_view, 10> kNames{
        "DATA",         "HEADERS", "PRIORITY", "RST_STREAM",    "SETTINGS",
        "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION"};
    return t < kNames.size() ? kNames.at(t) : std::string_view{"UNKNOWN"};
}

}  // namespace prahari::http2
