// SPDX-License-Identifier: MIT
// Passive HTTP/2 (RFC 9113) decoder for cleartext SBI (h2c with prior knowledge),
// fed with the two reassembled byte streams of one TCP connection.
//
// Frames are parsed here; header blocks are decompressed with nghttp2's HPACK
// inflater (RFC 7541), one per direction, because HPACK state is per connection
// and per direction. Any framing or HPACK error marks the connection broken: past
// that point the header tables are out of sync and nothing can be trusted.
//
// Output is one Message per completed request or response (END_STREAM).
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

struct nghttp2_hd_inflater;

namespace prahari::http2 {

enum class Dir : std::uint8_t { kClientToServer = 0, kServerToClient = 1 };

struct Message {
    Dir dir{Dir::kClientToServer};
    std::uint32_t stream_id{};
    std::uint64_t ts_ns{};  // first HEADERS frame of this message
    // Requests: method + path (raw, may contain identities: sanitise before output).
    // Responses carry their request's method, path and body too, so the response
    // event can be correlated without a second lookup.
    std::string method;
    std::string path;
    std::string request_body;  // responses only
    // Responses: final status (1xx informational responses are skipped).
    int status{};
    std::string content_type;
    std::string body;  // first kMaxBody bytes only
    std::size_t header_bytes{};
    std::size_t body_bytes{};
    bool body_truncated{};
};

class Connection {
public:
    static constexpr std::size_t kMaxFrame = std::size_t{1} << 20;
    static constexpr std::size_t kMaxHeaderBlock = std::size_t{64} * 1024;
    static constexpr std::size_t kMaxBody = std::size_t{16} * 1024;
    static constexpr std::size_t kMaxStreams = 1024;
    static constexpr std::size_t kMaxPathBytes = 2048;

    Connection();
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;
    ~Connection();

    // Feeds in-order bytes of one direction. Completed messages are appended to `out`.
    void feed(Dir dir, std::span<const std::uint8_t> bytes, std::uint64_t ts_ns,
              std::vector<Message>& out);

    [[nodiscard]] bool broken() const noexcept { return !error_.empty(); }
    [[nodiscard]] std::string_view error() const noexcept { return error_; }
    [[nodiscard]] std::uint64_t frames() const noexcept { return frames_; }
    [[nodiscard]] std::size_t open_streams() const noexcept { return streams_.size(); }
    [[nodiscard]] std::uint64_t streams_dropped() const noexcept { return streams_dropped_; }

private:
    struct HalfState {
        std::vector<std::uint8_t> buf;
        std::size_t pos{};
        std::size_t preface_left{};
        nghttp2_hd_inflater* hpack{};
        // Header block in progress (HEADERS / PUSH_PROMISE + CONTINUATION).
        std::uint32_t block_stream{};
        bool block_active{};
        bool block_end_stream{};
        bool block_is_push{};
        std::vector<std::uint8_t> block;
        std::size_t block_wire_bytes{};
    };
    struct Stream {
        Message req;
        Message resp;
        bool req_headers_seen{};
        bool resp_headers_seen{};
        bool req_done{};
    };

    void fail(std::string_view why);
    void frame(Dir dir, std::uint8_t type, std::uint8_t flags, std::uint32_t sid,
               std::span<const std::uint8_t> payload, std::uint64_t ts_ns,
               std::vector<Message>& out);
    void header_block_done(Dir dir, std::uint64_t ts_ns, std::vector<Message>& out);
    void data(Dir dir, std::uint32_t sid, std::span<const std::uint8_t> payload, bool end_stream,
              std::vector<Message>& out);
    void settings(Dir dir, std::span<const std::uint8_t> payload);
    void end_of_stream(Dir dir, std::uint32_t sid, std::vector<Message>& out);
    [[nodiscard]] Stream* stream_for(std::uint32_t sid, bool create);
    [[nodiscard]] HalfState& half(Dir d) noexcept;

    HalfState c2s_;
    HalfState s2c_;
    std::unordered_map<std::uint32_t, Stream> streams_;
    std::string error_;
    std::uint64_t frames_{};
    std::uint64_t streams_dropped_{};
};

[[nodiscard]] std::string_view frame_type_name(std::uint8_t type) noexcept;

}  // namespace prahari::http2
