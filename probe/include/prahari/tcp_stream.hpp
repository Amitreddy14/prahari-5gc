// SPDX-License-Identifier: MIT
// One direction of a TCP connection, reassembled into an in-order byte stream.
//
// Passive reassembly with hard bounds: the probe must survive loss, reordering,
// retransmission and hostile traffic without unbounded memory.
//   - Decoding starts only at a SYN. A connection first seen mid-stream is never
//     synced: SBI uses HPACK, whose dynamic table cannot be rebuilt mid-connection.
//   - Retransmitted / overlapping bytes are trimmed and delivered once.
//   - Out-of-order segments wait in a bounded buffer. A gap that cannot be filled
//     within the bounds breaks the stream: delivering bytes across a hole would
//     desynchronise every layer above.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "prahari/net.hpp"

namespace prahari::tcp {

enum class StreamState : std::uint8_t {
    kUnsynced,  // no SYN seen: bytes are ignored
    kOpen,
    kClosed,  // FIN reached in order
    kBroken,  // unrecoverable gap or bounds exceeded
};

class HalfStream {
public:
    static constexpr std::size_t kMaxPendingBytes = std::size_t{256} * 1024;
    static constexpr std::size_t kMaxPendingSegments = 128;
    static constexpr std::uint64_t kMaxAhead = std::uint64_t{1} << 20;

    // Applies one segment. In-order bytes (including any pending segments they
    // unblock) are appended to `out`.
    void feed(std::uint32_t seq, std::uint8_t flags, std::span<const std::uint8_t> payload,
              std::vector<std::uint8_t>& out);

    [[nodiscard]] StreamState state() const noexcept { return state_; }
    [[nodiscard]] std::uint64_t delivered() const noexcept { return next_abs_; }
    [[nodiscard]] std::size_t pending_bytes() const noexcept { return pending_bytes_; }
    [[nodiscard]] std::uint64_t retransmitted_bytes() const noexcept { return retrans_; }

private:
    // Absolute stream offset of `seq`, relative to the next expected byte.
    [[nodiscard]] std::int64_t offset_of(std::uint32_t seq) const noexcept;
    void accept(std::int64_t rel, std::span<const std::uint8_t> data,
                std::vector<std::uint8_t>& out);
    void drain(std::vector<std::uint8_t>& out);

    StreamState state_{StreamState::kUnsynced};
    std::uint32_t next_seq_{};  // sequence number of the next in-order byte
    std::uint64_t next_abs_{};  // bytes delivered so far
    bool fin_pending_{};
    std::uint64_t fin_abs_{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> pending_;  // keyed by absolute offset
    std::size_t pending_bytes_{};
    std::uint64_t retrans_{};
};

struct SocketAddr {
    net::IpAddress ip;
    std::uint16_t port{};
    friend bool operator==(const SocketAddr&, const SocketAddr&) = default;
};

// Direction-independent key for one TCP connection.
struct FlowKey {
    SocketAddr lo;
    SocketAddr hi;
    [[nodiscard]] static FlowKey of(const SocketAddr& a, const SocketAddr& b) noexcept;
    friend bool operator==(const FlowKey&, const FlowKey&) = default;
};

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& k) const noexcept;
};

}  // namespace prahari::tcp
