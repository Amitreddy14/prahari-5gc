// SPDX-License-Identifier: MIT
#include "prahari/tcp_stream.hpp"

#include <algorithm>
#include <tuple>

namespace prahari::tcp {

std::int64_t HalfStream::offset_of(std::uint32_t seq) const noexcept {
    // Serial-number arithmetic (RFC 1982): signed distance from the next expected byte.
    return static_cast<std::int32_t>(seq - next_seq_);
}

void HalfStream::feed(std::uint32_t seq, std::uint8_t flags, std::span<const std::uint8_t> payload,
                      std::vector<std::uint8_t>& out) {
    if (state_ == StreamState::kBroken || state_ == StreamState::kClosed) {
        return;
    }
    if ((flags & net::tcp_flag::kSyn) != 0) {
        if (state_ == StreamState::kUnsynced) {
            state_ = StreamState::kOpen;
            next_seq_ = seq + 1;  // SYN consumes one sequence number
            next_abs_ = 0;
        }
        ++seq;
    }
    if (state_ == StreamState::kUnsynced) {
        return;
    }
    const auto rel = offset_of(seq);
    // Absolute offset just past this segment, fixed before accept() moves next_abs_.
    const auto end_abs =
        static_cast<std::int64_t>(next_abs_) + rel + static_cast<std::int64_t>(payload.size());
    if (!payload.empty()) {
        accept(rel, payload, out);
    }
    if ((flags & net::tcp_flag::kFin) != 0 && state_ == StreamState::kOpen && end_abs >= 0) {
        fin_pending_ = true;
        fin_abs_ = static_cast<std::uint64_t>(end_abs);
    }
    if (fin_pending_ && state_ == StreamState::kOpen && next_abs_ >= fin_abs_) {
        state_ = StreamState::kClosed;
    }
}

void HalfStream::accept(std::int64_t rel, std::span<const std::uint8_t> data,
                        std::vector<std::uint8_t>& out) {
    const auto len = static_cast<std::int64_t>(data.size());
    if (rel < 0) {
        if (-rel >= len) {
            retrans_ += data.size();
            return;  // entirely old
        }
        retrans_ += static_cast<std::uint64_t>(-rel);
        data = data.subspan(static_cast<std::size_t>(-rel));
        rel = 0;
    }
    if (rel == 0) {
        out.insert(out.end(), data.begin(), data.end());
        next_abs_ += data.size();
        next_seq_ += static_cast<std::uint32_t>(data.size());
        drain(out);
        return;
    }
    // Ahead of the next expected byte: hold it, within bounds.
    const auto ahead = static_cast<std::uint64_t>(rel);
    if (ahead > kMaxAhead || pending_.size() >= kMaxPendingSegments ||
        pending_bytes_ + data.size() > kMaxPendingBytes) {
        state_ = StreamState::kBroken;
        pending_.clear();
        pending_bytes_ = 0;
        return;
    }
    const auto abs = next_abs_ + ahead;
    auto [it, inserted] = pending_.try_emplace(abs);
    if (inserted || it->second.size() < data.size()) {
        pending_bytes_ -= it->second.size();
        it->second.assign(data.begin(), data.end());
        pending_bytes_ += data.size();
    } else {
        retrans_ += data.size();
    }
}

void HalfStream::drain(std::vector<std::uint8_t>& out) {
    while (!pending_.empty()) {
        auto it = pending_.begin();
        if (it->first > next_abs_) {
            return;  // still a hole
        }
        const auto skip = next_abs_ - it->first;
        auto& seg = it->second;
        if (skip < seg.size()) {
            const auto first = seg.begin() + static_cast<std::ptrdiff_t>(skip);
            out.insert(out.end(), first, seg.end());
            const auto n = seg.size() - static_cast<std::size_t>(skip);
            next_abs_ += n;
            next_seq_ += static_cast<std::uint32_t>(n);
        }
        retrans_ += std::min<std::uint64_t>(skip, seg.size());
        pending_bytes_ -= seg.size();
        pending_.erase(it);
    }
}

FlowKey FlowKey::of(const SocketAddr& a, const SocketAddr& b) noexcept {
    const auto key_a = std::tie(a.ip.v6, a.ip.bytes, a.port);
    const auto key_b = std::tie(b.ip.v6, b.ip.bytes, b.port);
    return key_a < key_b ? FlowKey{a, b} : FlowKey{b, a};
}

std::size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    const net::IpAddressHash h;
    std::size_t x = h(k.lo.ip);
    x = x * 0x9E3779B97F4A7C15ULL ^ h(k.hi.ip);
    x = x * 0x9E3779B97F4A7C15ULL ^ (std::size_t{k.lo.port} << 16U | k.hi.port);
    return x;
}

}  // namespace prahari::tcp
