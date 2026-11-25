// SPDX-License-Identifier: MIT
#include "prahari/session_table.hpp"

#include <vector>

#include "prahari/pfcp.hpp"
#include "prahari/pfcp_ie.hpp"

namespace prahari::pfcp {

namespace {
constexpr std::uint64_t kSweepEvery = 4096;

// Which index the header SEID belongs to, by message type.
enum class HeaderRef : std::uint8_t { kNone, kCp, kUp };

HeaderRef header_ref(std::uint8_t type) noexcept {
    switch (static_cast<MessageType>(type)) {
        case MessageType::kSessionEstablishmentResponse:
        case MessageType::kSessionModificationResponse:
        case MessageType::kSessionDeletionResponse:
        case MessageType::kSessionReportRequest:         return HeaderRef::kCp;
        case MessageType::kSessionModificationRequest:
        case MessageType::kSessionDeletionRequest:
        case MessageType::kSessionReportResponse:        return HeaderRef::kUp;
        default:                                         return HeaderRef::kNone;
    }
}
}  // namespace

std::string_view to_string(SessionState s) noexcept {
    switch (s) {
        case SessionState::kEstablishing: return "establishing";
        case SessionState::kActive:       return "active";
        case SessionState::kDeleted:      return "deleted";
        case SessionState::kUnknown:      return "unknown";
    }
    return "unknown";
}

SessionView SessionTable::view(const Session& s, bool known) {
    return SessionView{s.cp_seid, s.up_seid, s.state, known};
}

void SessionTable::erase(std::uint64_t id) {
    const auto it = sessions_.find(id);
    if (it == sessions_.end()) {
        return;
    }
    const Session& s = it->second;
    by_cp_.erase(Key{s.cp_ip, s.cp_seid});
    if (s.up_seid) {
        by_up_.erase(Key{s.up_ip, *s.up_seid});
    }
    if (s.state == SessionState::kActive && active_ > 0) {
        --active_;
    }
    sessions_.erase(it);
}

void SessionTable::sweep(std::uint64_t now_ns) {
    std::vector<std::uint64_t> stale;
    for (const auto& [id, s] : sessions_) {
        if (s.state == SessionState::kEstablishing && now_ns > s.created_ns &&
            now_ns - s.created_ns > establish_timeout_ns_) {
            stale.push_back(id);
        }
    }
    for (const auto id : stale) {
        erase(id);
        ++expired_;
    }
}

SessionView SessionTable::apply(const SessionMessage& m) {
    if (++ops_ % kSweepEvery == 0) {
        sweep(m.ts_ns);
    }

    if (m.type == static_cast<std::uint8_t>(MessageType::kSessionEstablishmentRequest)) {
        if (!m.f_seid) {
            return SessionView{std::nullopt, std::nullopt, SessionState::kUnknown, false};
        }
        const Key key{m.src, *m.f_seid};
        if (const auto it = by_cp_.find(key); it != by_cp_.end()) {
            return view(sessions_.at(it->second), true);  // retransmission
        }
        if (sessions_.size() >= max_sessions_) {
            ++dropped_full_;
            return SessionView{m.f_seid, std::nullopt, SessionState::kUnknown, false};
        }
        const auto id = next_id_++;
        Session s;
        s.cp_ip = m.src;
        s.up_ip = m.dst;
        s.cp_seid = *m.f_seid;
        s.created_ns = m.ts_ns;
        sessions_.emplace(id, s);
        by_cp_.emplace(key, id);
        return view(s, true);
    }

    const auto ref = header_ref(m.type);
    if (ref == HeaderRef::kNone || !m.header_seid) {
        return SessionView{};
    }
    // The header SEID is the receiver's: look it up under the destination's address.
    const Key key{m.dst, *m.header_seid};
    auto& index = ref == HeaderRef::kCp ? by_cp_ : by_up_;
    const auto it = index.find(key);
    if (it == index.end()) {
        SessionView unknown;
        unknown.state = SessionState::kUnknown;
        unknown.known = false;
        if (ref == HeaderRef::kCp) {
            unknown.cp_seid = m.header_seid;
            unknown.up_seid = m.f_seid;
        } else {
            unknown.up_seid = m.header_seid;
        }
        return unknown;
    }
    const auto id = it->second;
    Session& s = sessions_.at(id);
    const bool accepted = m.cause && cause_accepted(*m.cause);

    switch (static_cast<MessageType>(m.type)) {
        case MessageType::kSessionEstablishmentResponse:
            if (accepted && m.f_seid && s.state == SessionState::kEstablishing) {
                s.up_seid = m.f_seid;
                s.state = SessionState::kActive;
                by_up_.emplace(Key{s.up_ip, *m.f_seid}, id);
                ++active_;
            } else if (!accepted) {
                const auto v = view(s, true);
                erase(id);  // rejected establishment never becomes a session
                return v;
            }
            break;
        case MessageType::kSessionDeletionResponse:
            if (accepted) {
                const bool was_active = s.state == SessionState::kActive;
                s.state = SessionState::kDeleted;
                auto v = view(s, true);
                erase(id);  // state is kDeleted now, so erase() does not touch active_
                if (was_active && active_ > 0) {
                    --active_;
                }
                return v;
            }
            break;
        default: break;
    }
    return view(s, true);
}

}  // namespace prahari::pfcp
