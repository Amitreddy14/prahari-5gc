// SPDX-License-Identifier: MIT
// PFCP session table: links each session's CP SEID (allocated by the SMF) and UP SEID
// (allocated by the UPF) so every N4 message can be tied to its session.
//
// Observed on Open5GS (and per TS 29.244 7.2.2.4.2): a message's header SEID is the
// *receiver's* SEID.
//   50 Establishment Request   SMF->UPF  header 0,       F-SEID IE = CP SEID
//   51 Establishment Response  UPF->SMF  header CP SEID, F-SEID IE = UP SEID
//   52/54 Modify/Delete Req    SMF->UPF  header UP SEID
//   53/55 Modify/Delete Resp   UPF->SMF  header CP SEID
//   56 Report Request          UPF->SMF  header CP SEID
//   57 Report Response         SMF->UPF  header UP SEID
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "prahari/net.hpp"

namespace prahari::pfcp {

enum class SessionState : std::uint8_t { kEstablishing, kActive, kDeleted, kUnknown };

[[nodiscard]] std::string_view to_string(SessionState s) noexcept;

struct SessionView {
    std::optional<std::uint64_t> cp_seid;
    std::optional<std::uint64_t> up_seid;
    SessionState state{SessionState::kUnknown};
    // False when a message refers to a session the probe never saw being created.
    // For a probe started mid-stream that is expected; for a fresh network it is a signal.
    bool known{};
    // SUPI pseudonym recorded at establishment (from the User ID IE), if any.
    std::optional<std::string> supi_hash;
};

struct SessionMessage {
    std::uint8_t type{};
    net::IpAddress src;
    net::IpAddress dst;
    std::optional<std::uint64_t> header_seid;
    std::optional<std::uint64_t> f_seid;  // from the F-SEID IE, if present
    std::optional<std::uint8_t> cause;
    std::uint64_t ts_ns{};
    std::optional<std::string> supi_hash;  // Establishment Request only
};

class SessionTable {
public:
    explicit SessionTable(std::size_t max_sessions = 1'000'000,
                          std::uint64_t establish_timeout_ns = 30'000'000'000ULL)
        : max_sessions_(max_sessions), establish_timeout_ns_(establish_timeout_ns) {}

    // Applies one session-related message (types 50..57) and returns the resolved view.
    SessionView apply(const SessionMessage& m);

    [[nodiscard]] std::size_t size() const noexcept { return sessions_.size(); }
    [[nodiscard]] std::size_t active() const noexcept { return active_; }
    [[nodiscard]] std::uint64_t dropped_table_full() const noexcept { return dropped_full_; }
    [[nodiscard]] std::uint64_t expired_establishing() const noexcept { return expired_; }

private:
    struct Key {
        net::IpAddress ip;
        std::uint64_t seid{};
        friend bool operator==(const Key&, const Key&) = default;
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return net::IpAddressHash{}(k.ip) ^ (k.seid * 0x9E3779B97F4A7C15ULL);
        }
    };
    struct Session {
        net::IpAddress cp_ip;
        net::IpAddress up_ip;
        std::uint64_t cp_seid{};
        std::optional<std::uint64_t> up_seid;
        SessionState state{SessionState::kEstablishing};
        std::uint64_t created_ns{};
        std::optional<std::string> supi_hash;
    };

    [[nodiscard]] static SessionView view(const Session& s, bool known);
    void erase(std::uint64_t id);
    void sweep(std::uint64_t now_ns);

    std::size_t max_sessions_;
    std::uint64_t establish_timeout_ns_;
    std::uint64_t next_id_{1};
    std::unordered_map<std::uint64_t, Session> sessions_;
    std::unordered_map<Key, std::uint64_t, KeyHash> by_cp_;  // (SMF ip, CP SEID)
    std::unordered_map<Key, std::uint64_t, KeyHash> by_up_;  // (UPF ip, UP SEID)
    std::size_t active_{};
    std::uint64_t dropped_full_{};
    std::uint64_t expired_{};
    std::uint64_t ops_{};
};

}  // namespace prahari::pfcp
