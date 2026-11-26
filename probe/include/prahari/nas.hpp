// SPDX-License-Identifier: MIT
// 5G NAS (TS 24.501) decoding for messages carried in NGAP NAS-PDU IEs.
//
//   5GMM: EPD 0x7E | security header type (low nibble) | ...
//     plain (SHT 0):      message type, IEs
//     protected (SHT 1-4): MAC(4) | SQN(1) | inner plain 5GMM message
//       SHT 1/3: integrity only -> inner is readable
//       SHT 2/4: integrity + ciphering -> readable only if the UE's selected
//                ciphering algorithm is NEA0 (null), learned from Security Mode Command
//   5GSM: EPD 0x2E | PDU session ID | PTI | message type | IEs
//
// Privacy: a SUCI with the null protection scheme exposes the IMSI. The decoder
// returns it in `supi` ONLY so the caller can hash it immediately; it must never
// be written anywhere (enforced by tests on the event output).
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "prahari/result.hpp"

namespace prahari::nas {

inline constexpr std::uint8_t kEpd5gmm = 0x7E;
inline constexpr std::uint8_t kEpd5gsm = 0x2E;
inline constexpr std::uint8_t kNea0 = 0;

enum class Identity : std::uint8_t {
    kNone = 0,
    kSuci = 1,
    kGuti = 2,
    kImei = 3,
    kSTmsi = 4,
    kImeisv = 5,
    kOther = 7,
};

[[nodiscard]] std::string_view to_string(Identity i) noexcept;

struct Info {
    bool is_5gsm{};                  // EPD of the (outer) message
    std::uint8_t security_header{};  // 0..4 (5GMM only)
    bool integrity_protected{};
    bool ciphered{};
    bool decoded{};               // false: ciphered with a non-null or unknown algorithm
    std::uint8_t message_type{};  // of the innermost readable 5GMM/5GSM message
    std::string_view message;     // name, or "Protected" if not decoded

    std::optional<std::uint8_t> registration_type;  // 1 initial .. 4 emergency
    std::optional<Identity> identity;
    std::optional<bool> suci_null_scheme;
    std::optional<std::string> supi;  // "imsi-<digits>": hash, never emit
    std::optional<std::uint8_t> pdu_session_id;
    std::optional<std::uint8_t> sm_message_type;  // 5GSM inside UL/DL NAS Transport
    std::string_view sm_message;
    std::optional<std::uint8_t> selected_ciphering;  // from Security Mode Command
    std::optional<std::uint8_t> selected_integrity;
    std::optional<std::uint8_t> mm_cause;
};

// `cipher_alg`: the UE's selected NAS ciphering algorithm if known (from an earlier
// Security Mode Command). Ciphered messages are decoded only when it is NEA0.
[[nodiscard]] Result<Info> decode(std::span<const std::uint8_t> pdu,
                                  std::optional<std::uint8_t> cipher_alg);

[[nodiscard]] std::string_view mm_message_name(std::uint8_t type) noexcept;
[[nodiscard]] std::string_view sm_message_name(std::uint8_t type) noexcept;

}  // namespace prahari::nas
