// SPDX-License-Identifier: MIT
// PLMN identity and BCD digit helpers shared by NGAP and NAS (TS 24.501 9.11.3.4,
// TS 38.413 9.3.3.5): MCC/MNC in TBCD with 0xF filler for 2-digit MNCs.
#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace prahari {

// 3 octets -> "MCCMNC" digits, e.g. {0x00, 0xF1, 0x10} -> "00101". Invalid nibbles -> '?'.
[[nodiscard]] std::string decode_plmn(std::span<const std::uint8_t> three);

// Packed BCD, low nibble first, stopping at a 0xF filler: {0x00, 0x20} -> "0002".
[[nodiscard]] std::string decode_bcd(std::span<const std::uint8_t> bytes);

}  // namespace prahari
