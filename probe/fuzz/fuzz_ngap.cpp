// SPDX-License-Identifier: MIT
// libFuzzer target: ngap::decode (APER, IE walk, UE-NGAP-ID pair, GlobalGnbId)
// must never crash, hang or read out of bounds on arbitrary bytes. Every NAS-PDU
// the decoder extracts is fed onward to nas::decode, the way the live probe does.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "prahari/nas.hpp"
#include "prahari/ngap.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto r = prahari::ngap::decode(std::span<const std::uint8_t>{data, size});
    if (!r.ok()) {
        return 0;
    }
    const auto& m = r.value();
    (void)prahari::ngap::message_name(m.procedure_code, m.pdu_type);
    for (const auto pdu : m.nas_pdus) {
        (void)prahari::nas::decode(pdu, std::nullopt);
        (void)prahari::nas::decode(pdu, std::uint8_t{0});  // NEA0: decode "ciphered" bodies
    }
    return 0;
}
