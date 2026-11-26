// SPDX-License-Identifier: MIT
// libFuzzer target: SBI path sanitisation, operation naming and body scanning.
// Also checks the privacy invariant: a sanitised path never contains "imsi-"/"suci-".
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "prahari/sbi.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view s{reinterpret_cast<const char*>(data), size};  // NOLINT
    const auto t = prahari::sbi::parse_target(s);
    if (t.path.size() > prahari::sbi::kMaxPath) {
        std::abort();
    }
    // A segment that *starts* with an identity prefix must have been replaced.
    for (const auto bad : {std::string_view{"/imsi-"}, std::string_view{"/suci-"}}) {
        if (t.path.find(bad) != std::string::npos) {
            std::abort();
        }
    }
    (void)prahari::sbi::operation_name("GET", t);
    (void)prahari::sbi::operation_name(s.substr(0, 8), t);
    (void)prahari::sbi::find_imsi(s);
    (void)prahari::sbi::find_pdu_session_id(s);
    (void)prahari::sbi::find_problem_cause(s);
    (void)prahari::sbi::imsi_from_identity(s);
    return 0;
}
