// SPDX-License-Identifier: MIT
// prahari-probe: passive 5G core signalling probe.
// Phase 0 ships the CLI shell and an offline PFCP header decoder; live capture
// (libpcap), NGAP/NAS/SBI decoding and Kafka export arrive in Phases 2-3.
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "prahari/pfcp.hpp"
#include "prahari/version.hpp"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitUsage = 64;    // EX_USAGE
constexpr int kExitDataErr = 65;  // EX_DATAERR

void print_usage(std::ostream& out) {
    out << "prahari-probe " << prahari::kVersion << "\n"
        << "Passive 5G core signalling probe (NGAP / NAS / PFCP / SBI).\n\n"
        << "Usage:\n"
        << "  prahari-probe --version\n"
        << "  prahari-probe --help\n"
        << "  prahari-probe decode-pfcp <hex>   Decode one PFCP header, print JSON\n";
}

std::optional<std::uint8_t> hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> parse_hex(std::string_view text) {
    std::vector<std::uint8_t> out;
    std::optional<std::uint8_t> high;
    for (const char c : text) {
        if (c == ' ' || c == ':') {
            continue;
        }
        const auto n = hex_nibble(c);
        if (!n) {
            return std::nullopt;
        }
        if (high) {
            out.push_back(static_cast<std::uint8_t>((*high << 4U) | *n));
            high.reset();
        } else {
            high = n;
        }
    }
    if (high) {
        return std::nullopt;  // odd number of digits
    }
    return out;
}

int decode_pfcp(std::string_view hex) {
    const auto bytes = parse_hex(hex);
    if (!bytes) {
        std::cerr << "error: input is not valid hex\n";
        return kExitUsage;
    }
    const auto result = prahari::pfcp::decode(std::span<const std::uint8_t>{*bytes});
    if (!result) {
        std::cout << R"({"ok":false,"error":")" << prahari::to_string(result.error()) << "\"}\n";
        return kExitDataErr;
    }
    const auto& h = result.value().header;
    std::cout << R"({"ok":true,"protocol":"pfcp","message_type":)" << unsigned{h.message_type}
              << R"(,"message":")" << prahari::pfcp::message_name(h.message_type) << '"'
              << R"(,"sequence":)" << h.sequence;
    if (h.seid) {
        std::cout << R"(,"seid":")" << *h.seid << '"';  // string: u64 exceeds JSON-safe ints
    }
    if (h.priority) {
        std::cout << R"(,"priority":)" << unsigned{*h.priority};
    }
    std::cout << R"(,"body_len":)" << result.value().body.size() << "}\n";
    return kExitOk;
}

int run(const std::vector<std::string_view>& args) {
    if (args.empty() || args[0] == "--help" || args[0] == "-h") {
        print_usage(std::cout);
        return args.empty() ? kExitUsage : kExitOk;
    }
    if (args[0] == "--version") {
        std::cout << "prahari-probe " << prahari::kVersion << '\n';
        return kExitOk;
    }
    if (args[0] == "decode-pfcp" && args.size() == 2) {
        return decode_pfcp(args[1]);
    }
    print_usage(std::cerr);
    return kExitUsage;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(std::vector<std::string_view>(argv + 1, argv + argc));
    } catch (const std::exception& e) {
        (void)std::fputs("fatal: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
    } catch (...) {
        (void)std::fputs("fatal: unknown exception\n", stderr);
    }
    return 70;  // EX_SOFTWARE
}
