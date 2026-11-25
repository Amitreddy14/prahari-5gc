// SPDX-License-Identifier: MIT
// Minimal Result<T> for decoders. Decoders never throw on malformed input:
// attacker-controlled bytes are an expected condition, not an exceptional one.
#pragma once

#include <cstdint>
#include <string_view>
#include <utility>
#include <variant>

namespace prahari {

enum class DecodeError : std::uint8_t {
    kTruncated,    // fewer bytes than the structure requires
    kBadVersion,   // protocol version field not supported
    kBadLength,    // declared length disagrees with available bytes
    kUnsupported,  // valid but not handled by this decoder yet
    kMalformed,    // violates the protocol specification
};

[[nodiscard]] constexpr std::string_view to_string(DecodeError e) noexcept {
    switch (e) {
        case DecodeError::kTruncated:   return "truncated";
        case DecodeError::kBadVersion:  return "bad_version";
        case DecodeError::kBadLength:   return "bad_length";
        case DecodeError::kUnsupported: return "unsupported";
        case DecodeError::kMalformed:   return "malformed";
    }
    return "unknown";
}

template <typename T>
class [[nodiscard]] Result {
public:
    // Implicit by design so decoders can `return value;` or `return DecodeError::k...;`.
    Result(T value) : data_(std::move(value)) {}  // NOLINT(google-explicit-constructor)
    Result(DecodeError error) : data_(error) {}   // NOLINT(google-explicit-constructor)

    [[nodiscard]] bool ok() const noexcept { return std::holds_alternative<T>(data_); }
    explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] const T& value() const& { return std::get<T>(data_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(data_)); }
    [[nodiscard]] DecodeError error() const { return std::get<DecodeError>(data_); }

private:
    std::variant<T, DecodeError> data_;
};

}  // namespace prahari
