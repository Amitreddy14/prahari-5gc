// SPDX-License-Identifier: MIT
// Bounds-checked, big-endian (network order) cursor over an immutable byte span.
// Every protocol decoder in the probe reads through this type, so an
// out-of-range read is impossible by construction: reads fail, they never overrun.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace prahari {

class ByteReader {
public:
    explicit ByteReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - pos_; }
    [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }

    [[nodiscard]] std::optional<std::uint8_t> u8() noexcept;
    [[nodiscard]] std::optional<std::uint16_t> u16() noexcept;
    [[nodiscard]] std::optional<std::uint32_t> u24() noexcept;
    [[nodiscard]] std::optional<std::uint32_t> u32() noexcept;
    [[nodiscard]] std::optional<std::uint64_t> u64() noexcept;

    // Returns a view of the next `n` bytes and advances, or nullopt if fewer remain.
    [[nodiscard]] std::optional<std::span<const std::uint8_t>> bytes(std::size_t n) noexcept;

    // Advances `n` bytes; false (and no movement) if fewer remain.
    [[nodiscard]] bool skip(std::size_t n) noexcept;

    // Peek without advancing.
    [[nodiscard]] std::optional<std::uint8_t> peek_u8() const noexcept;

    // A reader over the next `n` bytes that also advances this reader past them.
    // Used for length-prefixed sub-structures (TLV / IE bodies).
    [[nodiscard]] std::optional<ByteReader> sub(std::size_t n) noexcept;

private:
    [[nodiscard]] std::optional<std::uint64_t> read_be(std::size_t width) noexcept;

    std::span<const std::uint8_t> data_;
    std::size_t pos_{0};
};

}  // namespace prahari
