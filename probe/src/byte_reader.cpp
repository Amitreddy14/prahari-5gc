// SPDX-License-Identifier: MIT
#include "prahari/byte_reader.hpp"

namespace prahari {

std::optional<std::uint64_t> ByteReader::read_be(std::size_t width) noexcept {
    if (remaining() < width) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value = (value << 8U) | data_[pos_ + i];
    }
    pos_ += width;
    return value;
}

std::optional<std::uint8_t> ByteReader::u8() noexcept {
    const auto v = read_be(1);
    if (!v) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(*v);
}

std::optional<std::uint16_t> ByteReader::u16() noexcept {
    const auto v = read_be(2);
    if (!v) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(*v);
}

std::optional<std::uint32_t> ByteReader::u24() noexcept {
    const auto v = read_be(3);
    if (!v) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(*v);
}

std::optional<std::uint32_t> ByteReader::u32() noexcept {
    const auto v = read_be(4);
    if (!v) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(*v);
}

std::optional<std::uint64_t> ByteReader::u64() noexcept {
    return read_be(8);
}

std::optional<std::span<const std::uint8_t>> ByteReader::bytes(std::size_t n) noexcept {
    if (remaining() < n) {
        return std::nullopt;
    }
    auto view = data_.subspan(pos_, n);
    pos_ += n;
    return view;
}

bool ByteReader::skip(std::size_t n) noexcept {
    if (remaining() < n) {
        return false;
    }
    pos_ += n;
    return true;
}

std::optional<std::uint8_t> ByteReader::peek_u8() const noexcept {
    if (empty()) {
        return std::nullopt;
    }
    return data_[pos_];
}

std::optional<ByteReader> ByteReader::sub(std::size_t n) noexcept {
    auto view = bytes(n);
    if (!view) {
        return std::nullopt;
    }
    return ByteReader{*view};
}

}  // namespace prahari
