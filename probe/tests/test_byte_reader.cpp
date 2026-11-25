// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include "prahari/byte_reader.hpp"

using prahari::ByteReader;

TEST(ByteReader, ReadsBigEndianIntegers) {
    constexpr std::array<std::uint8_t, 18> kData{0x01,                    // u8
                                                 0x02, 0x03,              // u16
                                                 0x04, 0x05, 0x06,        // u24
                                                 0x07, 0x08, 0x09, 0x0a,  // u32
                                                 0x0b, 0x0c, 0x0d, 0x0e,
                                                 0x0f, 0x10, 0x11, 0x12};  // u64
    ByteReader r{kData};

    EXPECT_EQ(r.u8(), 0x01U);
    EXPECT_EQ(r.u16(), 0x0203U);
    EXPECT_EQ(r.u24(), 0x040506U);
    EXPECT_EQ(r.u32(), 0x0708090aU);
    EXPECT_EQ(r.u64(), 0x0b0c0d0e0f101112ULL);
    EXPECT_TRUE(r.empty());
}

TEST(ByteReader, FailedReadDoesNotAdvance) {
    constexpr std::array<std::uint8_t, 3> kData{0xaa, 0xbb, 0xcc};
    ByteReader r{kData};

    EXPECT_FALSE(r.u32().has_value());
    EXPECT_EQ(r.position(), 0U);
    EXPECT_FALSE(r.skip(4));
    EXPECT_EQ(r.position(), 0U);
    EXPECT_EQ(r.u24(), 0xaabbccU);
    EXPECT_FALSE(r.u8().has_value());
    EXPECT_FALSE(r.peek_u8().has_value());
}

TEST(ByteReader, EmptyInputIsSafe) {
    ByteReader r{std::span<const std::uint8_t>{}};
    EXPECT_TRUE(r.empty());
    EXPECT_FALSE(r.u8().has_value());
    EXPECT_FALSE(r.bytes(1).has_value());
    EXPECT_TRUE(r.bytes(0).has_value());
}

TEST(ByteReader, SubReaderIsBoundedAndAdvancesParent) {
    constexpr std::array<std::uint8_t, 5> kData{0x00, 0x02, 0xde, 0xad, 0xff};
    ByteReader r{kData};

    const auto len = r.u16();
    ASSERT_TRUE(len.has_value());
    auto body = r.sub(*len);
    ASSERT_TRUE(body.has_value());
    EXPECT_EQ(body->u16(), 0xdeadU);
    EXPECT_FALSE(body->u8().has_value());  // cannot read past its own window
    EXPECT_EQ(r.u8(), 0xffU);              // parent moved past the sub-window
}

TEST(ByteReader, SubReaderRejectsOverlongLength) {
    constexpr std::array<std::uint8_t, 3> kData{0x00, 0x10, 0x01};
    ByteReader r{kData};
    const auto len = r.u16();
    ASSERT_TRUE(len.has_value());
    EXPECT_FALSE(r.sub(*len).has_value());
    EXPECT_EQ(r.remaining(), 1U);
}
