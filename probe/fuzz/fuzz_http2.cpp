// SPDX-License-Identifier: MIT
// libFuzzer target: http2::Connection (frames, padding, CONTINUATION, SETTINGS,
// HPACK via nghttp2) must never crash or grow without bound on arbitrary input.
// Input: a sequence of chunks, each "<header byte><data>", where the header's top
// bit picks the direction and its low 7 bits the chunk length.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "prahari/http2.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    prahari::http2::Connection c;
    std::vector<prahari::http2::Message> out;
    std::span<const std::uint8_t> in{data, size};
    std::uint64_t ts = 0;
    while (!in.empty() && !c.broken()) {
        const auto h = in[0];
        in = in.subspan(1);
        const std::size_t len = std::min<std::size_t>(h & 0x7FU, in.size());
        const auto dir = (h & 0x80U) != 0 ? prahari::http2::Dir::kServerToClient
                                          : prahari::http2::Dir::kClientToServer;
        c.feed(dir, in.subspan(0, len), ++ts, out);
        in = in.subspan(len);
        out.clear();
    }
    return 0;
}
