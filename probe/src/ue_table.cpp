// SPDX-License-Identifier: MIT
#include "prahari/ue_table.hpp"

#include <iterator>

namespace prahari::ngap {

namespace {
constexpr std::uint64_t kSweepEvery = 4096;
}  // namespace

UeContext* UeTable::touch(const net::IpAddress& gnb, std::uint32_t ran_ue_ngap_id,
                          std::uint64_t now_ns) {
    if (++ops_ % kSweepEvery == 0) {
        sweep(now_ns);
    }
    const Key key{gnb, ran_ue_ngap_id};
    auto it = map_.find(key);
    if (it == map_.end()) {
        if (map_.size() >= max_) {
            ++dropped_full_;
            return nullptr;
        }
        it = map_.emplace(key, UeContext{}).first;
    }
    it->second.last_seen_ns = now_ns;
    return &it->second;
}

void UeTable::release(const net::IpAddress& gnb, std::uint32_t ran_ue_ngap_id) {
    map_.erase(Key{gnb, ran_ue_ngap_id});
}

void UeTable::sweep(std::uint64_t now_ns) {
    for (auto it = map_.begin(); it != map_.end();) {
        if (now_ns > it->second.last_seen_ns &&
            now_ns - it->second.last_seen_ns > idle_timeout_ns_) {
            it = map_.erase(it);
            ++expired_;
        } else {
            it = std::next(it);
        }
    }
}

}  // namespace prahari::ngap
