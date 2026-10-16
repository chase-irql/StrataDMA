#pragma once
#include "DMA.Types.hpp"

namespace StrataDetail {
inline std::unordered_map<DWORD, std::pair<uint64_t, uint64_t>> HeapSegmentTotals(
    const VMMDLL_MAP_HEAP_SEGMENTENTRY* segments, DWORD count)
{
    std::unordered_map<DWORD, std::pair<uint64_t, uint64_t>> totals;
    for (DWORD i = 0; i < count; ++i) {
        auto& total = totals[segments[i].iHeap];
        ++total.first;
        total.second += segments[i].cb;
    }
    return totals;
}
}
