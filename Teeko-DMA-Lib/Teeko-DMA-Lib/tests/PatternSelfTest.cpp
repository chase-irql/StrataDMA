#include <cstdint>
#include <iostream>
#include <type_traits>
#include <vector>

#include "../Teeko-DMA/DMA.hpp"

auto main() -> int
{
    static_assert(std::is_same<DMA, _DMA>::value,
        "The legacy _DMA name must remain source-compatible");
    const std::vector<uint8_t> bytes = {
        0x48, 0x8B, 0x01, 0x90, 0x48, 0x8B, 0xFF, 0x90
    };

    const bool passed =
        DMA::IsSignatureValid("48 8B ? 90") &&
        DMA::IsSignatureValid("48 8B ?? 90") &&
        !DMA::IsSignatureValid("") &&
        !DMA::IsSignatureValid("48 ZZ") &&
        !DMA::IsSignatureValid("4") &&
        DMA::ScanBuffer(bytes, "48 8B ?? 90", 0x1000) == 0x1000 &&
        DMA::ScanBuffer(bytes, "AA BB", 0x1000) == 0 &&
        DMA::ScanBufferAll(bytes, "48 8B ? 90", 0x1000) ==
            std::vector<uint64_t>{ 0x1000, 0x1004 } &&
        DMA::ScanBufferAll(bytes, "48 8B ? 90", 0x1000, 1) ==
            std::vector<uint64_t>{ 0x1000 };

    std::cout << (passed ? "Pattern self-test passed.\n"
        : "Pattern self-test failed.\n");
    return passed ? 0 : 1;
}
