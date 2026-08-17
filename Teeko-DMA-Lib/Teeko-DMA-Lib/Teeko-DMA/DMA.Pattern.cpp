#include "DMA.hpp"

#include <cctype>
#include <cstdlib>

namespace {
bool IsHexDigit(char value)
{
    return std::isxdigit(static_cast<unsigned char>(value)) != 0;
}
}

bool DMA::ParseSignature(const std::string& signature,
    std::vector<PatternByte>& pattern) {
    pattern.clear();
    size_t position = 0;

    while (position < signature.size()) {
        while (position < signature.size() &&
            std::isspace(static_cast<unsigned char>(signature[position]))) {
            ++position;
        }
        if (position == signature.size())
            break;

        const size_t tokenStart = position;
        while (position < signature.size() &&
            !std::isspace(static_cast<unsigned char>(signature[position]))) {
            ++position;
        }
        const std::string token = signature.substr(tokenStart, position - tokenStart);
        if (token == "?" || token == "??") {
            pattern.push_back({ 0, true });
            continue;
        }
        if (token.size() != 2 || !IsHexDigit(token[0]) || !IsHexDigit(token[1])) {
            pattern.clear();
            return false;
        }
        pattern.push_back({
            static_cast<uint8_t>(std::strtoul(token.c_str(), nullptr, 16)), false });
    }

    return !pattern.empty();
}

std::vector<DMA::PatternByte> DMA::ParseSignature(const std::string& signature)
{
    std::vector<PatternByte> pattern;
    ParseSignature(signature, pattern);
    return pattern;
}

uint64_t DMA::ScanLocalBuffer(const std::vector<uint8_t>& buffer,
    uint64_t baseAddress,
    const std::vector<DMA::PatternByte>& pattern) {
    if (pattern.empty() || buffer.size() < pattern.size())
        return 0;
    for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].ignore && buffer[i + j] != pattern[j].value) {
                found = false;
                break;
            }
        }
        if (found)
            return baseAddress + i;
    }
    return 0;
}

std::vector<uint64_t> DMA::ScanAllLocalBuffer(
    const std::vector<uint8_t>& buffer,
    uint64_t baseAddress,
    const std::vector<DMA::PatternByte>& pattern,
    size_t maxResults)
{
    std::vector<uint64_t> results;
    if (pattern.empty() || buffer.size() < pattern.size())
        return results;

    for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i)
    {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j)
        {
            if (!pattern[j].ignore && buffer[i + j] != pattern[j].value)
            {
                found = false;
                break;
            }
        }
        if (found) {
            results.push_back(baseAddress + i);
            if (maxResults != 0 && results.size() >= maxResults)
                break;
        }
    }
    return results;
}

bool DMA::IsSignatureValid(const std::string& signature)
{
    std::vector<PatternByte> pattern;
    return ParseSignature(signature, pattern);
}

uint64_t DMA::ScanBuffer(const std::vector<uint8_t>& buffer,
    const std::string& signature, uint64_t baseAddress)
{
    std::vector<PatternByte> pattern;
    if (!ParseSignature(signature, pattern))
        return 0;
    return ScanLocalBuffer(buffer, baseAddress, pattern);
}

std::vector<uint64_t> DMA::ScanBufferAll(const std::vector<uint8_t>& buffer,
    const std::string& signature, uint64_t baseAddress, size_t maxResults)
{
    std::vector<PatternByte> pattern;
    if (!ParseSignature(signature, pattern))
        return {};
    return ScanAllLocalBuffer(buffer, baseAddress, pattern, maxResults);
}
