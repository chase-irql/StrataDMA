#include "DMA.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <future>
#include <limits>
#include <sstream>

namespace {
int HexValue(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

bool MatchesAt(const std::vector<uint8_t>& buffer, size_t offset,
    const DMACompiledPattern& pattern)
{
    for (size_t index = 0; index < pattern.bytes.size(); ++index) {
        const auto& byte = pattern.bytes[index];
        if ((buffer[offset + index] & byte.mask) != (byte.value & byte.mask))
            return false;
    }
    return true;
}

std::vector<size_t> ScanOffsets(const std::vector<uint8_t>& buffer,
    const DMACompiledPattern& pattern, size_t begin, size_t end, size_t alignment,
    uint64_t baseAddress)
{
    std::vector<size_t> offsets;
    if (pattern.bytes.empty() || buffer.size() < pattern.bytes.size())
        return offsets;
    const size_t last = std::min(end, buffer.size() - pattern.bytes.size() + 1);
    for (size_t offset = begin; offset < last; ++offset) {
        if (alignment > 1 && (baseAddress + offset) % alignment != 0)
            continue;
        if (MatchesAt(buffer, offset, pattern))
            offsets.push_back(offset);
    }
    return offsets;
}

uint64_t ReadUnsigned(const uint8_t* data, size_t size)
{
    uint64_t value = 0;
    std::memcpy(&value, data, std::min(size, sizeof(value)));
    return value;
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
}

DMAResult<DMACompiledPattern> DMA::CompilePattern(
    const std::string& signature, const std::vector<DMAScanCapture>& captures)
{
    DMAResult<DMACompiledPattern> result;
    std::istringstream stream(signature);
    std::string token;
    while (stream >> token) {
        if (token.size() == 1 && token[0] == '?')
            token = "??";
        if (token.size() != 2) {
            result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
                "Pattern tokens must be two hexadecimal/wildcard nibbles.");
            return result;
        }
        DMACompiledPatternByte byte;
        for (size_t nibble = 0; nibble < 2; ++nibble) {
            if (token[nibble] == '?')
                continue;
            const int value = HexValue(token[nibble]);
            if (value < 0) {
                result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
                    "Pattern contains a non-hexadecimal token.");
                result.value.bytes.clear();
                return result;
            }
            const unsigned shift = nibble == 0 ? 4 : 0;
            byte.value |= static_cast<uint8_t>(value << shift);
            byte.mask |= static_cast<uint8_t>(0x0f << shift);
        }
        result.value.bytes.push_back(byte);
    }
    if (result.value.bytes.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
            "Pattern cannot be empty.");
        return result;
    }
    for (const auto& capture : captures) {
        size_t required = capture.size;
        if (required == 0) {
            switch (capture.kind) {
            case DMAScanCaptureKind::Rel8: required = 1; break;
            case DMAScanCaptureKind::Rel32:
            case DMAScanCaptureKind::UInt32: required = 4; break;
            case DMAScanCaptureKind::UInt16: required = 2; break;
            case DMAScanCaptureKind::UInt64: required = 8; break;
            case DMAScanCaptureKind::Bytes: break;
            }
        }
        if (required == 0 || capture.offset > result.value.bytes.size() ||
            required > result.value.bytes.size() - capture.offset) {
            result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
                "A pattern capture lies outside the compiled pattern.");
            result.value.bytes.clear();
            return result;
        }
        auto normalized = capture;
        normalized.size = required;
        result.value.captures.push_back(std::move(normalized));
    }
    result.operation = DMAOperationResult::Success(result.value.bytes.size());
    return result;
}

DMAResult<std::vector<DMAScanMatch>> DMA::ScanBufferAdvanced(
    const std::vector<uint8_t>& buffer, const DMACompiledPattern& pattern,
    uint64_t baseAddress, const DMAScanOptions& options)
{
    DMAResult<std::vector<DMAScanMatch>> result;
    if (!pattern.IsValid() || options.alignment == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A valid pattern and non-zero alignment are required.");
        return result;
    }
    std::vector<size_t> offsets;
    const size_t candidates = buffer.size() >= pattern.bytes.size()
        ? buffer.size() - pattern.bytes.size() + 1 : 0;
    const unsigned workers = options.parallel && candidates >= 1024 * 1024
        ? std::max(1u, std::thread::hardware_concurrency()) : 1u;
    if (workers == 1) {
        offsets = ScanOffsets(buffer, pattern, 0, candidates, options.alignment,
            baseAddress);
    }
    else {
        std::vector<std::future<std::vector<size_t>>> jobs;
        const size_t chunk = (candidates + workers - 1) / workers;
        for (unsigned worker = 0; worker < workers; ++worker) {
            const size_t begin = std::min(candidates, chunk * worker);
            const size_t end = std::min(candidates, begin + chunk);
            if (begin == end)
                continue;
            jobs.push_back(std::async(std::launch::async,
                [&buffer, &pattern, begin, end, &options, baseAddress] {
                    return ScanOffsets(buffer, pattern, begin, end,
                        options.alignment, baseAddress);
                }));
        }
        for (auto& job : jobs) {
            auto part = job.get();
            offsets.insert(offsets.end(), part.begin(), part.end());
        }
        std::sort(offsets.begin(), offsets.end());
    }

    if (options.nthMatch != 0) {
        if (options.nthMatch > offsets.size())
            offsets.clear();
        else
            offsets = { offsets[options.nthMatch - 1] };
    }
    if (options.maxResults != 0 && offsets.size() > options.maxResults)
        offsets.resize(options.maxResults);

    for (const size_t offset : offsets) {
        DMAScanMatch match;
        match.address = baseAddress + offset;
        for (const auto& capture : pattern.captures) {
            const uint8_t* data = buffer.data() + offset + capture.offset;
            if (capture.kind == DMAScanCaptureKind::Bytes) {
                match.byteCaptures[capture.name] =
                    std::vector<uint8_t>(data, data + capture.size);
                continue;
            }
            uint64_t value = ReadUnsigned(data, capture.size);
            bool relative = false;
            if (capture.kind == DMAScanCaptureKind::Rel8) {
                const auto displacement = static_cast<int8_t>(value);
                value = static_cast<uint64_t>(static_cast<int64_t>(
                    match.address + capture.offset + 1) + displacement);
                relative = true;
            }
            else if (capture.kind == DMAScanCaptureKind::Rel32) {
                int32_t displacement = 0;
                std::memcpy(&displacement, data, sizeof(displacement));
                value = static_cast<uint64_t>(static_cast<int64_t>(
                    match.address + capture.offset + 4) + displacement);
                relative = true;
            }
            match.numericCaptures[capture.name] = value;
            if (relative && options.transformFromFirstRelativeCapture &&
                match.transformedAddress == 0) {
                match.transformedAddress = value;
            }
        }
        result.value.push_back(std::move(match));
    }
    result.operation = DMAOperationResult::Success(buffer.size());
    return result;
}

DMAResult<std::vector<DMAScanMatch>> DMA::ScanModuleAdvanced(
    const std::string& moduleName, const DMACompiledPattern& pattern,
    const DMAScanOptions& options,
    const std::vector<std::string>& sectionNames)
{
    DMAResult<std::vector<DMAScanMatch>> result;
    const uint64_t base = GetModuleBase(moduleName);
    const uint32_t size = GetModuleSize(moduleName);
    if (base == 0 || size == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested module was not found.");
        return result;
    }
    if (sectionNames.empty()) {
        auto bytes = DumpMemory(base, size);
        if (bytes.empty()) {
            result.operation = DMAOperationResult::Failure(DMAStatus::BackendError,
                "Unable to read the module image.");
            return result;
        }
        return ScanBufferAdvanced(bytes, pattern, base, options);
    }

    auto sections = GetModuleSections(moduleName);
    if (!sections)
        return { sections.operation, {} };
    std::vector<std::string> requested;
    for (const auto& name : sectionNames)
        requested.push_back(Lower(name));
    DMAScanOptions sectionOptions = options;
    sectionOptions.nthMatch = 0;
    sectionOptions.maxResults = 0;
    for (const auto& section : sections.value) {
        if (std::find(requested.begin(), requested.end(), Lower(section.name)) ==
            requested.end()) {
            continue;
        }
        const size_t sectionSize = section.virtualSize != 0
            ? section.virtualSize : section.rawSize;
        auto bytes = DumpMemory(section.address, sectionSize);
        if (bytes.empty())
            continue;
        auto matches = ScanBufferAdvanced(bytes, pattern, section.address,
            sectionOptions);
        if (!matches) {
            result.operation = matches.operation;
            return result;
        }
        result.value.insert(result.value.end(), matches.value.begin(),
            matches.value.end());
    }
    std::sort(result.value.begin(), result.value.end(),
        [](const auto& left, const auto& right) { return left.address < right.address; });
    if (options.nthMatch != 0) {
        if (options.nthMatch <= result.value.size())
            result.value = { result.value[options.nthMatch - 1] };
        else
            result.value.clear();
    }
    if (options.maxResults != 0 && result.value.size() > options.maxResults)
        result.value.resize(options.maxResults);
    result.operation = DMAOperationResult::Success();
    return result;
}


DMAResult<DMAStringSearchResult> DMA::ExtractStrings(
    const std::vector<uint8_t>& buffer, const DMAStringSearchOptions& options,
    uint64_t baseAddress, bool finalChunk)
{
    DMAResult<DMAStringSearchResult> result;
    if ((options.encoding != DMAStringEncoding::ASCII && options.encoding != DMAStringEncoding::UTF16LE) ||
        options.minimumLength == 0 || options.maximumLength < options.minimumLength ||
        options.maximumLength > 4096 || options.maximumResults == 0 || options.maximumResults > 4096 ||
        options.contains.size() > 256 || (!buffer.empty() && buffer.size() - 1 > UINT64_MAX - baseAddress)) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Invalid string encoding, lengths, filter, result limit or address range.");
        return result;
    }
    const bool wide = options.encoding == DMAStringEncoding::UTF16LE;
    const size_t width = wide ? 2 : 1;
    const auto folded = [](std::string value) {
        for (auto& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return value;
    };
    const auto filter = options.caseSensitive ? options.contains : folded(options.contains);
    const auto utf8 = [](uint32_t code) {
        std::string text;
        if (code < 0x80) text += static_cast<char>(code);
        else if (code < 0x800) { text += static_cast<char>(0xc0 | (code >> 6)); text += static_cast<char>(0x80 | (code & 63)); }
        else if (code < 0x10000) { text += static_cast<char>(0xe0 | (code >> 12)); text += static_cast<char>(0x80 | ((code >> 6) & 63)); text += static_cast<char>(0x80 | (code & 63)); }
        else { text += static_cast<char>(0xf0 | (code >> 18)); text += static_cast<char>(0x80 | ((code >> 12) & 63)); text += static_cast<char>(0x80 | ((code >> 6) & 63)); text += static_cast<char>(0x80 | (code & 63)); }
        return text;
    };
    struct Rune { uint32_t code = 0; size_t size = 0; bool printable = false; bool incomplete = false; };
    const auto rune = [&](size_t at) {
        Rune value; value.size = width;
        if (buffer.size() - at < width) { value.incomplete = true; return value; }
        value.code = buffer[at];
        if (!wide) { value.printable = value.code >= 32 && value.code <= 126; return value; }
        value.code |= static_cast<uint32_t>(buffer[at + 1]) << 8;
        if (value.code >= 0xd800 && value.code <= 0xdbff) {
            if (buffer.size() - at < 4) { value.incomplete = true; return value; }
            const auto low = static_cast<uint32_t>(buffer[at + 2]) | (static_cast<uint32_t>(buffer[at + 3]) << 8);
            if (low < 0xdc00 || low > 0xdfff) return value;
            value.code = 0x10000 + ((value.code - 0xd800) << 10) + low - 0xdc00; value.size = 4;
        } else if (value.code >= 0xdc00 && value.code <= 0xdfff) return value;
        value.printable = value.code >= 32 && !(value.code >= 127 && value.code <= 159) &&
            !(value.code >= 0xfdd0 && value.code <= 0xfdef) && (value.code & 0xffff) < 0xfffe;
        return value;
    };
    size_t cursor = wide && baseAddress % 2 ? 1 : 0;
    cursor = std::min(cursor, buffer.size());
    while (cursor < buffer.size()) {
        const size_t start = cursor;
        size_t characters = 0; std::string full, preview; bool incomplete = false;
        while (cursor < buffer.size() && characters < options.maximumLength) {
            const auto value = rune(cursor);
            if (value.incomplete) { incomplete = true; break; }
            if (!value.printable) break;
            const auto encoded = utf8(value.code); full += encoded;
            if (characters < 256) preview += encoded;
            characters++; cursor += value.size;
        }
        if (!finalChunk && characters < options.maximumLength && (cursor == buffer.size() || incomplete)) {
            result.value.consumedBytes = start;
            result.operation = DMAOperationResult::Success(start);
            return result;
        }
        if (characters >= options.minimumLength &&
            (filter.empty() || (options.caseSensitive ? full : folded(full)).find(filter) != std::string::npos)) {
            result.value.matches.push_back({ baseAddress + start, cursor - start, characters, preview,
                characters > 256 || characters == options.maximumLength });
            if (result.value.matches.size() == options.maximumResults) {
                result.value.consumedBytes = cursor; result.value.limited = cursor < buffer.size();
                result.operation = DMAOperationResult::Success(cursor); return result;
            }
        }
        if (characters == options.maximumLength) continue;
        cursor = std::min(buffer.size(), cursor + width);
    }
    result.value.consumedBytes = buffer.size();
    result.operation = DMAOperationResult::Success(buffer.size());
    return result;
}
