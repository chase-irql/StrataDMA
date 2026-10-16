#include "DMA.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>

namespace {
bool Timestamp(const std::string& s) {
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' ||
        s[13] != ':' || s[16] != ':' || s[19] != 'Z') return false;
    for (size_t i = 0; i < s.size(); ++i) if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 && i != 19 &&
        (s[i] < '0' || s[i] > '9')) return false;
    const int year = std::stoi(s.substr(0, 4)), month = std::stoi(s.substr(5, 2)), day = std::stoi(s.substr(8, 2));
    const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (year < 1601 || month < 1 || month > 12) return false;
    const int maximum = days[month - 1] + (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
    return day >= 1 && day <= maximum && std::stoi(s.substr(11, 2)) < 24 &&
        std::stoi(s.substr(14, 2)) < 60 && std::stoi(s.substr(17, 2)) < 60;
}
std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
bool Number(const std::string& s, uint64_t& value, int base = 10) {
    const auto p = std::from_chars(s.data(), s.data() + s.size(), value, base);
    return !s.empty() && p.ec == std::errc{} && p.ptr == s.data() + s.size();
}
bool Utf8(const std::string& s) {
    for (size_t i = 0; i < s.size();) {
        const auto first = static_cast<unsigned char>(s[i++]);
        if (first < 0x80) continue;
        const size_t count = first >= 0xc2 && first <= 0xdf ? 1 : first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : 0;
        if (!count || count > s.size() - i) return false;
        const auto next = static_cast<unsigned char>(s[i]);
        if ((first == 0xe0 && next < 0xa0) || (first == 0xed && next >= 0xa0) ||
            (first == 0xf0 && next < 0x90) || (first == 0xf4 && next >= 0x90)) return false;
        for (size_t n = 0; n < count; ++n) if ((static_cast<unsigned char>(s[i++]) & 0xc0) != 0x80) return false;
    }
    return true;
}
bool Parse(const std::string& line, DMATimelineEvent& event) {
    if (line.find('\0') != std::string::npos || !Utf8(line)) return false;
    std::istringstream input(line);
    std::string date, time, zone, pid, number, address;
    if (!(input >> date >> time >> zone >> event.type >> event.action >> pid >> number >> address) ||
        zone != "UTC" || event.type.size() > 32 || event.action.size() > 8) return false;
    event.timestamp = date + "T" + time + "Z";
    uint64_t p = 0, n = 0;
    if (!Timestamp(event.timestamp) || !Number(pid, p) || p > UINT32_MAX || !Number(number, n) || n > UINT32_MAX ||
        address.size() > 16 || !Number(address, event.address, 16)) return false;
    event.pid = static_cast<DWORD>(p); event.number = static_cast<DWORD>(n);
    std::getline(input, event.description);
    if (!event.description.empty() && event.description.front() == ' ') event.description.erase(0, 1);
    return true;
}
}

DMAResult<DMATimelinePage> DMA::ReadTimeline(const DMATimelineQuery& query) const {
    DMAResult<DMATimelinePage> result;
    result.value.nextOffset = query.offset;
    std::string path = query.path;
    std::replace(path.begin(), path.end(), '/', '\\');
    const std::string prefix = "\\forensic\\timeline\\timeline_";
    if (path.size() > 1024 || path.compare(0, prefix.size(), prefix) != 0 || path.size() < prefix.size() + 5 ||
        path.substr(path.size() - 4) != ".txt" || path.find("..") != std::string::npos ||
        path.find('\\', prefix.size()) != std::string::npos || path.find('\0') != std::string::npos ||
        query.limit == 0 || query.limit > 4096 || query.maxBytes < 65537 || query.maxBytes > 4 * 1024 * 1024 ||
        query.offset > std::numeric_limits<uint64_t>::max() - query.maxBytes || query.filter.size() > 256 ||
        query.filter.find('\0') != std::string::npos ||
        (!query.action.empty() && query.action != "CRE" && query.action != "MOD" && query.action != "RD" && query.action != "DEL") ||
        (!query.from.empty() && !Timestamp(query.from)) || (!query.until.empty() && !Timestamp(query.until)) ||
        (!query.from.empty() && !query.until.empty() && query.from > query.until)) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Invalid timeline path, UTC filters or page bounds.");
        return result;
    }
    if (!std::all_of(path.begin() + prefix.size(), path.end() - 4, [](unsigned char c) { return std::isalnum(c) || c == '_' || c == '-'; })) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Invalid timeline filename."); return result;
    }
    if (!IsInitialized()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotInitialized, "Initialize DMA before reading a forensic timeline.");
        return result;
    }
    if (query.offset) {
        char previous = 0; DWORD transferred = 0;
        const auto op = backend->ReadVfs(path, query.offset - 1, &previous, 1, transferred);
        if (!op) { result.operation = op; return result; }
        if (transferred != 1 || previous != '\n') {
            result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Timeline offset must follow a complete line.");
            return result;
        }
    }
    const auto filter = Lower(query.filter);
    std::string pending;
    uint64_t cursor = query.offset;
    auto consume = [&](std::string line, uint64_t at) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.compare(0, 4, "DATE") == 0 || line.compare(0, 3, "===") == 0) { ++result.value.headerLines; return; }
        DMATimelineEvent event; event.offset = at;
        if (!Parse(line, event)) { ++result.value.malformedLines; return; }
        if ((!query.action.empty() && event.action != query.action) || (query.pid && event.pid != query.pid) ||
            (!query.from.empty() && event.timestamp < query.from) || (!query.until.empty() && event.timestamp > query.until) ||
            (!filter.empty() && Lower(line).find(filter) == std::string::npos)) return;
        result.value.events.push_back(std::move(event));
    };
    while (result.value.readBytes < query.maxBytes) {
        char buffer[16384]; DWORD transferred = 0;
        const auto size = static_cast<DWORD>(std::min(sizeof(buffer), query.maxBytes - result.value.readBytes));
        auto op = backend->ReadVfs(path, query.offset + result.value.readBytes, buffer, size, transferred);
        if (transferred > size) {
            result.operation = DMAOperationResult::Failure(DMAStatus::BackendError, "Timeline provider returned an invalid byte count."); return result;
        }
        if (!op) { result.operation = op; return result; }
        result.value.readBytes += transferred;
        pending.append(buffer, transferred);
        size_t begin = 0, newline;
        while ((newline = pending.find('\n', begin)) != std::string::npos) {
            if (newline - begin > 65536) {
                result.operation = DMAOperationResult::Failure(DMAStatus::Unsupported, "Timeline line exceeds 64 KiB; this page is incomplete."); return result;
            }
            consume(pending.substr(begin, newline - begin), cursor);
            cursor += newline + 1 - begin; begin = newline + 1;
            result.value.nextOffset = cursor; result.value.scannedBytes = static_cast<size_t>(cursor - query.offset);
            if (result.value.events.size() == query.limit) { result.operation = DMAOperationResult::Success(result.value.readBytes); return result; }
        }
        pending.erase(0, begin);
        if (pending.size() > 65536) {
            result.operation = DMAOperationResult::Failure(DMAStatus::Unsupported, "Timeline line exceeds 64 KiB; this page is incomplete."); return result;
        }
        if (!transferred) {
            if (!pending.empty()) { consume(pending, cursor); cursor += pending.size(); }
            result.value.nextOffset = cursor; result.value.scannedBytes = static_cast<size_t>(cursor - query.offset); result.value.endOfFile = true;
            result.operation = DMAOperationResult::Success(result.value.readBytes); return result;
        }
    }
    // Only complete lines advance the cursor; a split line is reread on the next bounded page.
    result.operation = DMAOperationResult::Success(result.value.readBytes);
    return result;
}
