#include "DMA.Types.hpp"

std::vector<DMAInspectionColumn> DMAInspectionColumns(const std::string& kind)
{
    static const std::unordered_map<std::string, std::vector<DMAInspectionColumn>> columns = {
        {"threads", {{"tid","number"},{"pid","number"},{"state","number"},{"running","boolean"},{"priority","number"},{"base_priority","number"},{"start","address"},{"win32_start","address"},{"ethread","address"},{"teb","address"},{"stack_base","address"},{"stack_limit","address"},{"kernel_stack_base","address"},{"kernel_stack_limit","address"},{"rip","address"},{"rsp","address"},{"created","filetime"},{"exited","filetime"},{"user_time","number"},{"kernel_time","number"},{"suspend_count","number"},{"wait_reason","number"}}},
        {"callstack", {{"frame","number"},{"return_address","address"},{"rsp","address"},{"base_sp","address"},{"module","text"},{"function","text"},{"displacement","number"},{"registers_present","boolean"}}},
        {"handles", {{"handle","address"},{"pid","number"},{"type","text"},{"name","text"},{"object","address"},{"access","address"},{"handle_count","number"},{"pointer_count","number"},{"security_descriptor","address"}}},
        {"heaps", {{"address","address"},{"heap_id","number"},{"index","number"},{"type","number"},{"is_32_bit","boolean"},{"segment_count","number"},{"segment_bytes","number"}}},
        {"heap-segments", {{"address","address"},{"size","number"},{"heap_index","number"},{"type","number"}}},
        {"heap-allocations", {{"address","address"},{"size","number"},{"type","number"}}},
        {"network", {{"pid","number"},{"state","number"},{"family","number"},{"local_address","text"},{"local_port","number"},{"remote_address","text"},{"remote_port","number"},{"local_valid","boolean"},{"remote_valid","boolean"},{"object","address"},{"created","filetime"},{"description","text"}}},
        {"services", {{"name","text"},{"display_name","text"},{"pid","number"},{"state","number"},{"start_type","number"},{"service_type","number"},{"path","text"},{"image_path","text"},{"account","text"},{"account_type","text"},{"object","address"},{"exit_code","number"}}},
        {"drivers", {{"name","text"},{"path","text"},{"service_key","text"},{"object","address"},{"base","address"},{"size","number"},{"device_object","address"}}},
        {"driver-dispatch", {{"driver","text"},{"driver_object","address"},{"major_index","number"},{"address","address"}}},
        {"devices", {{"object","address"},{"type","text"},{"type_id","number"},{"depth","number"},{"driver_object","address"},{"attached_device","address"},{"filesystem_device","address"},{"volume","text"}}},
        {"objects", {{"name","text"},{"type","text"},{"address","address"},{"parent","address"},{"child_count","number"}}},
        {"pool", {{"tag","text"},{"address","address"},{"size","number"},{"pool_type","number"},{"segment_type","number"},{"allocated","boolean"}}},
        {"unloaded-modules", {{"name","text"},{"base","address"},{"size","number"},{"wow64","boolean"},{"checksum","address"},{"pe_timestamp","number"},{"unloaded","filetime"}}}
    };
    const auto found = columns.find(kind == "kernel-unloaded-modules" ? "unloaded-modules" : kind);
    return found == columns.end() ? std::vector<DMAInspectionColumn>{} : found->second;
}

#include <cstring>

std::string DMARegistryValue::AsString() const
{
    if (data.empty())
        return {};

    // REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ are stored as UTF-16LE.
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        std::string result;
        const size_t characters = data.size() / sizeof(char16_t);
        result.reserve(characters);
        for (size_t index = 0; index < characters; ++index) {
            char16_t value = 0;
            std::memcpy(&value, data.data() + index * sizeof(value), sizeof(value));
            if (value == u'\0')
                break;
            result.push_back(value <= 0x7f ? static_cast<char>(value) : '?');
        }
        return result;
    }

    const auto* end = static_cast<const uint8_t*>(
        std::memchr(data.data(), 0, data.size()));
    const size_t length = end ? static_cast<size_t>(end - data.data()) : data.size();
    return std::string(reinterpret_cast<const char*>(data.data()), length);
}

uint32_t DMARegistryValue::AsDword(uint32_t fallback) const
{
    if (type != REG_DWORD || data.size() < sizeof(uint32_t))
        return fallback;
    uint32_t value = 0;
    std::memcpy(&value, data.data(), sizeof(value));
    return value;
}

uint64_t DMARegistryValue::AsQword(uint64_t fallback) const
{
    if (type != REG_QWORD || data.size() < sizeof(uint64_t))
        return fallback;
    uint64_t value = 0;
    std::memcpy(&value, data.data(), sizeof(value));
    return value;
}
