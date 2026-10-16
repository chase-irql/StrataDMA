#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

STRATA_TEST_CASE(registry_value_conversions_handle_supported_types)
{
    DMARegistryValue text;
    text.type = REG_SZ;
    const std::string expected = "value";
    const std::u16string encoded = u"value";
    text.data.resize((encoded.size() + 1) * sizeof(char16_t));
    std::memcpy(text.data.data(), encoded.c_str(), text.data.size());
    STRATA_REQUIRE(text.AsString() == expected);

    DMARegistryValue dword;
    dword.type = REG_DWORD;
    dword.data.resize(sizeof(uint32_t));
    const uint32_t dwordValue = 0x12345678;
    std::memcpy(dword.data.data(), &dwordValue, sizeof(dwordValue));
    STRATA_REQUIRE(dword.AsDword() == dwordValue);

    DMARegistryValue qword;
    qword.type = REG_QWORD;
    qword.data.resize(sizeof(uint64_t));
    const uint64_t qwordValue = 0x1122334455667788ULL;
    std::memcpy(qword.data.data(), &qwordValue, sizeof(qwordValue));
    STRATA_REQUIRE(qword.AsQword() == qwordValue);

    DMARegistryValue invalid;
    invalid.type = REG_BINARY;
    invalid.data = { 1 };
    STRATA_REQUIRE(invalid.AsDword(77) == 77);
    STRATA_REQUIRE(invalid.AsQword(88) == 88);
}

STRATA_TEST_CASE(registry_enumeration_and_query_return_owned_data)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    auto hives = fixture.dma.GetRegistryHives();
    auto keys = fixture.dma.EnumerateRegistryKeys("HKLM\\SYSTEM");
    auto values = fixture.dma.EnumerateRegistryValues("HKLM\\SYSTEM");
    auto answer = fixture.dma.QueryRegistryValue(
        "HKLM\\SOFTWARE\\Answer");
    STRATA_REQUIRE(hives && hives.value.size() == 1);
    STRATA_REQUIRE(hives.value[0].rootPath == "HKLM\\SYSTEM");
    STRATA_REQUIRE(keys && keys.value[0].name == "Child");
    STRATA_REQUIRE(values && values.value[0].AsDword() == 42);
    STRATA_REQUIRE(answer && answer.value.AsDword() == 42);

    auto invalid = fixture.dma.EnumerateRegistryKeys("");
    STRATA_REQUIRE(!invalid);
    STRATA_REQUIRE_STATUS(invalid.operation, DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(raw_registry_hive_reads_and_writes_report_byte_counts)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    const std::array<uint8_t, 4> expected{ 1, 2, 3, 4 };
    auto written = fixture.dma.WriteRegistryHive(0x1111, 0x20,
        expected.data(), expected.size());
    STRATA_REQUIRE(written);
    STRATA_REQUIRE(written.transferredBytes == expected.size());
    std::array<uint8_t, 4> actual{};
    auto read = fixture.dma.ReadRegistryHive(0x1111, 0x20, actual.data(),
        actual.size());
    STRATA_REQUIRE(read && actual == expected);
    STRATA_REQUIRE(read.requestedBytes == expected.size());
    STRATA_REQUIRE(read.transferredBytes == expected.size());

    STRATA_REQUIRE_STATUS(fixture.dma.ReadRegistryHive(0x1111, 0, nullptr, 0),
        DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(fixture.dma.WriteRegistryHive(0x1111, 0, nullptr, 0),
        DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(vfs_listing_full_reads_and_offset_reads_work)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    auto entries = fixture.dma.ListVfs("\\");
    STRATA_REQUIRE(entries && entries.value.size() == 2);
    STRATA_REQUIRE(entries.value[0].name == "mock.txt");
    STRATA_REQUIRE(entries.value[1].directory);

    auto file = fixture.dma.ReadVfsFile("\\mock.txt");
    STRATA_REQUIRE(file);
    STRATA_REQUIRE(std::string(file.value.begin(), file.value.end()) == "mock");

    std::array<char, 2> tail{};
    auto read = fixture.dma.ReadVfs("\\mock.txt", 2, tail.data(), tail.size());
    STRATA_REQUIRE(read);
    STRATA_REQUIRE(std::string(tail.data(), tail.size()) == "ck");
    STRATA_REQUIRE(read.address == 2);
    STRATA_REQUIRE(read.transferredBytes == 2);
}

STRATA_TEST_CASE(vfs_size_limits_and_missing_files_are_reported)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    fixture.backend->vfsFiles["\\large.bin"] =
        std::vector<uint8_t>(32, 0xaa);
    auto limited = fixture.dma.ReadVfsFile("\\large.bin", 8);
    STRATA_REQUIRE(!limited);
    STRATA_REQUIRE_STATUS(limited.operation, DMAStatus::PartialTransfer);
    STRATA_REQUIRE(limited.value.size() == 8);

    auto missing = fixture.dma.ReadVfsFile("\\missing.bin");
    STRATA_REQUIRE(!missing);
    STRATA_REQUIRE_STATUS(missing.operation, DMAStatus::NotFound);
    STRATA_REQUIRE(!fixture.dma.ReadVfsFile("", 16));
    STRATA_REQUIRE(!fixture.dma.ReadVfsFile("\\mock.txt", 0));
}

STRATA_TEST_CASE(vfs_writes_modify_and_extend_files)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    const std::array<uint8_t, 3> replacement{ 'X', 'Y', 'Z' };
    auto written = fixture.dma.WriteVfs("\\mock.txt", 1,
        replacement.data(), replacement.size());
    STRATA_REQUIRE(written);
    STRATA_REQUIRE(written.requestedBytes == replacement.size());
    STRATA_REQUIRE(written.transferredBytes == replacement.size());
    auto updated = fixture.dma.ReadVfsFile("\\mock.txt");
    STRATA_REQUIRE(updated);
    STRATA_REQUIRE(std::string(updated.value.begin(), updated.value.end()) ==
        "mXYZ");

    const uint8_t extra = '!';
    STRATA_REQUIRE(fixture.dma.WriteVfs("\\mock.txt", 6, &extra, 1));
    STRATA_REQUIRE(fixture.backend->vfsFiles["\\mock.txt"].size() == 7);
    STRATA_REQUIRE_STATUS(fixture.dma.WriteVfs("\\mock.txt", 0, nullptr, 0),
        DMAStatus::InvalidArgument);
}

namespace {
class MinimalBackend final : public IVmmBackend {
public:
    DMAOperationResult Initialize(const std::vector<std::string>&) override
    {
        initialized = true;
        return DMAOperationResult::Success();
    }
    void Close() override { initialized = false; }
    bool IsInitialized() const noexcept override { return initialized; }
    bool initialized = false;
};
}

STRATA_TEST_CASE(optional_backend_methods_default_to_unsupported)
{
    MinimalBackend backend;
    std::vector<DMARegistryHiveInfo> hives;
    std::vector<DMAPhysicalMemoryRange> ranges;
    DWORD transferred = 0;
    uint8_t byte = 0;
    STRATA_REQUIRE_STATUS(backend.InitializePlugins(), DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.GetRegistryHives(hives),
        DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.GetPhysicalMemoryMap(ranges),
        DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.ReadVfs("\\file", 0, &byte, 1,
        transferred), DMAStatus::Unsupported);
    STRATA_REQUIRE(!backend.CreateScatter(42, 0));
}

STRATA_TEST_CASE(timeline_pages_preserve_exact_fields_and_filter_utc_events)
{
    MockDmaFixture fixture; fixture.Initialize(true);
    DMATimelineQuery query; query.limit = 1;
    const auto first = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(first && first.value.events.size() == 1);
    STRATA_REQUIRE(first.value.events[0].address == UINT64_C(0xfffffffffffffff0));
    STRATA_REQUIRE(first.value.events[0].timestamp == "2026-10-15T12:00:02Z");
    STRATA_REQUIRE(first.value.scannedBytes == first.value.nextOffset && first.value.readBytes >= first.value.scannedBytes);
    query.offset = first.value.nextOffset;
    const auto second = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(second && second.value.events[0].type == "REG");
    STRATA_REQUIRE(second.value.events[0].offset == query.offset);
    query.offset = 0; query.limit = 100; query.action = "DEL"; query.pid = 42;
    query.from = "2026-10-15T12:00:00Z"; query.until = "2026-10-15T12:00:01Z";
    query.filter = "TEST.EXE";
    const auto filtered = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(filtered && filtered.value.events.size() == 1 && filtered.value.endOfFile);
    STRATA_REQUIRE(filtered.value.events[0].description == "test.exe stopped");
    STRATA_REQUIRE(fixture.backend->initialized && fixture.dma.GetPID() == 0);
}
STRATA_TEST_CASE(timeline_bounds_and_line_alignment_are_validated)
{
    MockDmaFixture fixture; DMATimelineQuery query;
    query.from = "2026-02-30T00:00:00Z";
    STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::InvalidArgument);
    query.from.clear(); STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::NotInitialized);
    fixture.Initialize(true); query.offset = 1;
    STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::InvalidArgument);
    query.offset = 0; query.path = "/forensic/timeline/../secret.txt";
    STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::InvalidArgument);
    query.path = "/forensic/timeline/timeline_all.txt"; query.limit = 4097;
    STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::InvalidArgument);
    query.limit = 100; query.maxBytes = 65536;
    STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::InvalidArgument);
}
STRATA_TEST_CASE(timeline_streams_split_lines_and_reports_malformed_records)
{
    MockDmaFixture fixture; fixture.Initialize(true);
    const std::string line = "2024-02-29 00:00:00 UTC PROC CRE 42 7 fffffffffffffff0 " + std::string(20000, 'x');
    const std::string text = "DATE TYPE ACTION PID NUM HEX DESC\n=====\nmalformed\n" + line + "\r\n" + line;
    fixture.backend->vfsFiles["\\forensic\\timeline\\timeline_all.txt"] = std::vector<uint8_t>(text.begin(), text.end());
    DMATimelineQuery query; const auto page = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(page && page.value.events.size() == 2 && page.value.endOfFile);
    STRATA_REQUIRE(page.value.headerLines == 2 && page.value.malformedLines == 1);
    STRATA_REQUIRE(page.value.events[0].description.size() == 20000);
    STRATA_REQUIRE(page.value.nextOffset == text.size());
    query.limit = 1; const auto first = fixture.dma.ReadTimeline(query); query.offset = first.value.nextOffset;
    const auto next = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(next && next.value.events.size() == 1 && next.value.events[0].offset == query.offset);
    const std::string longLine(65538, 'x');
    fixture.backend->vfsFiles["\\forensic\\timeline\\timeline_all.txt"] = std::vector<uint8_t>(longLine.begin(), longLine.end());
    query.offset = 0; STRATA_REQUIRE_STATUS(fixture.dma.ReadTimeline(query).operation, DMAStatus::Unsupported);
    const std::string invalidUtf8 = "2024-02-29 00:00:00 UTC PROC CRE 42 7 fffffffffffffff0 " + std::string(1, static_cast<char>(0xff)) + "\n";
    fixture.backend->vfsFiles["\\forensic\\timeline\\timeline_all.txt"] = std::vector<uint8_t>(invalidUtf8.begin(), invalidUtf8.end());
    const auto invalid = fixture.dma.ReadTimeline(query);
    STRATA_REQUIRE(invalid && invalid.value.events.empty() && invalid.value.malformedLines == 1);
}
