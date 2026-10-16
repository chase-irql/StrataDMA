#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace {
void StoreValidPe64(MockVmmBackend& backend)
{
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    backend.Store(MockVmmBackend::MemoryBase, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.SizeOfImage = 0x8000;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
        .VirtualAddress = 0x777;
    backend.Store(MockVmmBackend::MemoryBase + 0x80, nt);

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".text", 5);
    section.Misc.VirtualSize = 0x200;
    section.VirtualAddress = 0x1000;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x400;
    section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    backend.Store(MockVmmBackend::MemoryBase + 0x80 +
        sizeof(IMAGE_NT_HEADERS64), section);
    backend.Fill(MockVmmBackend::MemoryBase + 0x1000, 0x200, 0x90);
}

std::filesystem::path TemporaryFile(const char* name)
{
    return std::filesystem::temp_directory_path() / name;
}

std::vector<uint8_t> ReadFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>() };
}
}

STRATA_TEST_CASE(saved_image_identity_and_relocations_need_no_device)
{
    const auto path = TemporaryFile("strata_dma_saved_image_test.bin");
    for (const bool is64 : { false, true }) {
        std::vector<uint8_t> bytes(0x12000);
        const auto store = [&](size_t at, const auto& value) { std::memcpy(bytes.data() + at, &value, sizeof(value)); };
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80; store(0, dos);
        DWORD signature = IMAGE_NT_SIGNATURE; store(0x80, signature);
        IMAGE_FILE_HEADER coff{}; coff.Machine = is64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        coff.NumberOfSections = 1; coff.TimeDateStamp = 0xfedcba98;
        coff.SizeOfOptionalHeader = is64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32); store(0x84, coff);
        const auto optional = [&](auto header) {
            header.Magic = is64 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            header.ImageBase = static_cast<decltype(header.ImageBase)>(is64 ? 0xfffff80000000000ULL : 0x400000);
            header.SizeOfImage = static_cast<DWORD>(bytes.size()); header.AddressOfEntryPoint = 0x1000;
            header.MajorImageVersion = 3; header.MinorImageVersion = 7; header.CheckSum = 0xabcdef01;
            header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0x11000, 12 }; store(0x98, header);
        };
        if (is64) optional(IMAGE_OPTIONAL_HEADER64{}); else optional(IMAGE_OPTIONAL_HEADER32{});
        IMAGE_BASE_RELOCATION block{}; block.VirtualAddress = 0xf000; block.SizeOfBlock = 12; store(0x11000, block);
        WORD entry = static_cast<WORD>(((is64 ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW) << 12) | 0xffe); store(0x11008, entry);
        const auto save = [&] { std::ofstream output(path, std::ios::binary | std::ios::trunc); output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); };
        save(); const auto result = DMA::InspectLoadedImage(path.u8string());
        STRATA_REQUIRE(result); STRATA_REQUIRE(result.value.is64Bit == is64);
        STRATA_REQUIRE(result.value.preferredBase == (is64 ? 0xfffff80000000000ULL : 0x400000));
        STRATA_REQUIRE(result.value.timestamp == 0xfedcba98 && result.value.checksum == 0xabcdef01);
        STRATA_REQUIRE(result.value.imageMajorVersion == 3 && result.value.imageMinorVersion == 7);
        STRATA_REQUIRE(result.value.relocationsComplete && result.value.relocations.size() == 1);
        STRATA_REQUIRE(result.value.relocations[0].rva == 0xfffe && result.value.relocations[0].width == (is64 ? 8 : 4));
        const auto gap = DMA::InspectLoadedImage(path.u8string(), {{0x10000,1}});
        STRATA_REQUIRE(gap && !gap.value.relocationsComplete && gap.value.relocations.empty());
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string(), {{0x90,1}}));
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string(), {{10,2},{11,1}}));
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string(), {{bytes.size(),1}}));
        store(0x1100a, entry); save();
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string()).value.relocationsComplete);
        WORD padding = 0; store(0x1100a, padding); entry = 0x7000; store(0x11008, entry); save();
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string()).value.relocationsComplete);
        block.SizeOfBlock = 10; store(0x11000, block); save();
        STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string()).value.relocationsComplete);
        bytes[0] = 0; save(); STRATA_REQUIRE(!DMA::InspectLoadedImage(path.u8string()));
    }
    std::filesystem::remove(path);
    STRATA_REQUIRE(DMA::InspectLoadedImage(path.u8string()).operation.status == DMAStatus::IoError);
}

STRATA_TEST_CASE(module_dump_rebuilds_file_layout_and_import_thunks)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    StoreValidPe64(*fixture.backend);
    const auto path = TemporaryFile("strata_dma_module_dump_test.bin");

    STRATA_REQUIRE(fixture.dma.DumpModule("test.exe", path.string()));
    const auto bytes = ReadFile(path);
    STRATA_REQUIRE(bytes.size() == fixture.backend->modules[0].imageSize);

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        bytes.data() + 0x80);
    STRATA_REQUIRE(nt->OptionalHeader.FileAlignment == 0x1000);
    STRATA_REQUIRE(nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress == 0);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    STRATA_REQUIRE(section->PointerToRawData == section->VirtualAddress);
    STRATA_REQUIRE(section->SizeOfRawData == 0x200);
    uint64_t thunk = 0;
    std::memcpy(&thunk, bytes.data() + 0x300, sizeof(thunk));
    STRATA_REQUIRE(thunk == 0x400);

    std::error_code error;
    std::filesystem::remove(path, error);
    STRATA_REQUIRE(!error);
}

STRATA_TEST_CASE(module_dump_rejects_invalid_or_truncated_headers)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    const auto path = TemporaryFile("strata_dma_invalid_dump_test.bin");

    fixture.backend->Store<uint16_t>(MockVmmBackend::MemoryBase, 0);
    auto dumped = fixture.dma.DumpModule("test.exe", path.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("DOS header") !=
        std::string::npos);

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x7ff0;
    fixture.backend->Store(MockVmmBackend::MemoryBase, dos);
    dumped = fixture.dma.DumpModule("test.exe", path.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("PE header") !=
        std::string::npos);
}

STRATA_TEST_CASE(memory_dump_obeys_pid_and_partial_read_contracts)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    fixture.backend->Fill(0x1800, 32, 0x5a);
    auto bytes = fixture.dma.DumpMemory(0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    STRATA_REQUIRE(bytes.front() == 0x5a && bytes.back() == 0x5a);

    fixture.backend->partialReadLimit = 8;
    bytes = fixture.dma.DumpMemory(0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    STRATA_REQUIRE(bytes[7] == 0x5a && bytes[8] == 0);

    bytes = fixture.dma.DumpMemoryEx(MockVmmBackend::TargetPid, 0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    bytes = fixture.dma.DumpMemoryEx(MockVmmBackend::TargetPid, 0x1800, 32,
        VMMDLL_FLAG_NOCACHE);
    STRATA_REQUIRE(bytes.size() == 8);
    STRATA_REQUIRE(fixture.backend->lastReadPid == MockVmmBackend::TargetPid);
}

STRATA_TEST_CASE(module_dump_reports_missing_module_and_output_failures)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    STRATA_REQUIRE(!fixture.dma.DumpModule("missing.dll", "unused.bin"));
    STRATA_REQUIRE(!fixture.dma.DumpModule("test.exe", ""));

    StoreValidPe64(*fixture.backend);
    const auto impossible = TemporaryFile("strata_dma_missing_directory") /
        "dump.bin";
    const auto dumped = fixture.dma.DumpModule("test.exe", impossible.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("open") != std::string::npos);
}
