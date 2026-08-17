#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
bool HasArgument(const std::vector<std::string>& arguments,
    const std::string& requested)
{
    return std::find(arguments.begin(), arguments.end(), requested) !=
        arguments.end();
}
}

TEEKO_TEST_CASE(initialization_forwards_options_and_plugins)
{
    MockDmaFixture fixture;
    DMAInitializationOptions options;
    options.device = "mock://device";
    options.useMemoryMap = true;
    options.memoryMapPath = "auto";
    options.debug = true;
    options.waitForInitialization = true;
    options.initializePlugins = true;
    options.extraArguments = { "-norefresh" };

    TEEKO_REQUIRE(fixture.dma.Initialize(options));
    TEEKO_REQUIRE(fixture.backend->pluginsInitialized);
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "mock://device"));
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments, "-memmap"));
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments, "auto"));
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments, "-v"));
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "-waitinitialize"));
    TEEKO_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "-norefresh"));
}

TEEKO_TEST_CASE(initialization_failures_preserve_diagnostics)
{
    auto backend = std::make_shared<MockVmmBackend>();
    DMA dma(backend);
    DMAInitializationOptions options;
    options.useMemoryMap = false;

    backend->failInitialize = true;
    TEEKO_REQUIRE(!dma.Initialize(options));
    TEEKO_REQUIRE(dma.GetLastError().find("mock initialization") !=
        std::string::npos);

    backend->failInitialize = false;
    backend->failPluginInitialization = true;
    options.initializePlugins = true;
    TEEKO_REQUIRE(!dma.Initialize(options));
    TEEKO_REQUIRE(!backend->initialized);
    TEEKO_REQUIRE(dma.GetLastError().find("plugin") != std::string::npos);
}

TEEKO_TEST_CASE(attach_detach_and_module_cache_are_consistent)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    TEEKO_REQUIRE(!fixture.dma.IsAttached());
    fixture.Attach();
    TEEKO_REQUIRE(fixture.dma.GetPID() == MockVmmBackend::TargetPid);
    TEEKO_REQUIRE(fixture.dma.GetMainBase() == MockVmmBackend::MemoryBase);

    const size_t calls = fixture.backend->moduleCalls.load();
    TEEKO_REQUIRE(fixture.dma.GetModuleBase("TEST.EXE") ==
        MockVmmBackend::MemoryBase);
    TEEKO_REQUIRE(fixture.dma.GetModuleSize("test.exe") == 0x8000);
    TEEKO_REQUIRE(fixture.backend->moduleCalls.load() == calls);

    TEEKO_REQUIRE(fixture.dma.GetModuleBase("helper.dll") == 0x9000);
    const size_t helperCalls = fixture.backend->moduleCalls.load();
    TEEKO_REQUIRE(fixture.dma.GetModuleBase("HELPER.DLL") == 0x9000);
    TEEKO_REQUIRE(fixture.backend->moduleCalls.load() == helperCalls);

    fixture.dma.Detach();
    TEEKO_REQUIRE(!fixture.dma.IsAttached());
    TEEKO_REQUIRE(fixture.dma.GetPID() == 0);
    TEEKO_REQUIRE(fixture.dma.GetMainBase() == 0);
}

TEEKO_TEST_CASE(process_discovery_and_expanded_metadata_are_exposed)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    const auto ids = fixture.dma.FindProcessIds("TEST.EXE");
    TEEKO_REQUIRE(ids == std::vector<DWORD>{ MockVmmBackend::TargetPid });

    auto process = fixture.dma.GetProcessInfoResult(MockVmmBackend::TargetPid);
    TEEKO_REQUIRE(process);
    TEEKO_REQUIRE(process.value.parentPid == 4);
    TEEKO_REQUIRE(process.value.eprocessAddress != 0);
    TEEKO_REQUIRE(process.value.pebAddress == 0x8000);
    TEEKO_REQUIRE(process.value.sid == "S-1-5-21-mock");
    TEEKO_REQUIRE(process.value.integrityLevel ==
        VMMDLL_PROCESS_INTEGRITY_LEVEL_HIGH);

    auto missing = fixture.dma.GetProcessInfoResult(99);
    TEEKO_REQUIRE(!missing);
    TEEKO_REQUIRE_STATUS(missing.operation, DMAStatus::NotFound);
}

TEEKO_TEST_CASE(structured_reads_and_writes_report_complete_context)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint64_t address = 0x1800;
    const uint32_t expected = 0x12345678;
    auto written = fixture.dma.WriteRawResult(address, &expected,
        sizeof(expected));
    TEEKO_REQUIRE(written);
    TEEKO_REQUIRE(written.pid == MockVmmBackend::TargetPid);
    TEEKO_REQUIRE(written.address == address);
    TEEKO_REQUIRE(written.requestedBytes == sizeof(expected));
    TEEKO_REQUIRE(written.transferredBytes == sizeof(expected));

    auto read = fixture.dma.ReadResult<uint32_t>(address,
        VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING);
    TEEKO_REQUIRE(read && read.value == expected);
    TEEKO_REQUIRE(read.operation.flags ==
        (VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING));
    TEEKO_REQUIRE(fixture.backend->lastReadFlags == read.operation.flags);

    fixture.backend->partialReadLimit = 2;
    uint32_t partialValue = 0;
    auto partial = fixture.dma.ReadRawResult(address, &partialValue,
        sizeof(partialValue));
    TEEKO_REQUIRE(!partial);
    TEEKO_REQUIRE_STATUS(partial, DMAStatus::PartialTransfer);
    TEEKO_REQUIRE(partial.transferredBytes == 2);

    fixture.backend->partialReadLimit = 0;
    fixture.backend->failWrites = true;
    auto failedWrite = fixture.dma.WriteRawResult(address, &expected,
        sizeof(expected));
    TEEKO_REQUIRE(!failedWrite);
    TEEKO_REQUIRE(fixture.dma.GetLastError().find("write") != std::string::npos);
}

TEEKO_TEST_CASE(invalid_memory_requests_fail_without_touching_backend)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const size_t reads = fixture.backend->readCalls.load();
    uint32_t value = 0;
    auto nullAddress = fixture.dma.ReadRawResult(0, &value, sizeof(value));
    auto nullBuffer = fixture.dma.ReadRawResult(0x1800, nullptr, sizeof(value));
    auto zeroSize = fixture.dma.ReadRawResult(0x1800, &value, 0);
    TEEKO_REQUIRE_STATUS(nullAddress, DMAStatus::InvalidArgument);
    TEEKO_REQUIRE_STATUS(nullBuffer, DMAStatus::InvalidArgument);
    TEEKO_REQUIRE_STATUS(zeroSize, DMAStatus::InvalidArgument);
    TEEKO_REQUIRE(fixture.backend->readCalls.load() == reads);
}

TEEKO_TEST_CASE(strings_pointer_chains_and_relative_addresses_work)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const char text[] = "hello";
    fixture.backend->StoreBytes(0x3000, text, sizeof(text));
    const wchar_t wide[] = L"wide";
    fixture.backend->StoreBytes(0x3100, wide, sizeof(wide));
    TEEKO_REQUIRE(fixture.dma.ReadString(0x3000, 32) == "hello");
    TEEKO_REQUIRE(fixture.dma.ReadWString(0x3100, 32) == L"wide");

    // ReadChain dereferences first, then applies each offset.
    fixture.backend->Store<uint64_t>(0x3200, 0x3400);
    fixture.backend->Store<uint64_t>(0x3410, 0x35e0);
    TEEKO_REQUIRE(fixture.dma.ReadChain(0x3200, { 0x10, 0x20 }) == 0x3600);
    uint64_t chain = 0;
    TEEKO_REQUIRE(fixture.dma.TryReadChain(0x3200, { 0x10, 0x20 }, chain));
    TEEKO_REQUIRE(chain == 0x3600);
    TEEKO_REQUIRE(fixture.dma.TryReadChain(0x3200, {}, chain));
    TEEKO_REQUIRE(chain == 0x3200);

    const int32_t displacement = 0x20;
    fixture.backend->Store(0x3703, displacement);
    TEEKO_REQUIRE(fixture.dma.ResolveRelative(0x3700, 3, 7) == 0x3727);
}

TEEKO_TEST_CASE(memory_contexts_bind_pid_flags_and_translation)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t expected = 99;
    fixture.backend->Store(0x4000, expected);

    auto process = fixture.dma.ProcessContext();
    auto value = process.Read<uint32_t>(0x4000);
    TEEKO_REQUIRE(value && value.value == expected);
    TEEKO_REQUIRE(fixture.backend->lastReadPid == MockVmmBackend::TargetPid);

    auto kernel = fixture.dma.KernelContext(4, VMMDLL_FLAG_NOPAGING);
    auto kernelValue = kernel.Read<uint32_t>(0x4000);
    TEEKO_REQUIRE(kernelValue && kernelValue.value == expected);
    TEEKO_REQUIRE(fixture.backend->lastReadPid ==
        (4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY));
    TEEKO_REQUIRE(fixture.backend->lastReadFlags == VMMDLL_FLAG_NOPAGING);

    uint64_t physical = 0;
    TEEKO_REQUIRE(fixture.dma.VirtualToPhysical(0x4000, physical));
    TEEKO_REQUIRE(physical == 0x103000);
    TEEKO_REQUIRE(fixture.dma.PrefetchPages({ 0x4000, 0x5000 }));
    TEEKO_REQUIRE(fixture.backend->prefetchedPages.size() == 2);
}

TEEKO_TEST_CASE(process_monitor_reports_exit_and_reattachment)
{
    MockDmaFixture fixture;
    fixture.Attach();
    std::atomic<size_t> exits{ 0 };
    std::atomic<size_t> reattachments{ 0 };
    TEEKO_REQUIRE(fixture.dma.StartProcessMonitor("test.exe", 10, true,
        [&](const DMAProcessEvent& event) {
            if (event.kind == DMAProcessEventKind::Exited)
                ++exits;
            if (event.kind == DMAProcessEventKind::Reattached ||
                event.kind == DMAProcessEventKind::Attached)
                ++reattachments;
        }));

    fixture.backend->processAvailable.store(false);
    for (int attempt = 0; attempt < 50 && exits.load() == 0; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fixture.backend->processAvailable.store(true);
    for (int attempt = 0; attempt < 50 && reattachments.load() == 0; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fixture.dma.StopProcessMonitor();

    TEEKO_REQUIRE(exits.load() >= 1);
    TEEKO_REQUIRE(reattachments.load() >= 1);
    TEEKO_REQUIRE(fixture.dma.IsAttached());
}
