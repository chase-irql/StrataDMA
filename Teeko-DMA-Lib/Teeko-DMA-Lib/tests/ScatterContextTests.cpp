#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <array>
#include <cstdint>
#include <vector>

TEEKO_TEST_CASE(raii_scatter_reads_writes_and_reports_each_request)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t source = 0x12345678;
    fixture.backend->Store(0x1800, source);
    uint32_t readValue = 0;
    const uint32_t writeValue = 0xaabbccdd;

    auto batch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE(batch.IsValid());
    TEEKO_REQUIRE(batch.AddRead(0x1800, readValue));
    TEEKO_REQUIRE(batch.AddWrite(0x1900, writeValue));
    TEEKO_REQUIRE(batch.Size() == 2);
    auto executed = batch.Execute();
    TEEKO_REQUIRE(executed);
    TEEKO_REQUIRE(readValue == source);
    TEEKO_REQUIRE(executed.value.size() == 2);
    TEEKO_REQUIRE(!executed.value[0].write);
    TEEKO_REQUIRE(executed.value[0].operation.transferredBytes == sizeof(source));
    TEEKO_REQUIRE(executed.value[1].write);
    TEEKO_REQUIRE(fixture.dma.Read<uint32_t>(0x1900) == writeValue);

    auto secondExecution = batch.Execute();
    TEEKO_REQUIRE(!secondExecution);
    TEEKO_REQUIRE_STATUS(secondExecution.operation, DMAStatus::InvalidArgument);
}

TEEKO_TEST_CASE(scatter_requests_are_split_at_page_boundaries)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const std::array<uint8_t, 8> expected{ 1, 2, 3, 4, 5, 6, 7, 8 };
    fixture.backend->StoreBytes(0x1ffc, expected.data(), expected.size());
    std::array<uint8_t, 8> actual{};

    const size_t before = fixture.backend->scatterPrepareCalls.load();
    auto batch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE(batch.AddRead(0x1ffc, actual));
    auto executed = batch.Execute();
    TEEKO_REQUIRE(executed && actual == expected);
    TEEKO_REQUIRE(fixture.backend->scatterPrepareCalls.load() - before == 2);
    TEEKO_REQUIRE(executed.value[0].operation.transferredBytes == expected.size());
}

TEEKO_TEST_CASE(scatter_partial_and_execution_failures_are_propagated)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->Fill(0x1800, 16, 0x5a);
    std::array<uint8_t, 16> buffer{};

    fixture.backend->partialReadLimit = 4;
    auto partialBatch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE(partialBatch.AddRead(0x1800, buffer));
    auto partial = partialBatch.Execute();
    TEEKO_REQUIRE(!partial);
    TEEKO_REQUIRE_STATUS(partial.operation, DMAStatus::PartialTransfer);
    TEEKO_REQUIRE(partial.value[0].operation.transferredBytes == 4);

    fixture.backend->partialReadLimit = 0;
    fixture.backend->failScatterExecute = true;
    auto failedBatch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE(failedBatch.AddRead(0x1800, buffer));
    auto failed = failedBatch.Execute();
    TEEKO_REQUIRE(!failed);
    TEEKO_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);
    TEEKO_REQUIRE_STATUS(failed.value[0].operation, DMAStatus::BackendError);
}

TEEKO_TEST_CASE(scatter_prepare_failure_invalidates_the_batch)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->failScatterPrepare = true;
    uint32_t value = 0;
    auto batch = fixture.dma.CreateScatterBatch();
    auto prepared = batch.AddRead(0x1800, value);
    TEEKO_REQUIRE(!prepared);
    TEEKO_REQUIRE(!batch.IsValid());
    TEEKO_REQUIRE(batch.Size() == 0);
    TEEKO_REQUIRE(!batch.Execute());
}

TEEKO_TEST_CASE(scatter_creation_and_input_validation_fail_cleanly)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->failScatterCreate = true;
    auto invalidBatch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE(!invalidBatch.IsValid());
    uint32_t value = 0;
    TEEKO_REQUIRE_STATUS(invalidBatch.AddRead(0x1800, value),
        DMAStatus::InvalidArgument);

    fixture.backend->failScatterCreate = false;
    auto batch = fixture.dma.CreateScatterBatch();
    TEEKO_REQUIRE_STATUS(batch.AddRead(0, value), DMAStatus::InvalidArgument);
    TEEKO_REQUIRE_STATUS(batch.AddRead(0x1800, nullptr, sizeof(value)),
        DMAStatus::InvalidArgument);
    TEEKO_REQUIRE_STATUS(batch.AddWrite(0x1800, nullptr, sizeof(value)),
        DMAStatus::InvalidArgument);
}

TEEKO_TEST_CASE(frame_gather_prefetches_deduplicated_pages_and_caches_reads)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t first = 11;
    const uint32_t second = 22;
    fixture.backend->Store(0x1800, first);
    fixture.backend->Store(0x1ffc, second);

    auto frame = fixture.dma.CreateFrameContext();
    auto gathered = frame.Gather({
        { 0x1800, sizeof(first) },
        { 0x1ffc, 8 }
    });
    TEEKO_REQUIRE(gathered && gathered.value.size() == 2);
    TEEKO_REQUIRE(frame.CachedBlockCount() == 2);
    TEEKO_REQUIRE(fixture.backend->prefetchedPages.size() == 2);

    const size_t reads = fixture.backend->readCalls.load();
    const uint32_t replacement = 99;
    fixture.backend->Store(0x1800, replacement);
    auto cached = frame.Read<uint32_t>(0x1800);
    TEEKO_REQUIRE(cached && cached.value == first);
    TEEKO_REQUIRE(fixture.backend->readCalls.load() == reads);

    frame.Clear();
    TEEKO_REQUIRE(frame.CachedBlockCount() == 0);
    auto refreshed = frame.Read<uint32_t>(0x1800);
    TEEKO_REQUIRE(refreshed && refreshed.value == replacement);
    TEEKO_REQUIRE(fixture.backend->readCalls.load() == reads + 1);
}

TEEKO_TEST_CASE(frame_gather_rejects_invalid_ranges_and_read_failures)
{
    MockDmaFixture fixture;
    fixture.Attach();
    auto frame = fixture.dma.CreateFrameContext();
    TEEKO_REQUIRE(!frame.Gather({}));
    auto invalid = frame.Gather({ { 0, 4 } });
    TEEKO_REQUIRE(!invalid);
    TEEKO_REQUIRE_STATUS(invalid.operation, DMAStatus::InvalidArgument);

    fixture.backend->failReads = true;
    auto failed = frame.Gather({ { 0x1800, 4 } });
    TEEKO_REQUIRE(!failed);
    TEEKO_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);
    TEEKO_REQUIRE(frame.CachedBlockCount() == 0);
}

TEEKO_TEST_CASE(legacy_scatter_api_remains_compatible)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t expected = 0x76543210;
    fixture.backend->Store(0x1800, expected);
    uint32_t actual = 0;
    TEEKO_REQUIRE(fixture.dma.AddScatter(0x1800, &actual));
    TEEKO_REQUIRE(fixture.dma.ExecuteScatter());
    TEEKO_REQUIRE(actual == expected);
    TEEKO_REQUIRE(fixture.dma.ResetScatter());

    const uint32_t replacement = 0xabcdef01;
    TEEKO_REQUIRE(fixture.dma.AddScatterWrite(0x1800, replacement));
    TEEKO_REQUIRE(fixture.dma.ExecuteScatter());
    TEEKO_REQUIRE(fixture.dma.Read<uint32_t>(0x1800) == replacement);
}
