# StrataDMA

## OS inspection tables

`DMAInspectionTable::sourceTotal` counts recovered rows in the requested scope before
text filtering, independently of pagination; `total` counts matching rows. A successful
empty source map is distinct from a filter excluding recovered rows. Neither establishes
that an object or activity never existed. Failed map reads remain operation errors.

`DMA::Inspect(DMAInspectionQuery)` exposes threads, call stacks, handles, heaps,
heap segments/allocations, network endpoints, services, driver objects and dispatch
functions, devices, kernel objects, pool allocations, and unloaded modules.
`kernel-unloaded-modules` reads System/PID 4's kernel history without requiring
an attachment; it rejects a process PID. Kernel symbol availability and retained
history determine what the runtime can recover. Returned addresses can be reused
after unloading and are historical metadata, not a preserved image.
`DMAInspectionKinds` lists supported kinds. Process datasets accept an explicit
PID or use the attached process; system datasets leave PID zero. Inspection never
changes attachment and never writes target memory.

The result owns its strings and exposes ordered `columns` (`name`, `type`), rows,
and the filtered `total`. Cell types are `text`, `number`, `address`, `filetime`,
and `boolean`; decimal numbers and hexadecimal addresses/timestamps are strings
to preserve 64-bit precision across language bindings. Set `offset`, `limit`
(1–4096), and an optional case-insensitive `filter` (up to 256 bytes). Native maps
are freed after copying only the requested page. `selector` is the thread ID for
`callstack`, heap number/address for `heap-allocations`, or optional driver-object
address for `driver-dispatch`. Zero selects heap number zero or all drivers.

Unavailable maps return structured backend errors; mismatched map versions return
`Unsupported`. Readable data and recoverable stacks depend on the target Windows
version, runtime, symbols, and available pages. Maps represent observations of a
running system rather than an atomic snapshot.

Heap rows include `segment_count` and `segment_bytes`, aggregated by heap index
from the same owning native heap map. Byte totals use 64-bit arithmetic and are
decimal strings. They sum recovered segment sizes, including zero-size records;
they do not measure allocated, free or committed bytes. Heap allocation views
remain separate.

Call `DMA::InitializePlugins()` to enable VFS providers in an already-connected
session. This preserves the device connection and process attachment; callers
should initialize providers once per session and retain any returned diagnostics.

[![Windows and Linux tests](https://github.com/chase-irql/StrataDMA/actions/workflows/tests.yml/badge.svg)](https://github.com/chase-irql/StrataDMA/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

A cross-platform C++17 wrapper around MemProcFS/VMMDLL for authorized
DMA-backed Windows memory inspection. Windows and 64-bit Linux hosts are
supported; the inspected target remains Windows. The repository vendors the
MemProcFS 5.16.5 and LeechCore headers plus Windows x64 import libraries.

Use it only on systems and processes you are authorized to inspect.

`DMA::GetProcesses()` and `FindProcessIds()` return running processes only,
excluding MemProcFS's retained terminated records. The `GetProcesses(output)`
overload preserves enumeration diagnostics. Low-level backend enumeration and
explicit `GetProcessInfo(pid)` remain available for forensic metadata.

## Highlights

- Configurable VMMDLL initialization with device URIs, memory maps, extra
  arguments, plugin initialization, fallback behavior, and readable errors.
- Attach by name or PID, process/module enumeration, monitoring, exit events,
  optional automatic re-attachment, expanded Windows process metadata, and
  native/WoW64 PEB inspection.
- Strict `DMAOperationResult`/`DMAResult<T>` memory APIs that report status,
  PID, address, flags, and requested/transferred byte counts.
- Explicit process and kernel memory contexts, per-frame coherent read caching,
  page prefetch gathers, and RAII scatter batches with per-request results.
- VAD/PTE memory-region maps and filters; module sections, imports, exports,
  PDB symbol lookup, type sizes, and child offsets.
- Bounded automatic CR3/DTB recovery with candidate diagnostics and rollback,
  plus structured physical-memory-map retrieval and VMMDLL-compatible export.
- Snapshots and byte-level diffs.
- Compiled signature patterns with full/nibble wildcards, captures, relative
  address transforms, alignment, nth-match selection, section scans, and
  optional parallel scanning; code-cave discovery cross-checks PE and live PTE
  read/write/execute permissions.
- Registry hive/key/value access and MemProcFS VFS directory/file access.
- PE32/PE32+ linear module dumping with bounds validation and IAT repair.
- Experimental keyboard, cursor, and configurable Xbox controller polling,
  including edge events, reconnect discovery, dead zones, and normalized axes.
- An injectable backend and hardware-free mock tests.

## Build and package

The existing Visual Studio solution builds the example executable:

```powershell
msbuild StrataDMA\StrataDMA.sln `
  /p:Configuration=Release /p:Platform=x64
```

The root CMake project provides the reusable static target
`StrataDMA::StrataDMA`, the example, an install layout, and mock tests:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix package
```

Options are `STRATA_DMA_BUILD_EXAMPLE`, `STRATA_DMA_BUILD_TESTS`, and
`STRATA_DMA_LINK_RUNTIME`. The last option is Linux-only in effect and defaults
to `ON`. Dynamic hosts that preload `leechcore.so` and `vmm.so` themselves may
turn it off; the final module must then allow and resolve the VMMDLL symbols.

At runtime, place `vmm.dll` and `leechcore.dll` beside the consuming executable.
Place `info.db` there as well when InfoDB/symbol functionality is used. The
repository contains import libraries, not the two runtime DLLs.

On Fedora, install the compiler and MemProcFS's USB dependency, unpack the
matching official MemProcFS Linux release, and point CMake at that directory:

```bash
sudo dnf install cmake gcc-c++ libusb1 ninja-build
export STRATA_DMA_RUNTIME_DIR=/opt/memprocfs
cmake -S . -B build -G Ninja \
  -DSTRATA_DMA_BUILD_EXAMPLE=ON \
  -DSTRATA_DMA_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The Linux runtime directory must contain `vmm.so` and `leechcore.so`; keep
`info.db` and any device or symbol plugins from the same MemProcFS release in
that directory. CMake links against the two shared libraries without copying
them into the install tree. At runtime, put the directory in the loader search
path or launch with `LD_LIBRARY_PATH="$STRATA_DMA_RUNTIME_DIR"`.

## Initialization and attachment

```cpp
#include "StrataDMA/DMA.hpp"

DMA dma;
DMAInitializationOptions options;
options.device = "fpga://algo=0";
options.memoryMapPath = "C:\\DMA\\mmap.txt";
options.fallbackWithoutMemoryMap = true;
options.initializePlugins = true; // required by VFS APIs; opt-in

const auto initialized = dma.Initialize(options);
if (!initialized) {
    std::cerr << initialized.message << '\n';
    return;
}

const auto attached = dma.Attach("target.exe");
if (!attached) {
    std::cerr << attached.message << '\n';
    return;
}
```

An empty memory-map path generates a fresh `%TEMP%\mmap.txt` through a
temporary `-waitinitialize -norefresh` device session, then reopens VMMDLL with
that map. If generation or mapped initialization fails,
`fallbackWithoutMemoryMap` controls whether StrataDMA retries directly. VMMDLL
is invoked with an empty `argv[0]` for compatibility with builds that otherwise
parse the program name as an invalid option.

For duplicate process names, use `FindProcessIds`, inspect each
`DMAProcessInfo`, and call `Attach(pid)`. `GetProcesses`, `GetModules`, and
`GetProcessInfo` expose the underlying discovery data without returning native
VMMDLL allocations.

## Process metadata, PEB, CR3, and physical ranges

`DMAProcessInfo` includes the DTB/user DTB, EPROCESS, native and WoW64 PEB
addresses, LUID, SID, integrity level, memory/system model, session, and names.
The stable leading fields of either PEB layout can be parsed without depending
on a private full Windows structure:

```cpp
auto process = dma.GetProcessInfo(); // PID 0 means current attachment
auto peb = dma.GetProcessEnvironmentBlock(); // prefers WoW64 PEB when present
if (peb) {
    std::cout << std::hex << peb.value.imageBaseAddress << '\n';
}
```

CR3 recovery may be used before attachment when an invalid DTB prevents module
discovery. It initializes the MemProcFS procinfo plugin, waits with a bounded
timeout, parses `\\misc\\procinfo\\dtb.txt`, tests applicable candidates against
the module and MZ header, and restores the original DTB if none work:

```cpp
auto attached = dma.AttachWithCR3Recovery("target.exe");
if (!attached) {
    std::cerr << attached.operation.message << '\n';
}

// Or recover explicitly after obtaining a PID:
auto recovered = dma.RecoverCR3(pid, "target.exe");
```

`DMACR3RecoveryOptions` controls the timeout, polling, candidate sources,
candidate limit, header validation, and rollback. Each attempted DTB has its
own structured result in the returned report. CR3 recovery needs `info.db` and
the symbol-support DLLs expected by the matching MemProcFS distribution.

Physical ranges can be consumed directly or exported in the two-column,
inclusive hexadecimal format accepted by VMMDLL's `-memmap` option:

```cpp
auto ranges = dma.GetPhysicalMemoryMap(true); // true refreshes the map first
auto exported = dma.ExportPhysicalMemoryMap("C:\\DMA\\mmap.txt");
```

## Results and memory contexts

Memory operations return structured results that retain failure details:

```cpp
auto health = dma.Read<int>(player + 0x100);
if (!health) {
    std::cerr << health.operation.message << " ("
              << health.operation.transferredBytes << "/"
              << health.operation.requestedBytes << ")\n";
}

auto process = dma.ProcessContext();
auto system = dma.KernelContext(4); // adds PROCESS_WITH_KERNELMEMORY
auto value = system.Read<uint64_t>(kernelAddress);
```

`DMAStatus` distinguishes invalid input, missing attachment, partial transfer,
not-found, unsupported backend operations, I/O errors, and backend failures.
Lifecycle, raw memory, address translation, prefetch, module-dump, and input
initialization calls use the same result model. Check the returned object and
read its `message`; there is no shared last-error state.

All target-memory reads are forced through `VMMDLL_FLAG_NOCACHE`, including
scatter batches, contexts, snapshots, dumps, scanners, and direct backend
reads. Additional caller flags remain additive, while conflicting cache-only
flags are removed.

```cpp
std::array<std::byte, 64> bytes{};
auto read = dma.ReadRaw(address, bytes.data(), bytes.size());
auto physical = dma.VirtualToPhysical(address);
auto chain = dma.ReadChain(root, { 0x10, 0x28 });
```

For a group of reads that should stay coherent during one update:

```cpp
auto frame = dma.CreateFrameContext();
auto gathered = frame.Gather({
    { player + 0x100, sizeof(int) },
    { player + 0x200, sizeof(float) * 3 }
});

// Reuses a containing gathered block instead of issuing another DMA read.
auto cachedHealth = frame.Read<int>(player + 0x100);
```

`Gather` deduplicates and prefetches involved 4 KiB pages before capturing the
requested blocks. A frame cache never silently refreshes; create a new frame or
call `Clear()` when the next update begins.

## Scatter batches

The scatter API owns its handle and is single-use:

```cpp
int health = 0;
float position[3]{};
auto batch = dma.CreateScatterBatch();
batch.AddRead(player + 0x100, health);
batch.AddRead(player + 0x200, position);

auto executed = batch.Execute();
for (const auto& request : executed.value) {
    if (!request.operation) {
        std::cerr << request.operation.message << '\n';
    }
}
```

Requests are split at 4 KiB boundaries and recombined into one result per user
request. Buffers must remain alive through `Execute`.

## Regions, modules, and symbols

```cpp
DMAMemoryRegionFilter filter;
filter.requireReadable = true;
filter.requireWritable = true;
filter.privateOnly = true;
auto writablePrivate = dma.GetMemoryRegions(filter);

auto sections = dma.GetModuleSections("target.exe");
auto imports = dma.GetModuleImports("target.exe");
auto exports = dma.GetModuleExports("target.exe");

auto pdb = dma.LoadModuleSymbols("target.exe");
if (pdb) {
    auto address = dma.ResolveSymbol(pdb.value, "SomeSymbol");
    auto size = dma.GetSymbolTypeSize(pdb.value, "SomeType");
    auto offset = dma.GetSymbolChildOffset(pdb.value, "SomeType", "Member");
}
```

VAD regions are enabled by default. Set `includePte` in the filter when PTE
regions are also needed; duplicate/overlapping entries are intentionally
preserved because they come from different VMMDLL maps.

## Snapshots and diffs

```cpp
auto before = dma.CaptureSnapshot(address, 0x1000);
// ...later...
auto after = dma.CaptureSnapshot(address, 0x1000);
auto changes = DMA::DiffSnapshots(before.value, after.value, 100);
```

Snapshots must have the same PID, base, and byte count. Each change contains
the absolute address, relative offset, old byte, and new byte.

## Advanced scanning

Compiled patterns accept `??`, full bytes, and nibble wildcards such as `A?`
or `?F`:

```cpp
auto pattern = DMA::CompilePattern("48 8B 05 ?? ?? ?? ??", {
    { "target", DMAScanCaptureKind::Rel32, 3, 4 }
});

DMAScanOptions scan;
scan.alignment = 1;
scan.parallel = true;
scan.transformFromFirstRelativeCapture = true;
auto matches = dma.ScanModuleAdvanced(
    "target.exe", pattern.value, scan, { ".text" });
```

`nthMatch` is one-based (`0` means all). `maxResults == 0` means unlimited.
Numeric relative captures contain the resolved absolute address; byte captures
retain their raw bytes.

Code-cave scanning defaults to sections that are RWX in the PE header and also
RWX in the live PTE map. It verifies actual memory bytes and accepts zero and
`0xCC` padding by default:

```cpp
DMACodeCaveOptions caves;
caves.alignment = 16;
caves.maxResults = 20;
auto found = dma.FindCodeCaves("target.exe", 128, caves);
for (const auto& cave : found.value.caves) {
    std::cout << std::hex << cave.address << " size=" << cave.size << '\n';
}
```

Padding bytes and read chunk size are configurable. Runtime permission checks
can be disabled explicitly, but keeping them enabled avoids treating PE flags
alone as proof that the live pages are writable and executable.

## Process monitoring

```cpp
dma.StartProcessMonitor("target.exe", 500, true,
    [](const DMAProcessEvent& event) {
        // Attached, Exited, Reattached, or Error.
    });
```

Call `StopProcessMonitor` before manually changing lifecycle state. Callbacks run
on the monitor thread and should return quickly. A re-attachment clears cached
modules, scans, scatter work, and input state just like a manual attachment.

## Registry and VFS

```cpp
auto hives = dma.GetRegistryHives();
auto keys = dma.EnumerateRegistryKeys("HKLM\\SOFTWARE");
auto value = dma.QueryRegistryValue(
    "HKLM\\SOFTWARE\\Vendor\\Product\\Setting");

auto root = dma.ListVfs("\\");
auto text = dma.ReadVfsFile("\\sys\\version.txt");
```

Registry values expose raw type/data plus `AsString`, `AsDword`, and `AsQword`
helpers. Raw hive writes and VFS writes are available but should be used only
when the underlying VMMDLL provider documents the path as writable. VFS calls
require successful plugin initialization.

## Input support

Keyboard edge events are consumed when read. Gamepad state has connection and
packet metadata, configurable signatures/offsets, reconnect discovery, button
edges, and normalized dead-zone-aware axes:

```cpp
auto keyboard = dma.InitKeyboard(10);
if (dma.IsKeyPressed(VK_SPACE)) { /* rising edge */ }

DMAGamepadConfig gamepad;
gamepad.pollIntervalMs = 4;
auto gamepadResult = dma.InitGamepad(gamepad);
if (gamepadResult) {
    auto state = dma.GetNormalizedGamepadState();
    if (dma.IsGamepadButtonJustPressed(XINPUT_GAMEPAD_A)) { /* edge */ }
}
```

These helpers depend on Windows kernel layouts, exports, symbols, and the
reverse-engineered `xboxgip.sys` layout. Treat their defaults as versioned
starting points and validate them on the target Windows build.

## Automated tests

All VMMDLL function calls are contained in `DMA.Backend.cpp`. Implement
`IVmmBackend` and pass a `shared_ptr` to `DMA` to test higher-level behavior
without hardware. Optional methods return `DMAStatus::Unsupported` unless the
mock overrides them.

CTest runs six hardware-independent executables. The suites cover lifecycle
and initialization errors, strict and partial memory transfers, pointer chains,
process/kernel contexts, monitoring, frame caching, RAII scatter,
patterns and captures, parallel/region/section scans, snapshots, symbols,
PE-dump reconstruction, CR3 recovery and rollback, native/WoW64 PEB parsing,
physical-map export, RWX cave scanning, registry, VFS, and unsupported backend
operations. Failure injection exercises prepare/execute, read/write, plugin,
timeout, malformed-data, and I/O paths. MSVC warnings are errors for the mock
test core. GitHub Actions runs Windows Debug/Release builds and a Fedora GCC
build.

```powershell
cmake -S . -B build -A x64 `
  -DSTRATA_DMA_BUILD_EXAMPLE=OFF `
  -DSTRATA_DMA_BUILD_TESTS=ON
cmake --build build --config Debug --parallel
ctest --test-dir build -C Debug --output-on-failure

# Run one labeled area while developing:
ctest --test-dir build -C Debug -L scatter --output-on-failure
```

The equivalent Linux label command omits the multi-config argument:

```bash
ctest --test-dir build -L scatter --output-on-failure
```

All native VMMDLL function calls are contained in `DMA.Backend.cpp`.
Implement `IVmmBackend` and pass a `shared_ptr` to `DMA` to add deterministic
fixtures without hardware. Optional methods return `DMAStatus::Unsupported`
unless the mock overrides them.

## Second-PC hardware smoke test

The example includes a finite, target-memory-read-only hardware check. Copy the
compiled example, matching VMMDLL/LeechCore runtime files, `info.db`, and symbol
support files from the same MemProcFS release to the acquisition PC, then run
on Windows:

```powershell
.\strata_dma_example.exe --hardware-test explorer.exe
```

On Linux, use the matching `.so` runtime and run:

```bash
LD_LIBRARY_PATH="$STRATA_DMA_RUNTIME_DIR" \
  ./strata_dma_example --hardware-test explorer.exe
```

It validates initialization/version discovery, the physical map, normal attach
with bounded CR3-recovery fallback, expanded process information, an MZ read,
scatter, module/section and VAD/PTE enumeration, then attempts PEB and VFS
checks. PEB and VFS are warnings because target choice and plugin availability
can make them legitimately unavailable. The runner never calls a target-memory
write API. Its console output is intended to be copied back when hardware-only
failures need diagnosis.

Hardware-dependent validation must still be done on the acquisition PC. A
useful order is initialization/version, process discovery, attach/module maps,
known reads, cross-page scatter, region/section scans, symbols, registry/VFS,
then input support. Test writes and DTB changes last.

## License

StrataDMA is free and open-source software licensed under the
[GNU Affero General Public License version 3](LICENSE). The vendored MemProcFS
and LeechCore components retain their upstream AGPLv3 and GPLv3 licenses; see
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) for versions, file scope, and
source links.

## String extraction

`DMA::ExtractStrings(bytes, options, baseAddress, finalChunk)` extracts printable
ASCII or word-aligned Unicode UTF-16LE strings, including surrogate pairs.
Matches retain exact addresses, byte lengths and character counts, with previews
up to 256 characters. Strings are split at `maximumLength` (up to 4096 characters).
The optional contains filter applies to each piece; case-insensitive matching
folds ASCII only. Result pages contain at most 4096 matches.

For streaming, use `finalChunk=false` and retain bytes beginning at
`result.value.consumedBytes`. Append the next contiguous block to that tail and
advance the base by the consumed count. With a limited result page, resume at the
same consumed offset. Flush with `finalChunk=true` at the end of a readable span;
never join bytes across unreadable gaps. This static API requires no device.

## Pointer-chain traces

`dma.ProcessContext(pid).TraceChain(base, offsets, pointerWidth)` returns owning
per-hop records (`address`, `pointer`, `offset`, `next`, `operation`) and the
final address. Use `KernelContext(sessionPid)` for kernel mappings. Pointer width
is 4 or 8 bytes; offsets are unsigned and each step dereferences before adding
its offset. Traces allow 1–64 steps, stop on null pointers, overflow or failed
reads, and retain the failed hop and its transfer diagnostics. They never change
the primary attachment or write target memory.

## Forensic timeline pages

`ReadTimeline(DMATimelineQuery)` reads completed MemProcFS text timelines through
the existing VFS backend without changing forensic mode or attachment. Initialize
plugins first. The default source is `/forensic/timeline/timeline_all.txt`; other
`timeline_*.txt` sources are supported. A stable memory image can be initialized
with `extraArguments = { "-forensic", "2" }` and `initializePlugins = true` to
prepare timelines using temporary forensic storage. Preparation is not started by
the reader itself; unavailable files remain explicit backend failures.

Queries accept inclusive `from`/`until` UTC timestamps (`YYYY-MM-DDTHH:mm:ssZ`),
action, PID and case-insensitive ASCII text filters. Pages preserve file order,
exact 64-bit addresses and source byte offsets. Resume using `nextOffset`; offsets
must follow complete lines. VFS-reported length defines EOF; reads never probe
beyond it, and premature short reads remain partial-transfer errors. The default budget is 1 MiB/100 matches, bounded to
4 MiB/4,096 matches. Records may span read blocks; malformed UTF-8, timestamps or
numeric fields are counted separately. Headers are counted separately from events.
Lines over 64 KiB fail explicitly. `scannedBytes` counts complete source bytes
examined; `readBytes` also includes provider read-ahead. Neither unavailable data
nor malformed records are turned into fabricated events. Timestamps have the
second precision provided by the text source; artifacts do not establish a full
activity history or the present validity of an address.

## Saved mapped-image inspection

`DMA::InspectLoadedImage(path, missingRanges)` is a static, hardware-independent API
for PE32/PE32+ images stored in mapped/RVA order. It returns machine, section count,
header image version, raw COFF timestamp/checksum, image size, entry RVA, preferred
base, and sorted x86 HIGHLOW/x64 DIR64 relocation fields with byte widths. ABSOLUTE
padding is ignored. It does not initialize, attach, write or load a DMA runtime.

Supply sorted, non-overlapping `DMAImageGap` offsets/sizes for unavailable source
bytes. Missing headers fail analysis; missing/unsupported relocation data retains
identity but sets `relocationsComplete=false` with `relocationMessage` and no usable
plan. Duplicate/overlapping/out-of-image targets are rejected. Limits are 512 MiB
source size, 1 MiB PE header offset, 8 MiB relocation directory, 262,144 fields and
131,072 gaps. Discarded relocation sections may make normalization unavailable.
Header image versions are not file/product versions; reproducible COFF timestamps
are not necessarily dates. No build authenticity or tampering conclusion is inferred.

## Source layout

- `DMA.hpp`: main public facade.
- `DMA.Types.*`: result and data-transfer types.
- `DMA.Backend.*`: injectable interface and native VMMDLL adapter.
- `DMA.Context.*`: process/kernel contexts, frame cache, and RAII scatter.
- `DMA.Advanced.cpp`: results, maps, symbols, snapshots, monitoring, registry,
  and VFS facade methods.
- `DMA.Timeline.cpp`: bounded forensic timeline parsing and filtering through VFS.
- `DMA.Scanner.cpp`: compiled-pattern and module scanners.
- `DMA.System.cpp`: process/PEB metadata, CR3 recovery, physical maps, and
  permission-aware code-cave discovery.
- `DMA.Module.cpp`: PE reconstruction.
- `DMA.Image.cpp`: bounded saved mapped-image PE identity and relocation inspection.
- `DMA.Input.cpp`: keyboard, cursor, and gamepad support.
