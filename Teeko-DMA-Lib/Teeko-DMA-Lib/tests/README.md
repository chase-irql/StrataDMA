# Test suite

These tests exercise the public `DMA.hpp` API against `MockVmmBackend`; they do
not load `vmm.dll`, contact a DMA device, or access another process.

| Executable | Primary coverage |
| --- | --- |
| `teeko_dma_lifecycle_tests` | initialization, attachment, metadata, reads/writes, strings, chains, contexts, monitoring |
| `teeko_dma_scatter_tests` | RAII and legacy scatter, cross-page splitting, frame gathering and caching, partial/failure paths |
| `teeko_dma_scanner_tests` | pattern parsing, captures, parallel scans, regions, sections, symbols, snapshots, RWX caves |
| `teeko_dma_system_tests` | native/WoW64 PEB parsing, CR3 recovery/rollback/timeout, physical maps and export |
| `teeko_dma_registry_vfs_tests` | registry conversion/enumeration/raw hive access, VFS list/read/write/limits |
| `teeko_dma_module_tests` | PE32+ layout reconstruction, IAT repair, malformed headers, partial dumps and file errors |
| `teeko_dma_pattern_tests` | standalone legacy pattern matcher |

Configure, build, and run from the repository root:

```powershell
cmake -S . -B build -A x64 `
  -DTEEKO_DMA_BUILD_EXAMPLE=OFF `
  -DTEEKO_DMA_BUILD_TESTS=ON
cmake --build build --config Debug --parallel
ctest --test-dir build -C Debug --output-on-failure
```

New high-level behavior should generally receive a test in the closest suite.
Extend `MockVmmBackend` only when the public behavior needs additional backend
state or a failure-injection switch. Each test case receives a fresh backend,
so cases must not depend on execution order.
