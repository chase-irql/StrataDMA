#include "DMA.Backend.hpp"
#include "DMA.Inspection.Internal.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace {
std::string N(uint64_t n) { return std::to_string(n); }
std::string A(uint64_t n) { std::ostringstream s; s << "0x" << std::hex << n; return s.str(); }
std::string S(const char* s) { return s ? s : ""; }
std::string B(bool b) { return b ? "true" : "false"; }
std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
class InspectionRows {
    const DMAInspectionQuery& query;
    DMAInspectionTable& table;
    std::string filter;
public:
    InspectionRows(const DMAInspectionQuery& q, DMAInspectionTable& t) : query(q), table(t), filter(Lower(q.filter)) {
        table = {}; table.columns = DMAInspectionColumns(q.kind);
    }
    void Add(std::initializer_list<std::string> cells) {
        if (cells.size() != table.columns.size()) throw std::logic_error("Inspection column mismatch.");
        if (!filter.empty() && std::none_of(cells.begin(), cells.end(), [&](const auto& s) { return Lower(s).find(filter) != std::string::npos; })) return;
        const size_t index = table.total++;
        if (index >= query.offset && table.rows.size() < query.limit) table.rows.emplace_back(cells);
    }
};
template<class Map, class Load, class Fill>
DMAOperationResult CopyInspectionMap(InspectionRows& rows, DWORD version, Load load, Fill fill) {
    Map* raw = nullptr;
    const bool loaded = load(&raw) != FALSE;
    const auto freeMap = [](Map* p) { if (p) VMMDLL_MemFree(p); };
    std::unique_ptr<Map, decltype(freeMap)> owner(raw, freeMap);
    if (!loaded || !raw) return DMAOperationResult::Failure(DMAStatus::BackendError, "Inspection map is unavailable for this target or runtime.");
    if (raw->dwVersion != version) return DMAOperationResult::Failure(DMAStatus::Unsupported, "Inspection map version does not match the runtime headers.");
    fill(*raw, rows);
    return DMAOperationResult::Success();
}
}

DMAOperationResult VmmdllBackend::Inspect(const DMAInspectionQuery& q, DMAInspectionTable& table) const
{
    if (!handle_) return DMAOperationResult::Failure(DMAStatus::NotInitialized, "VMMDLL is not initialized.");
    InspectionRows rows(q, table);
    if (q.kind == "threads") return CopyInspectionMap<VMMDLL_MAP_THREAD>(rows, VMMDLL_MAP_THREAD_VERSION,
        [&](auto p) { return VMMDLL_Map_GetThread(handle_, q.pid, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                out.Add({N(e.dwTID),N(e.dwPID),N(e.bState),B(e.bRunning != 0),N(e.bPriority),N(e.bBasePriority),A(e.vaStartAddress),A(e.vaWin32StartAddress),A(e.vaETHREAD),A(e.vaTeb),A(e.vaStackBaseUser),A(e.vaStackLimitUser),A(e.vaStackBaseKernel),A(e.vaStackLimitKernel),A(e.vaRIP),A(e.vaRSP),A(e.ftCreateTime),A(e.ftExitTime),N(e.dwUserTime),N(e.dwKernelTime),N(e.bSuspendCount),N(e.bWaitReason)});
            }
        });
    if (q.kind == "callstack") return CopyInspectionMap<VMMDLL_MAP_THREAD_CALLSTACK>(rows, VMMDLL_MAP_THREAD_CALLSTACK_VERSION,
        [&](auto p) { return VMMDLL_Map_GetThread_CallstackU(handle_, q.pid, static_cast<DWORD>(q.selector), 0, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                out.Add({N(e.i),A(e.vaRetAddr),A(e.vaRSP),A(e.vaBaseSP),S(e.uszModule),S(e.uszFunction),N(e.cbDisplacement),B(e.fRegPresent != FALSE)});
            }
        });
    if (q.kind == "handles") return CopyInspectionMap<VMMDLL_MAP_HANDLE>(rows, VMMDLL_MAP_HANDLE_VERSION,
        [&](auto p) { return VMMDLL_Map_GetHandleU(handle_, q.pid, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                out.Add({A(e.dwHandle),N(e.dwPID),S(e.uszType),S(e.uszText),A(e.vaObject),A(e.dwGrantedAccess),N(e.qwHandleCount),N(e.qwPointerCount),A(e.vaSecurityDescriptor)});
            }
        });
    if (q.kind == "heaps" || q.kind == "heap-segments") return CopyInspectionMap<VMMDLL_MAP_HEAP>(rows, VMMDLL_MAP_HEAP_VERSION,
        [&](auto p) { return VMMDLL_Map_GetHeap(handle_, q.pid, p); }, [&](const auto& map, auto& out) {
            if (q.kind == "heaps") {
                auto totals = StrataDetail::HeapSegmentTotals(map.pSegments, map.cSegments);
                for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i]; const auto& total = totals[e.iHeap];
                    out.Add({A(e.va),N(e.dwHeapNum),N(e.iHeap),N(e.tp),B(e.f32 != FALSE),N(total.first),N(total.second)});
                }
            } else {
                for (DWORD i = 0; i < map.cSegments; ++i) { const auto& e = map.pSegments[i]; out.Add({A(e.va),N(e.cb),N(e.iHeap),N(e.tp)}); }
            }
        });
    if (q.kind == "heap-allocations") return CopyInspectionMap<VMMDLL_MAP_HEAPALLOC>(rows, VMMDLL_MAP_HEAPALLOC_VERSION,
        [&](auto p) { return VMMDLL_Map_GetHeapAlloc(handle_, q.pid, q.selector, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i]; out.Add({A(e.va),N(e.cb),N(e.tp)}); }
        });
    if (q.kind == "network") return CopyInspectionMap<VMMDLL_MAP_NET>(rows, VMMDLL_MAP_NET_VERSION,
        [&](auto p) { return VMMDLL_Map_GetNetU(handle_, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                out.Add({N(e.dwPID),N(e.dwState),N(e.AF),S(e.Src.uszText),N(e.Src.port),S(e.Dst.uszText),N(e.Dst.port),B(e.Src.fValid != FALSE),B(e.Dst.fValid != FALSE),A(e.vaObj),A(e.ftTime),S(e.uszText)});
            }
        });
    if (q.kind == "services") return CopyInspectionMap<VMMDLL_MAP_SERVICE>(rows, VMMDLL_MAP_SERVICE_VERSION,
        [&](auto p) { return VMMDLL_Map_GetServicesU(handle_, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                out.Add({S(e.uszServiceName),S(e.uszDisplayName),N(e.dwPID),N(e.ServiceStatus.dwCurrentState),N(e.dwStartType),N(e.ServiceStatus.dwServiceType),S(e.uszPath),S(e.uszImagePath),S(e.uszUserAcct),S(e.uszUserTp),A(e.vaObj),N(e.ServiceStatus.dwWin32ExitCode)});
            }
        });
    if (q.kind == "drivers" || q.kind == "driver-dispatch") return CopyInspectionMap<VMMDLL_MAP_KDRIVER>(rows, VMMDLL_MAP_KDRIVER_VERSION,
        [&](auto p) { return VMMDLL_Map_GetKDriverU(handle_, p); }, [&](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                if (q.kind == "drivers") out.Add({S(e.uszName),S(e.uszPath),S(e.uszServiceKeyName),A(e.va),A(e.vaDriverStart),N(e.cbDriverSize),A(e.vaDeviceObject)});
                else if (q.selector == 0 || q.selector == e.va) for (size_t j = 0; j < 28; ++j) out.Add({S(e.uszName),A(e.va),N(j),A(e.MajorFunction[j])});
            }
        });
    if (q.kind == "devices") return CopyInspectionMap<VMMDLL_MAP_KDEVICE>(rows, VMMDLL_MAP_KDEVICE_VERSION,
        [&](auto p) { return VMMDLL_Map_GetKDeviceU(handle_, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i]; out.Add({A(e.va),S(e.uszDeviceType),N(e.dwDeviceType),N(e.iDepth),A(e.vaDriverObject),A(e.vaAttachedDevice),A(e.vaFileSystemDevice),S(e.uszVolumeInfo)}); }
        });
    if (q.kind == "objects") return CopyInspectionMap<VMMDLL_MAP_KOBJECT>(rows, VMMDLL_MAP_KOBJECT_VERSION,
        [&](auto p) { return VMMDLL_Map_GetKObjectU(handle_, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i]; out.Add({S(e.uszName),S(e.uszType),A(e.va),A(e.vaParent),N(e.cvaChild)}); }
        });
    if (q.kind == "pool") return CopyInspectionMap<VMMDLL_MAP_POOL>(rows, VMMDLL_MAP_POOL_VERSION,
        [&](auto p) { return VMMDLL_Map_GetPool(handle_, p, VMMDLL_POOLMAP_FLAG_ALL); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i];
                std::string tag(e.szTag, 4); for (auto& c : tag) if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) c = '.';
                out.Add({tag,A(e.va),N(e.cb),N(e.tpPool),N(e.tpSS),B(e.fAlloc != 0)});
            }
        });
    if (q.kind == "unloaded-modules" || q.kind == "kernel-unloaded-modules") return CopyInspectionMap<VMMDLL_MAP_UNLOADEDMODULE>(rows, VMMDLL_MAP_UNLOADEDMODULE_VERSION,
        [&](auto p) { return VMMDLL_Map_GetUnloadedModuleU(handle_, q.kind == "kernel-unloaded-modules" ? 4 : q.pid, p); }, [](const auto& map, auto& out) {
            for (DWORD i = 0; i < map.cMap; ++i) { const auto& e = map.pMap[i]; out.Add({S(e.uszText),A(e.vaBase),N(e.cbImageSize),B(e.fWoW64 != FALSE),A(e.dwCheckSum),N(e.dwTimeDateStamp),A(e.ftUnload)}); }
        });
    return DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Unknown inspection kind.");
}
