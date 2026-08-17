
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <utility>

namespace {
constexpr uint64_t kPageMask = 0xFFF;
constexpr size_t kPageSize = 0x1000;
constexpr size_t kHeapChunkSize = 0x1000000;

template <typename T>
T LoadUnaligned(const uint8_t* source)
{
    T value{};
    std::memcpy(&value, source, sizeof(value));
    return value;
}

}

void DMA::SetLastError(std::string message)
{
    std::lock_guard<std::mutex> lock(errorMutex);
    lastError = std::move(message);
}

std::string DMA::GetLastError() const
{
    std::lock_guard<std::mutex> lock(errorMutex);
    return lastError;
}

std::string DMA::NormalizeName(const std::string& name)
{
    std::string normalized = name;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return normalized;
}

void DMA::StartKeyboardThread(int pollMs)
{
    StopKeyboardThread();
    kb_running.store(true);
    kb_thread = std::thread(&DMA::KeyboardThread, this, std::max(1, pollMs));
}

void DMA::StopKeyboardThread()
{
    kb_running.store(false);
    if (kb_thread.joinable())
        kb_thread.join();
}

void DMA::StopGamepadThread()
{
    gamepad_running.store(false);
    if (gamepad_thread.joinable())
        gamepad_thread.join();
}

void DMA::KeyboardThread(int poll_ms) {
    while (kb_running.load()) {
        if (IsInitialized() && gafAsyncKeyStateExport) {
            uint8_t tmp[64] = { 0 };
            DWORD bytesRead = 0;
            if (backend->ReadMemory(
                win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                gafAsyncKeyStateExport,
                tmp, 64, VMMDLL_FLAG_NOCACHE, bytesRead) && bytesRead == 64) {
                std::lock_guard<std::mutex> lock(kb_mutex);
                for (int i = 0; i < 64; i++) {
                    uint8_t became_set = tmp[i] & ~state_bitmap[i]; // bits that turned on
                    uint8_t became_clear = state_bitmap[i] & ~tmp[i]; // bits that turned off
                    pressed_bitmap[i] |= became_set;
                    released_bitmap[i] |= became_clear;
                }
                std::memcpy(state_bitmap.data(), tmp, state_bitmap.size());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }
}

void DMA::GamepadThread(int poll_ms) {
    DWORD sysPid = 4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;

    while (gamepad_running.load()) {
        if (IsInitialized() && active_controller_address) {
            std::vector<uint8_t> buffer(std::max<size_t>(16,
                gamepadConfig.stateSize), 0);
            DWORD br = 0;

            if (backend->ReadMemory(sysPid,
                active_controller_address + gamepadConfig.stateOffset,
                buffer.data(), static_cast<DWORD>(buffer.size()),
                VMMDLL_FLAG_NOCACHE, br) && br == buffer.size()) {

                uint16_t xinput_buttons = 0;
                uint8_t b1 = buffer[1];
                uint8_t b2 = buffer[2];

                // --- Translate Byte 1 (Face Buttons & System) ---
                if (b1 & 0x04) xinput_buttons |= XINPUT_GAMEPAD_START;
                if (b1 & 0x08) xinput_buttons |= XINPUT_GAMEPAD_BACK;
                if (b1 & 0x10) xinput_buttons |= XINPUT_GAMEPAD_A;
                if (b1 & 0x20) xinput_buttons |= XINPUT_GAMEPAD_B;
                if (b1 & 0x40) xinput_buttons |= XINPUT_GAMEPAD_X;
                if (b1 & 0x80) xinput_buttons |= XINPUT_GAMEPAD_Y;

                // --- Translate Byte 2 (D-Pad & Bumpers & Clicks) ---
                if (b2 & 0x01) xinput_buttons |= XINPUT_GAMEPAD_DPAD_UP;
                if (b2 & 0x02) xinput_buttons |= XINPUT_GAMEPAD_DPAD_DOWN;
                if (b2 & 0x04) xinput_buttons |= XINPUT_GAMEPAD_DPAD_LEFT;
                if (b2 & 0x08) xinput_buttons |= XINPUT_GAMEPAD_DPAD_RIGHT;
                if (b2 & 0x10) xinput_buttons |= XINPUT_GAMEPAD_LEFT_SHOULDER;
                if (b2 & 0x20) xinput_buttons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;
                if (b2 & 0x40) xinput_buttons |= XINPUT_GAMEPAD_LEFT_THUMB;
                if (b2 & 0x80) xinput_buttons |= XINPUT_GAMEPAD_RIGHT_THUMB;

                // --- Translate 10-bit Triggers to 8-bit (0-255) ---
                // Read 2 bytes, mask off garbage bits, and divide by 4 (shift right by 2)
                const uint16_t rawLT = LoadUnaligned<uint16_t>(&buffer[3]) & 0x03FF;
                const uint16_t rawRT = LoadUnaligned<uint16_t>(&buffer[5]) & 0x03FF;

                std::lock_guard<std::mutex> lock(gamepad_mutex);

                pressedGamepadButtons |= static_cast<uint16_t>(
                    xinput_buttons & ~previousGamepadButtons);
                releasedGamepadButtons |= static_cast<uint16_t>(
                    previousGamepadButtons & ~xinput_buttons);
                previousGamepadButtons = xinput_buttons;
                currentGamepadState.buttons = xinput_buttons;
                currentGamepadState.leftTrigger = static_cast<uint8_t>(rawLT / 4);
                currentGamepadState.rightTrigger = static_cast<uint8_t>(rawRT / 4);

                // --- Map the 16-bit Thumbsticks ---
                currentGamepadState.thumbLX = LoadUnaligned<int16_t>(&buffer[7]);
                currentGamepadState.thumbLY = LoadUnaligned<int16_t>(&buffer[9]);
                currentGamepadState.thumbRX = LoadUnaligned<int16_t>(&buffer[11]);
                currentGamepadState.thumbRY = LoadUnaligned<int16_t>(&buffer[13]);
                currentGamepadState.connected = true;
                ++currentGamepadState.packetNumber;
            }
            else {
                std::lock_guard<std::mutex> lock(gamepad_mutex);
                currentGamepadState.connected = false;
                active_controller_address = 0;
            }
        }
        else if (IsInitialized() && gamepadArrayStart != 0) {
            for (size_t slot = 0; slot < gamepadConfig.slotCount; ++slot) {
                const uint64_t address = gamepadArrayStart +
                    slot * gamepadConfig.slotStride;
                uint8_t active = 0;
                DWORD transferred = 0;
                if (backend->ReadMemory(sysPid,
                    address + gamepadConfig.activeOffset, &active, 1,
                    VMMDLL_FLAG_NOCACHE, transferred) && transferred == 1 &&
                    active == 1) {
                    active_controller_address = address;
                    break;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }
}

bool DMA::CacheModule(const std::string& moduleName) {
    if (!IsAttached())
        return false;
    DMAModuleInfo module;
    if (backend->GetModule(targetPID, moduleName, module)) {
        moduleCache[NormalizeName(moduleName)] = { module.baseAddress,
                                   module.imageSize };
        return true;
    }
    return false;
}

std::vector<HeapRegion> DMA::GetHeapRegions() {
    std::vector<HeapRegion> heaps;
    if (!IsAttached())
        return heaps;
    std::vector<DMAMemoryRegion> regions;
    if (!backend->GetMemoryRegions(targetPID, true, false, regions))
        return heaps;
    for (const auto& region : regions) {
        if (!region.privateMemory || region.image || region.mappedFile ||
            region.teb || region.stack || region.size == 0 ||
            region.size > 0x80000000) {
            continue;
        }
        heaps.push_back({ region.baseAddress, region.EndAddress() });
    }
    return heaps;
}

DMA::DMA(std::shared_ptr<IVmmBackend> customBackend)
    : backend(customBackend ? std::move(customBackend) : CreateVmmdllBackend())
{
}

DMA::~DMA() { Disconnect(); }

/// <summary>
/// Initializes the VMMDLL interface with default FPGA settings.
/// </summary>
/// <returns>True if initialization was successful, false otherwise.</returns>
bool DMA::Initialize(bool memMap, bool debug)
{
    DMAInitializationOptions options;
    options.useMemoryMap = memMap;
    options.debug = debug;
    return Initialize(options);
}

bool DMA::Initialize(const DMAInitializationOptions& options)
{
    Disconnect();
    SetLastError({});

    if (options.device.empty()) {
        SetLastError("The MemProcFS device URI cannot be empty.");
        return false;
    }

    std::string memoryMapPath = options.memoryMapPath;
    if (options.useMemoryMap && memoryMapPath.empty()) {
        try {
            memoryMapPath = (std::filesystem::temp_directory_path() / "mmap.txt").string();
        }
        catch (const std::exception& exception) {
            if (!options.fallbackWithoutMemoryMap) {
                SetLastError(std::string("Unable to resolve the temporary memory-map path: ") +
                    exception.what());
                return false;
            }
        }
    }

    bool memoryMapAvailable = options.useMemoryMap && memoryMapPath == "auto";
    if (options.useMemoryMap && !memoryMapPath.empty() && memoryMapPath != "auto") {
        std::error_code error;
        memoryMapAvailable = std::filesystem::exists(memoryMapPath, error) && !error;
    }
    if (options.useMemoryMap && !memoryMapAvailable &&
        !options.fallbackWithoutMemoryMap) {
        SetLastError("The requested memory-map file does not exist: " + memoryMapPath);
        return false;
    }

    auto attemptInitialize = [&](bool includeMemoryMap) {
        std::vector<std::string> arguments = {
            "Teeko-DMA-Lib", "-device", options.device
        };
        if (options.debug) {
            arguments.push_back("-v");
            arguments.push_back("-printf");
        }
        if (options.waitForInitialization)
            arguments.push_back("-waitinitialize");
        if (includeMemoryMap) {
            arguments.push_back("-memmap");
            arguments.push_back(memoryMapPath);
        }
        arguments.insert(arguments.end(), options.extraArguments.begin(),
            options.extraArguments.end());

        const auto result = backend->Initialize(arguments);
        hVMM = backend->NativeHandle();
        if (!result) {
            SetLastError(result.message);
            return false;
        }
        if (options.initializePlugins) {
            const auto plugins = backend->InitializePlugins();
            if (!plugins) {
                SetLastError(plugins.message);
                backend->Close();
                hVMM = nullptr;
                return false;
            }
        }
        return true;
    };

    if (memoryMapAvailable && attemptInitialize(true))
        return true;

    if (memoryMapAvailable && options.fallbackWithoutMemoryMap) {
        backend->Close();
        hVMM = nullptr;
        return attemptInitialize(false);
    }

    return !options.useMemoryMap || options.fallbackWithoutMemoryMap
        ? attemptInitialize(false)
        : false;
}

/// <summary>
/// Closes all active VMMDLL handles and cleans up resources.
/// </summary>
void DMA::Disconnect() {
    StopProcessMonitor();
    StopKeyboardThread();
    StopGamepadThread();
    ResetAttachmentState();
    if (backend)
        backend->Close();
    hVMM = nullptr;
}

void DMA::ResetAttachmentState()
{
    legacyScatter.reset();
    scatterReadStatuses.clear();
    scatterHasWrites = false;
    targetPID = 0;
    mainModuleBase = 0;
    attachedMainModuleName.clear();
    moduleCache.clear();
    queuedModuleScans.clear();
    scanResults.clear();
    scanResultsMulti.clear();
    gafAsyncKeyStateExport = 0;
    gptCursorAsyncExport = 0;
    win_logon_pid = 0;
    active_controller_address = 0;
    gamepadArrayStart = 0;
    {
        std::lock_guard<std::mutex> lock(kb_mutex);
        state_bitmap.fill(0);
        pressed_bitmap.fill(0);
        released_bitmap.fill(0);
    }
    {
        std::lock_guard<std::mutex> lock(gamepad_mutex);
        currentGamepadState = {};
    }
}

void DMA::Detach()
{
    StopKeyboardThread();
    StopGamepadThread();
    ResetAttachmentState();
}

bool DMA::RecreateScatterHandle()
{
    legacyScatter.reset();
    scatterReadStatuses.clear();
    scatterHasWrites = false;
    if (!IsInitialized() || targetPID == 0)
        return false;
    legacyScatter = backend->CreateScatter(targetPID, scatterFlags);
    if (!legacyScatter)
        SetLastError("VMMDLL_Scatter_Initialize failed.");
    return legacyScatter != nullptr;
}

/// <summary>
/// Attempts to find and attach to a target process by name.
/// </summary>
/// <param name="processName">Name of the process (e.g., "game.exe").</param>
/// <returns>True if process found and scatter handle initialized.</returns>
bool DMA::Attach(const std::string& processName) {
    if (!IsInitialized()) {
        SetLastError("Initialize DMA before attaching to a process.");
        return false;
    }
    DWORD pid = 0;
    const auto result = backend->FindPid(processName, pid);
    if (!result) {
        SetLastError("Process not found: " + processName);
        return false;
    }
    return Attach(pid, processName);
}

bool DMA::Attach(DWORD pid, const std::string& mainModuleName)
{
    if (!IsInitialized() || pid == 0) {
        SetLastError("A valid VMM handle and non-zero PID are required.");
        return false;
    }

    Detach();
    targetPID = pid;

    DMAModuleInfo module;
    if (!backend->GetModule(targetPID, mainModuleName, module)) {
        SetLastError("Unable to resolve the process main module.");
        ResetAttachmentState();
        return false;
    }

    mainModuleBase = module.baseAddress;
    const std::string resolvedName = module.name.empty() ? mainModuleName : module.name;
    attachedMainModuleName = resolvedName;
    moduleCache[NormalizeName(resolvedName)] = { module.baseAddress, module.imageSize };
    if (!mainModuleName.empty())
        moduleCache[NormalizeName(mainModuleName)] = { module.baseAddress, module.imageSize };

    if (!RecreateScatterHandle()) {
        ResetAttachmentState();
        return false;
    }
    SetLastError({});
    return true;
}

DMAVersionInfo DMA::GetVmmVersion() const
{
    DMAVersionInfo version;
    if (!IsInitialized())
        return version;
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, version.major);
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, version.minor);
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, version.revision);
    return version;
}

uint32_t DMA::GetWindowsBuild() const
{
    uint64_t build = 0;
    if (!IsInitialized() || !backend->ConfigGet(VMMDLL_OPT_WIN_VERSION_BUILD, build))
        return 0;
    return static_cast<uint32_t>(build);
}

bool DMA::GetProcessInfo(DWORD pid, DMAProcessInfo& info) const
{
    info = {};
    if (!IsInitialized() || pid == 0)
        return false;
    return static_cast<bool>(backend->GetProcess(pid, info));
}

std::vector<DMAProcessInfo> DMA::GetProcesses() const
{
    std::vector<DMAProcessInfo> result;
    if (!IsInitialized())
        return result;
    backend->GetProcesses(result);
    return result;
}

std::vector<DWORD> DMA::FindProcessIds(const std::string& processName) const
{
    std::vector<DWORD> result;
    const std::string requested = NormalizeName(processName);
    if (requested.empty())
        return result;
    for (const auto& process : GetProcesses()) {
        if (NormalizeName(process.name) == requested ||
            NormalizeName(process.longName) == requested) {
            result.push_back(process.pid);
        }
    }
    return result;
}

bool DMA::RefreshProcess()
{
    if (!IsAttached())
        return false;
    const bool success = static_cast<bool>(backend->ConfigSet(
        VMMDLL_OPT_REFRESH_SPECIFIC_PROCESS | targetPID, 1));
    if (success)
        moduleCache.clear();
    else
        SetLastError("MemProcFS failed to refresh the attached process.");
    return success;
}

/// <summary>
/// Verifies if the current Directory Table Base (DTB/CR3) is valid.
/// Checks for the "MZ" header at the main module base.
/// </summary>
/// <returns>True if the DTB is valid.</returns>
bool DMA::IsCR3Valid() {
    if (!IsAttached() || mainModuleBase == 0)
        return false;

    // Use NOCACHE to ensure we are querying the physical memory state right now
    uint16_t magic = Read<uint16_t>(mainModuleBase);
    return magic == 0x5A4D; // 0x5A4D is 'MZ'
}

/// <summary>
/// Manually sets the process Directory Table Base (DTB/CR3).
/// Useful for bypassing anti-cheats that scramble the DTB.
/// </summary>
/// <param name="dtb">The new Directory Table Base.</param>
bool DMA::SetCR3(uint64_t dtb) {
    if (!IsAttached())
        return false;

    // VMMDLL_OPT_PROCESS_DTB expects the PID in the lower DWORD
    uint64_t option = VMMDLL_OPT_PROCESS_DTB | targetPID;
    return static_cast<bool>(backend->ConfigSet(option, dtb));
}

/// <summary>
/// Flushes the internal VMMDLL Transport Lookaside Buffer (TLB) and memory
/// cache. Use this if memory reads fail due to anti-cheat memory swapping.
/// </summary>
bool DMA::ClearCache() {
    if (!IsInitialized())
        return false;
    const bool tlb = static_cast<bool>(backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_TLB, 1));
    const bool mem = static_cast<bool>(backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_MEM, 1));
    return tlb && mem;
}

/// <summary>
/// Retrieves the base address of a module in the target process.
/// Caches the result to minimize VMMDLL calls.
/// </summary>
/// <param name="moduleName">Name of the module (e.g.,
/// "kernel32.dll").</param> <returns>Base address of the module, or 0 if not
/// found.</returns>
uint64_t DMA::GetModuleBase(const std::string& moduleName) {
    const auto key = NormalizeName(moduleName);
    if (moduleCache.find(key) == moduleCache.end())
        if (!CacheModule(moduleName))
            return 0;
    return moduleCache.at(key).baseAddress;
}

/// <summary>
/// Retrieves the size of a module in bytes.
/// </summary>
/// <param name="moduleName">Name of the module.</param>
/// <returns>Size of the module, or 0 if not found.</returns>
uint32_t DMA::GetModuleSize(const std::string& moduleName) {
    const auto key = NormalizeName(moduleName);
    if (moduleCache.find(key) == moduleCache.end())
        if (!CacheModule(moduleName))
            return 0;
    return moduleCache.at(key).size;
}

void DMA::ClearModuleCache()
{
    moduleCache.clear();
}

std::vector<DMAModuleInfo> DMA::GetModules(bool refresh)
{
    std::vector<DMAModuleInfo> result;
    if (!IsAttached())
        return result;
    if (refresh)
        RefreshProcess();

    if (!backend->GetModules(targetPID, result))
        return result;
    for (const auto& info : result)
        moduleCache[NormalizeName(info.name)] = { info.baseAddress, info.imageSize };
    return result;
}

/// <summary>
/// Reads raw memory from the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="buffer">Local buffer to store the read data.</param>
/// <param name="size">Number of bytes to read.</param>
/// <param name="flags">VMMDLL flags (e.g., VMMDLL_FLAG_NOCACHE).</param>
/// <returns>True if the read was successful.</returns>
bool DMA::ReadRaw(uint64_t address, void* buffer, size_t size, ULONG64 flags) {
    return ReadRawEx(targetPID, address, buffer, size, flags);
}

bool DMA::ReadRawEx(DWORD pid, uint64_t address, void* buffer, size_t size,
    ULONG64 flags) {
    return static_cast<bool>(ReadRawResultEx(pid, address, buffer, size, flags));
}

/// <summary>
/// Writes raw memory to the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="buffer">Local buffer containing data to write.</param>
/// <param name="size">Number of bytes to write.</param>
/// <returns>True if the write was successful.</returns>
bool DMA::WriteRaw(uint64_t address, const void* buffer, size_t size) {
    return WriteRawEx(targetPID, address, buffer, size);
}

bool DMA::WriteRawEx(DWORD pid, uint64_t address, const void* buffer, size_t size) {
    return static_cast<bool>(WriteRawResultEx(pid, address, buffer, size));
}

/// <summary>
/// Follows a pointer chain to retrieve the final address.
/// </summary>
/// <param name="base">Base address to start from.</param>
/// <param name="offsets">List of offsets to apply sequentially.</param>
/// <returns>The final address, or 0 if the chain is broken.</returns>
uint64_t DMA::ReadChain(uint64_t base,
    const std::vector<uint64_t>& offsets) {
    uint64_t result = 0;
    return TryReadChain(base, offsets, result) ? result : 0;
}

bool DMA::TryReadChain(uint64_t base, const std::vector<uint64_t>& offsets,
    uint64_t& result) {
    result = 0;
    if (base == 0)
        return false;

    uint64_t currentAddress = base;
    for (const auto& offset : offsets) {
        if (!TryRead(currentAddress, currentAddress) || currentAddress == 0 ||
            offset > std::numeric_limits<uint64_t>::max() - currentAddress) {
            return false;
        }
        currentAddress += offset;
    }
    result = currentAddress;
    return true;
}

/// <summary>
/// Reads an ASCII string from the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="maxLength">Maximum characters to read.</param>
/// <returns>The read string, truncated at the first null
/// terminator.</returns>
std::string DMA::ReadString(uint64_t address, size_t maxLength) {
    if (address == 0 || maxLength == 0)
        return "";
    std::string result;
    result.resize(maxLength);
    if (ReadRaw(address, result.data(), maxLength)) {
        size_t nullTerminator = result.find('\0');
        if (nullTerminator != std::string::npos) {
            result.resize(nullTerminator);
        }
        return result;
    }
    return "";
}

/// <summary>
/// Reads a Unicode (wide) string from the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="maxLength">Maximum characters to read.</param>
/// <returns>The read string, truncated at the first null
/// terminator.</returns>
std::wstring DMA::ReadWString(uint64_t address, size_t maxLength) {
    if (address == 0 || maxLength == 0 ||
        maxLength > std::numeric_limits<size_t>::max() / sizeof(wchar_t))
        return L"";
    std::wstring result;
    result.resize(maxLength);
    if (ReadRaw(address, result.data(), maxLength * sizeof(wchar_t))) {
        size_t nullTerminator = result.find(L'\0');
        if (nullTerminator != std::wstring::npos) {
            result.resize(nullTerminator);
        }
        return result;
    }
    return L"";
}

/// <summary>
/// Resolves a relative memory address (common in x64 instructions like
/// RIP-relative addressing).
/// </summary>
/// <param name="instructionAddress">Address of the instruction.</param>
/// <param name="offsetOffset">Offset to the displacement value within the
/// instruction.</param> <param name="instructionSize">Total size of the
/// instruction.</param> <returns>The absolute address resolved from the
/// relative offset.</returns>
uint64_t DMA::ResolveRelative(uint64_t instructionAddress,
    uint32_t offsetOffset,
    uint32_t instructionSize) {
    if (instructionAddress == 0)
        return 0;
    if (offsetOffset > std::numeric_limits<uint64_t>::max() - instructionAddress)
        return 0;
    int32_t relativeOffset = 0;
    if (!TryRead(instructionAddress + offsetOffset, relativeOffset))
        return 0;
    if (instructionSize > std::numeric_limits<uint64_t>::max() - instructionAddress)
        return 0;
    const uint64_t nextInstruction = instructionAddress + instructionSize;
    if (relativeOffset >= 0) {
        const auto positiveOffset = static_cast<uint64_t>(relativeOffset);
        if (positiveOffset > std::numeric_limits<uint64_t>::max() - nextInstruction)
            return 0;
        return nextInstruction + positiveOffset;
    }
    const auto magnitude = static_cast<uint64_t>(-static_cast<int64_t>(relativeOffset));
    return magnitude > nextInstruction ? 0 : nextInstruction - magnitude;
}

bool DMA::VirtualToPhysical(uint64_t virtualAddress,
    uint64_t& physicalAddress) const
{
    physicalAddress = 0;
    return IsAttached() && virtualAddress != 0 &&
        static_cast<bool>(backend->VirtualToPhysical(targetPID, virtualAddress,
            physicalAddress));
}

bool DMA::PrefetchPages(const std::vector<uint64_t>& addresses) const
{
    if (!IsAttached() || addresses.empty() ||
        addresses.size() > std::numeric_limits<DWORD>::max()) {
        return false;
    }
    return static_cast<bool>(backend->PrefetchPages(targetPID, addresses));
}

/// <summary>
/// Reads a block of memory from the target process.
/// </summary>
std::vector<uint8_t> DMA::DumpMemory(uint64_t address, size_t size,
    ULONG64 flags) {
    return DumpMemoryEx(targetPID, address, size, flags);
}

/// <summary>
/// Reads a block of memory using an explicit PID (e.g. a csrss/winlogon pid
/// ORed with VMMDLL_PID_PROCESS_WITH_KERNELMEMORY for kernel module dumps).
/// Use this instead of DumpMemory whenever the target address lives in kernel
/// space (win32k.sys, win32kbase.sys, win32ksgd.sys, etc.).
/// </summary>
std::vector<uint8_t> DMA::DumpMemoryEx(DWORD pid, uint64_t address, size_t size,
    ULONG64 flags) {
    if (!IsInitialized() || address == 0 || size == 0 ||
        size - 1 > std::numeric_limits<uint64_t>::max() - address) {
        return {};
    }

    std::vector<uint8_t> buffer(size, 0);
    constexpr size_t maxReadSize = 0x40000000; // VMMDLL documents a 1 GiB maximum.
    size_t offset = 0;
    while (offset < size) {
        const DWORD chunkSize = static_cast<DWORD>(
            std::min(maxReadSize, size - offset));
        DWORD bytesRead = 0;
        const auto result = backend->ReadMemory(pid, address + offset,
            buffer.data() + offset, chunkSize, flags, bytesRead);
        if (!result && result.status != DMAStatus::PartialTransfer) {
            buffer.clear();
            return buffer;
        }
        if (bytesRead != chunkSize &&
            !(flags & VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
            buffer.resize(offset + bytesRead);
            return buffer;
        }
        offset += chunkSize;
    }
    return buffer;
}

/// <summary>Add a signature scan request to the queue.</summary>
void DMA::QueueModuleScan(const std::string& moduleName,
    const std::string& scanName,
    const std::string& signature) {
    queuedModuleScans[moduleName].push_back({ scanName, signature });
}

/// <summary>Queue a multi-result signature scan. Use GetScanResultAll() to retrieve.</summary>
void DMA::QueueModuleScanAll(const std::string& moduleName,
    const std::string& scanName,
    const std::string& signature) {
    queuedModuleScans[moduleName].push_back({ scanName, signature, true });
}

/// <summary>Execute all queued module scans.</summary>
bool DMA::ExecuteModuleScans() {
    bool allSucceeded = true;
    for (const auto& [modName, requests] : queuedModuleScans) {
        uint64_t modBase = GetModuleBase(modName);
        uint32_t modSize = GetModuleSize(modName);

        if (modBase == 0 || modSize == 0) {
            allSucceeded = false;
            continue;
        }

        std::vector<uint8_t> localDump = DumpMemory(modBase, modSize);
        if (localDump.empty()) {
            allSucceeded = false;
            continue;
        }

        for (const auto& req : requests) {
            std::vector<PatternByte> pattern;
            if (!ParseSignature(req.signature, pattern)) {
                allSucceeded = false;
                if (req.wantsAll)
                    scanResultsMulti[req.name] = {};
                else
                    scanResults[req.name] = 0;
                continue;
            }
            if (req.wantsAll)
                scanResultsMulti[req.name] = ScanAllLocalBuffer(localDump, modBase, pattern);
            else
                scanResults[req.name] = ScanLocalBuffer(localDump, modBase, pattern);
        }
    }
    queuedModuleScans.clear();
    return allSucceeded;
}

/// <summary>Retrieve the result of a previous scan.</summary>
uint64_t DMA::GetScanResult(const std::string& scanName) const {
    const auto found = scanResults.find(scanName);
    return found == scanResults.end() ? 0 : found->second;
}

/// <summary>Retrieve all results from a previous multi-result scan.</summary>
std::vector<uint64_t> DMA::GetScanResultAll(const std::string& scanName) const {
    auto it = scanResultsMulti.find(scanName);
    if (it != scanResultsMulti.end())
        return it->second;
    return {};
}

void DMA::ClearScanResults()
{
    scanResults.clear();
    scanResultsMulti.clear();
}

/// <summary>
/// Scans the private heap of the process for a signature.
/// WARNING: This can be slow as it reads significant amounts of memory.
/// </summary>
uint64_t DMA::SigScanHeap(const std::string& signature) {
    const auto results = SigScanHeapAll(signature, 1);
    return results.empty() ? 0 : results.front();
}

std::vector<uint64_t> DMA::SigScanHeapAll(const std::string& signature,
    size_t maxResults) {
    std::vector<PatternByte> pattern;
    if (!ParseSignature(signature, pattern))
        return {};

    std::vector<uint64_t> results;
    for (const auto& region : GetHeapRegions()) {
        const uint64_t regionSize64 = region.end - region.start;
        if (regionSize64 == 0 || regionSize64 > std::numeric_limits<size_t>::max())
            continue;
        const size_t regionSize = static_cast<size_t>(regionSize64);
        const size_t overlap = pattern.size() > 1 ? pattern.size() - 1 : 0;

        for (size_t offset = 0; offset < regionSize;) {
            const size_t payloadSize = std::min(kHeapChunkSize, regionSize - offset);
            const size_t readSize = std::min(regionSize - offset, payloadSize + overlap);
            auto localDump = DumpMemory(region.start + offset, readSize,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (!localDump.empty()) {
                auto chunkResults = ScanAllLocalBuffer(localDump,
                    region.start + offset, pattern,
                    maxResults == 0 ? 0 : maxResults - results.size());
                for (uint64_t match : chunkResults) {
                    // Matches starting in overlap belong to the next chunk.
                    if (match < region.start + offset + payloadSize)
                        results.push_back(match);
                    if (maxResults != 0 && results.size() >= maxResults)
                        return results;
                }
            }
            offset += payloadSize;
        }
    }
    return results;
}

/// <summary>
/// Internal helper: prepares one or more scatter entries to cover [address, address+size),
/// splitting automatically at every 4 KB page boundary so no single VMMDLL element
/// crosses a page. Both source address and destination pointer advance in lockstep.
/// No heap allocation; writes go directly into the caller-supplied output buffer.
/// </summary>
bool DMA::PrepareScatterSplit(uint64_t address, void* outBuffer, size_t size)
{
    if (!legacyScatter || address == 0 || !outBuffer || size == 0 ||
        size - 1 > std::numeric_limits<uint64_t>::max() - address)
        return false;

    auto* out = static_cast<uint8_t*>(outBuffer);
    uint64_t cur = address;
    size_t   remain = size;

    while (remain > 0)
    {
        const size_t pageOffset = static_cast<size_t>(cur & kPageMask);
        const size_t bytesThisPage = kPageSize - pageOffset;
        const size_t chunk = (remain < bytesThisPage) ? remain : bytesThisPage;

        scatterReadStatuses.push_back(
            { static_cast<DWORD>(chunk), 0 });

        if (!legacyScatter->PrepareRead(cur, out, static_cast<DWORD>(chunk),
            &scatterReadStatuses.back().actual))
        {
            RecreateScatterHandle();
            SetLastError("VMMDLL_Scatter_PrepareEx failed; queued scatter work was reset.");
            return false;
        }

        cur += chunk;
        out += chunk;
        remain -= chunk;
    }

    return true;
}

/// <summary>
/// Prepares a raw scatter read. Automatically splits across 4 KB page boundaries.
/// Returns false on invalid inputs or if any VMMDLL prepare call fails.
/// </summary>
bool DMA::AddScatterRaw(uint64_t address, void* outBuffer, size_t size)
{
    return PrepareScatterSplit(address, outBuffer, size);
}

bool DMA::AddScatterWriteRaw(uint64_t address, const void* buffer, size_t size)
{
    if (!legacyScatter || address == 0 || !buffer || size == 0 ||
        size - 1 > std::numeric_limits<uint64_t>::max() - address) {
        return false;
    }

    auto* source = static_cast<const uint8_t*>(buffer);
    uint64_t currentAddress = address;
    size_t remaining = size;
    while (remaining != 0) {
        const size_t pageOffset = static_cast<size_t>(currentAddress & kPageMask);
        const size_t chunk = std::min(remaining, kPageSize - pageOffset);
        if (!legacyScatter->PrepareWrite(currentAddress, source,
            static_cast<DWORD>(chunk))) {
            RecreateScatterHandle();
            SetLastError("VMMDLL_Scatter_PrepareWrite failed; queued scatter work was reset.");
            return false;
        }
        scatterHasWrites = true;
        currentAddress += chunk;
        source += chunk;
        remaining -= chunk;
    }
    return true;
}

/// <summary>Executes all prepared scatter reads and clears the handle for reuse.</summary>
bool DMA::ExecuteScatter()
{
    if (!legacyScatter || (scatterReadStatuses.empty() && !scatterHasWrites))
        return false;

    const bool executed = static_cast<bool>(legacyScatter->Execute(scatterHasWrites));
    bool complete = executed;
    if (executed) {
        for (const auto& status : scatterReadStatuses) {
            if (status.actual != status.expected) {
                complete = false;
                break;
            }
        }
    }

    // PrepareEx retains caller buffer pointers for the lifetime of the handle.
    // Recreate it after every batch so stack/local output buffers are safe to release.
    const bool reset = RecreateScatterHandle();
    if (!executed)
        SetLastError("VMMDLL scatter execution failed.");
    else if (!complete)
        SetLastError("One or more scatter reads returned only partial data.");
    return complete && reset;
}

bool DMA::ResetScatter()
{
    return RecreateScatterHandle();
}
