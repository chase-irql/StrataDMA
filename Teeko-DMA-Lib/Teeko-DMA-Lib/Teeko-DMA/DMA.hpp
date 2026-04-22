#pragma once

#include "deps/vmmdll.h"
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <thread>
#include <mutex>
#include <iostream>

#pragma comment(lib, "vmm.lib")
#pragma comment(lib, "leechcore.lib")

// Standard XInput Button Bitmasks
#define XINPUT_GAMEPAD_DPAD_UP          0x0001
#define XINPUT_GAMEPAD_DPAD_DOWN        0x0002
#define XINPUT_GAMEPAD_DPAD_LEFT        0x0004
#define XINPUT_GAMEPAD_DPAD_RIGHT       0x0008
#define XINPUT_GAMEPAD_START            0x0010
#define XINPUT_GAMEPAD_BACK             0x0020
#define XINPUT_GAMEPAD_LEFT_THUMB       0x0040 // Left stick click
#define XINPUT_GAMEPAD_RIGHT_THUMB      0x0080 // Right stick click
#define XINPUT_GAMEPAD_LEFT_SHOULDER    0x0100 // LB
#define XINPUT_GAMEPAD_RIGHT_SHOULDER   0x0200 // RB
#define XINPUT_GAMEPAD_A                0x1000
#define XINPUT_GAMEPAD_B                0x2000
#define XINPUT_GAMEPAD_X                0x4000
#define XINPUT_GAMEPAD_Y                0x8000

struct HeapRegion {
    uint64_t start;
    uint64_t end;
};

// --- Gamepad State ---
struct GamepadState {
    uint16_t buttons;
    uint8_t leftTrigger;
    uint8_t rightTrigger;
    int16_t thumbLX;
    int16_t thumbLY;
    int16_t thumbRX;
    int16_t thumbRY;
};

class _DMA {
private:
    VMM_HANDLE hVMM = nullptr;
    DWORD targetPID = 0;

    struct ModuleData {
        uint64_t baseAddress;
        uint32_t size;
    };

    std::unordered_map<std::string, ModuleData> moduleCache;
    uint64_t mainModuleBase = 0;

    VMMDLL_SCATTER_HANDLE hScatter = nullptr;

    // --- Signature Scanning Helpers ---
    struct PatternByte {
        uint8_t value;
        bool ignore;
    };

    struct SigScanRequest {
        std::string name;
        std::string signature;
        bool wantsAll = false;
    };

    std::unordered_map<std::string, std::vector<SigScanRequest>> queuedModuleScans;
    std::unordered_map<std::string, uint64_t> scanResults;
    std::unordered_map<std::string, std::vector<uint64_t>> scanResultsMulti;

    struct HeapProfile {
        bool fPrivateMemory = false;
        DWORD VadType = 0;
        bool valid = false;
    };
    HeapProfile heapProfile;

    // --- Keyboard State ---
    uint64_t gafAsyncKeyStateExport = 0;
    DWORD win_logon_pid = 0;
    uint8_t state_bitmap[64] = { 0 };
    uint8_t prev_bitmap[64] = { 0 };
    std::atomic<bool> kb_running = false;
    std::thread kb_thread;
    std::mutex kb_mutex;
    uint8_t pressed_bitmap[64] = { 0 };
    uint8_t released_bitmap[64] = { 0 };

    uint64_t active_controller_address = 0;
    GamepadState currentGamepadState = { 0 };
    std::atomic<bool> gamepad_running = false;
    std::thread gamepad_thread;
    std::mutex gamepad_mutex;

    void KeyboardThread(int poll_ms = 10);

    // Call this after InitKeyboard succeeds
    inline void StartKeyboardThread(int poll_ms = 10) {
        kb_running = true;
        kb_thread = std::thread(&_DMA::KeyboardThread, this, poll_ms);
    }

    /// <summary>
    /// Stops the background keyboard polling thread.
    /// </summary>
    inline void StopKeyboardThread() {
        kb_running = false;
        if (kb_thread.joinable())
            kb_thread.join();
    }

    inline void StopGamepadThread() {
        gamepad_running = false;
        if (gamepad_thread.joinable())
            gamepad_thread.join();
    }

    void GamepadThread(int poll_ms = 4);
    std::vector<PatternByte> ParseSignature(const std::string& signature);
    uint64_t ScanLocalBuffer(const std::vector<uint8_t>& buffer,
        uint64_t baseAddress,
        const std::vector<PatternByte>& pattern);
    std::vector<uint64_t> ScanAllLocalBuffer(const std::vector<uint8_t>& buffer,
        uint64_t baseAddress,
        const std::vector<PatternByte>& pattern);
    bool CacheModule(const std::string& moduleName);
    std::vector<HeapRegion> GetHeapRegions();

public:
    _DMA() = default;
    ~_DMA();

    /// <summary>
    /// Returns the global _DMA singleton instance.
    /// </summary>
    /// <remarks>
    /// The instance is lazily initialized on first call and is guaranteed
    /// to be thread-safe since C++11. The object has static storage duration
    /// and is destroyed during program shutdown.
    /// </remarks>
    /// <returns>
    /// Reference to the unique _DMA instance (never null).
    /// </returns>
    static _DMA& Get()
    {
        static _DMA instance;
        return instance;
    }

    /// <summary>Initializes the VMMDLL interface with default FPGA settings.</summary>
    bool Initialize(bool memMap = true, bool debug = false);

    /// <summary>Closes all active VMMDLL handles and cleans up resources.</summary>
    void Disconnect();

    /// <summary>Attempts to find and attach to a target process by name.</summary>
    bool Attach(const std::string& processName);

    // ==========================================
    // CR3 / DTB Management (Anti-Cheat Bypass)
    // ==========================================

    /// <summary>Verifies if the current Directory Table Base (DTB/CR3) is valid.</summary>
    bool IsCR3Valid();

    /// <summary>Manually sets the process Directory Table Base (DTB/CR3).</summary>
    bool SetCR3(uint64_t dtb);

    /// <summary>Flushes the internal VMMDLL Transport Lookaside Buffer (TLB) and memory cache.</summary>
    bool ClearCache();

    // ==========================================
    // Module Management
    // ==========================================

    /// <summary>Retrieves the base address of a module in the target process.</summary>
    uint64_t GetModuleBase(const std::string& moduleName);

    /// <summary>Retrieves the size of a module in bytes.</summary>
    uint32_t GetModuleSize(const std::string& moduleName);

    /// <summary>Returns the base address of the main module (process executable).</summary>
    inline uint64_t GetMainBase() const { return mainModuleBase; }
    /// <summary>Returns the Process ID (PID) of the attached target.</summary>
    inline DWORD GetPID() const { return targetPID; }

    /// <summary>
    /// Returns the VMM_HANDLE
    /// </summary>
    inline VMM_HANDLE GetVMM() const { return hVMM; }

    // ==========================================
    // Raw Memory IO & Traversal
    // ==========================================

    /// <summary>Reads raw memory from the target process.</summary>
    bool ReadRaw(uint64_t address, void* buffer, size_t size);

    /// <summary>Writes raw memory to the target process.</summary>
    bool WriteRaw(uint64_t address, const void* buffer, size_t size);

    /// <summary>
    /// Reads a value of type T from the target process.
    /// </summary>
    /// <typeparam name="T">The type of data to read.</typeparam>
    /// <param name="address">Target virtual address.</param>
    /// <param name="flags">VMMDLL flags.</param>
    /// <returns>The read value, or T{} on failure.</returns>
    template <typename T> inline T Read(uint64_t address) {
        T buffer{};
        ReadRaw(address, &buffer, sizeof(T));
        return buffer;
    }

    /// <summary>
    /// Writes a value of type T to the target process.
    /// </summary>
    /// <typeparam name="T">The type of data to write.</typeparam>
    /// <param name="address">Target virtual address.</param>
    /// <param name="value">The value to write.</param>
    /// <returns>True if the write was successful.</returns>
    template <typename T> inline bool Write(uint64_t address, const T& value) {
        return WriteRaw(address, &value, sizeof(T));
    }

    /// <summary>Follows a pointer chain to retrieve the final address.</summary>
    uint64_t ReadChain(uint64_t base, const std::vector<uint64_t>& offsets);

    /// <summary>Reads an ASCII string from the target process.</summary>
    std::string ReadString(uint64_t address, size_t maxLength = 256);

    /// <summary>Reads a Unicode (wide) string from the target process.</summary>
    std::wstring ReadWString(uint64_t address, size_t maxLength = 256);

    /// <summary>Resolves a relative memory address from RIP-relative instructions.</summary>
    uint64_t ResolveRelative(uint64_t instructionAddress,
        uint32_t offsetOffset,
        uint32_t instructionSize);

    // ==========================================
    // Signature Scanning
    // ==========================================

    /// <summary>Reads a block of memory from the target process.</summary>
    std::vector<uint8_t> DumpMemory(uint64_t address, size_t size,
        ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL);

    /// <summary>Reads a block of memory using an explicit PID.</summary>
    std::vector<uint8_t> DumpMemoryEx(DWORD pid, uint64_t address, size_t size,
        ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL);

    /// <summary>Add a signature scan request to the queue.</summary>
    void QueueModuleScan(const std::string& moduleName,
        const std::string& scanName,
        const std::string& signature);

    /// <summary>Queue a multi-result signature scan. Use GetScanResultAll() to retrieve.</summary>
    void QueueModuleScanAll(const std::string& moduleName,
        const std::string& scanName,
        const std::string& signature);

    /// <summary>Execute all queued module scans.</summary>
    void ExecuteModuleScans();

    /// <summary>Retrieve the result of a previous scan.</summary>
    uint64_t GetScanResult(const std::string& scanName);

    /// <summary>Retrieve all results from a previous multi-result scan.</summary>
    std::vector<uint64_t> GetScanResultAll(const std::string& scanName);

    /// <summary>Scans the private heap of the process for a signature.</summary>
    uint64_t SigScanHeap(const std::string& signature);

    // ==========================================
    // Automated Scatter Read System
    // ==========================================

private:
    /// <summary>Internal helper that prepares one or more scatter entries.</summary>
    bool PrepareScatterSplit(uint64_t address, void* outBuffer, size_t size);

public:
    /// <summary>
    /// Prepares a typed scatter read. Automatically splits across 4 KB page boundaries.
    /// Returns false on invalid inputs or if any VMMDLL prepare call fails.
    /// </summary>
    template <typename T>
    inline bool AddScatter(uint64_t address, T* outBuffer)
    {
        return PrepareScatterSplit(address, outBuffer, sizeof(T));
    }

    /// <summary>Prepares a raw scatter read.</summary>
    bool AddScatterRaw(uint64_t address, void* outBuffer, size_t size);

    /// <summary>Executes all prepared scatter reads and clears the handle for reuse.</summary>
    bool ExecuteScatter();

    /// <summary>Dumps a module from memory to disk using a Linear Dump strategy.</summary>
    bool DumpModule(const std::string& moduleName, const std::string& outPath);

    // ==========================================
    // Keyboard Support
    // ==========================================

    /// <summary>Initialize the keyboard state reader.</summary>
    bool InitKeyboard(int poll_ms, bool debug = false);

    /// <summary>Initializes the Xbox Gamepad reader.</summary>
    bool InitGamepad(int poll_ms = 4, bool debug = false);

    /// <summary>Returns a thread-safe copy of the current Gamepad State.</summary>
    GamepadState GetGamepadState();

    /// <summary>Checks if a specific XInput button bitmask is currently pressed.</summary>
    bool IsGamepadButtonPressed(uint16_t buttonMask);

    /// <summary>Check if a key is currently held down.</summary>
    bool IsKeyDown(uint32_t vk);

    /// <summary>Check if a key was just pressed since the last poll (rising edge).</summary>
    bool IsKeyPressed(uint32_t vk);

    /// <summary>Check if a key was just released since the last poll (falling edge).</summary>
    bool IsKeyReleased(uint32_t vk);

    /// <summary>Reads the global mouse cursor position from win32kbase.sys.</summary>
    POINT GetCursorPosition(bool debug = false);

    /// <summary>Returns the live 24-byte hardware state buffer for real-time diffing.</summary>
    std::vector<uint8_t> GetLiveGamepadBuffer(bool debug = false);
};
