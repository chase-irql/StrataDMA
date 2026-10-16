#include "DMA.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

DMAResult<DMALoadedImageInfo> DMA::InspectLoadedImage(const std::string& path,
    const std::vector<DMAImageGap>& missing) {
    DMAResult<DMALoadedImageInfo> result;
    const auto require = [](bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    };
    if (path.empty() || path.size() > 32767 || path.find('\0') != std::string::npos || missing.size() > 131072) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Invalid image path or gap list.");
        return result;
    }
    try {
        std::ifstream file(std::filesystem::u8path(path), std::ios::binary | std::ios::ate);
        if (!file) {
            result.operation = DMAOperationResult::Failure(DMAStatus::IoError, "Cannot open the saved image.");
            return result;
        }
        const auto end = file.tellg();
        require(end >= 64 && end <= 512LL * 1024 * 1024, "Saved images must contain 64 bytes to 512 MiB.");
        const auto size = static_cast<uint64_t>(end);
        uint64_t previous = 0;
        for (const auto& gap : missing) {
            if (!gap.size || gap.offset < previous || gap.offset > size || gap.size > size - gap.offset) {
                result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument, "Image gaps must be sorted, non-overlapping and inside the file.");
                return result;
            }
            previous = gap.offset + gap.size;
        }
        const auto known = [&](uint64_t at, uint64_t length) {
            if (at > size || length > size - at) return false;
            auto found = std::lower_bound(missing.begin(), missing.end(), at,
                [](const DMAImageGap& gap, uint64_t offset) { return gap.offset + gap.size <= offset; });
            return found == missing.end() || found->offset >= at + length;
        };
        const auto read = [&](uint64_t at, void* target, size_t length) {
            require(known(at, length), "Required image bytes are missing or outside the saved image.");
            file.seekg(static_cast<std::streamoff>(at));
            file.read(static_cast<char*>(target), static_cast<std::streamsize>(length));
            require(static_cast<size_t>(file.gcount()) == length, "Saved image was truncated while reading.");
        };
        IMAGE_DOS_HEADER dos{}; read(0, &dos, sizeof(dos));
        require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= 64 && dos.e_lfanew <= 1024 * 1024,
            "Invalid or unsupported DOS/PE header offset.");
        DWORD signature = 0; read(dos.e_lfanew, &signature, sizeof(signature));
        require(signature == IMAGE_NT_SIGNATURE, "Invalid PE signature.");
        IMAGE_FILE_HEADER coff{}; read(static_cast<uint64_t>(dos.e_lfanew) + 4, &coff, sizeof(coff));
        require(coff.NumberOfSections > 0 && coff.NumberOfSections <= 96, "Invalid PE section count.");
        const auto optionalAt = static_cast<uint64_t>(dos.e_lfanew) + 24;
        WORD magic = 0; read(optionalAt, &magic, sizeof(magic));
        auto& info = result.value;
        info.machine = coff.Machine; info.sectionCount = coff.NumberOfSections; info.timestamp = coff.TimeDateStamp;
        IMAGE_DATA_DIRECTORY relocation{};
        const auto fields = [&](const auto& optional) {
            info.preferredBase = optional.ImageBase; info.checksum = optional.CheckSum;
            info.imageSize = optional.SizeOfImage; info.entryRva = optional.AddressOfEntryPoint;
            info.imageMajorVersion = optional.MajorImageVersion; info.imageMinorVersion = optional.MinorImageVersion;
            require(optional.NumberOfRvaAndSizes <= IMAGE_NUMBEROF_DIRECTORY_ENTRIES, "Unsupported PE data-directory count.");
            if (optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                relocation = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        };
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            require(coff.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64), "Truncated PE32+ optional header.");
            IMAGE_OPTIONAL_HEADER64 optional{}; read(optionalAt, &optional, sizeof(optional)); fields(optional); info.is64Bit = true;
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            require(coff.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32), "Truncated PE32 optional header.");
            IMAGE_OPTIONAL_HEADER32 optional{}; read(optionalAt, &optional, sizeof(optional)); fields(optional);
        } else require(false, "Unsupported PE optional-header format.");
        const auto tableAt = optionalAt + coff.SizeOfOptionalHeader;
        const auto tableSize = static_cast<size_t>(coff.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        require(known(optionalAt, coff.SizeOfOptionalHeader) && known(tableAt, tableSize), "PE headers or section table are missing.");
        require(info.imageSize > 0 && info.imageSize <= 512U * 1024 * 1024 && tableAt + tableSize <= info.imageSize && info.entryRva < info.imageSize,
            "Invalid PE image size or entry point.");
        result.operation = DMAOperationResult::Success();
        // Identity survives a discarded/unreadable relocation directory; normalization does not.
        try {
            require((info.is64Bit && coff.Machine == IMAGE_FILE_MACHINE_AMD64) || (!info.is64Bit && coff.Machine == IMAGE_FILE_MACHINE_I386),
                "Relocation normalization supports x86 and x64 images only.");
            require(!(coff.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && relocation.VirtualAddress && relocation.Size,
                "Base relocation directory is absent or stripped.");
            require(relocation.Size <= 8U * 1024 * 1024 && relocation.VirtualAddress <= info.imageSize && relocation.Size <= info.imageSize - relocation.VirtualAddress,
                "Base relocation directory is outside the image or exceeds 8 MiB.");
            std::vector<uint8_t> bytes(relocation.Size); read(relocation.VirtualAddress, bytes.data(), bytes.size());
            for (size_t at = 0; at < bytes.size();) {
                require(bytes.size() - at >= sizeof(IMAGE_BASE_RELOCATION), "Truncated base relocation block.");
                IMAGE_BASE_RELOCATION block{}; std::memcpy(&block, bytes.data() + at, sizeof(block));
                require(block.SizeOfBlock >= 8 && block.SizeOfBlock % 4 == 0 && block.SizeOfBlock <= bytes.size() - at && block.VirtualAddress % 4096 == 0,
                    "Invalid base relocation block size or page RVA.");
                for (size_t pos = at + 8; pos < at + block.SizeOfBlock; pos += 2) {
                    WORD entry = 0; std::memcpy(&entry, bytes.data() + pos, sizeof(entry));
                    const auto type = entry >> 12;
                    if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                    require(type == (info.is64Bit ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW), "Unsupported base relocation type.");
                    const auto rva = static_cast<uint64_t>(block.VirtualAddress) + (entry & 0xfff);
                    const uint8_t width = info.is64Bit ? 8 : 4;
                    require(rva <= info.imageSize && width <= info.imageSize - rva && known(rva, width), "A relocation target is unreadable or outside the image.");
                    require(info.relocations.size() < 262144, "Base relocation count exceeds 262,144.");
                    info.relocations.push_back({ static_cast<uint32_t>(rva), width });
                }
                at += block.SizeOfBlock;
            }
            std::sort(info.relocations.begin(), info.relocations.end(), [](const auto& a, const auto& b) { return a.rva < b.rva; });
            for (size_t i = 1; i < info.relocations.size(); ++i)
                require(info.relocations[i].rva >= info.relocations[i - 1].rva + info.relocations[i - 1].width, "Overlapping or duplicate relocation targets.");
            info.relocationsComplete = true;
        } catch (const std::runtime_error& error) {
            info.relocations.clear(); info.relocationMessage = error.what();
        }
    } catch (const std::exception& error) {
        result.operation = DMAOperationResult::Failure(DMAStatus::ParseError, error.what());
        result.value = {};
    }
    return result;
}
