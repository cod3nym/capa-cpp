// Usermode process minidump (.dmp) container parsing for capa-cpp.
//
// The MINIDUMP_* layouts are declared here rather than pulled from <minidumpapiset.h>
// for three reasons: a 64-bit capa-cpp must read 32-bit dumps and vice versa, the
// SDK's CONTEXT is only ever the host architecture's, and a forensic tool has to
// survive a truncated or malformed dump rather than fault on it. Every offset is
// validated against the file size before it is dereferenced.
//
// This layer is deliberately dumb: it decodes streams into plain structs and does no
// interpretation. Deciding what is a module, what is shellcode, and what is worth
// scanning is minidump/analysis.h's job.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace capa::mdmp {

class MdmpError : public std::runtime_error {
public:
    explicit MdmpError(const std::string& what) : std::runtime_error(what) {}
};

enum class Cpu { X86, Amd64, Arm64, Unknown };

const char* cpu_name(Cpu c);

// ---- memory ----

// One dumped range of process memory and where its bytes live in the file.
struct MemRange {
    std::uint64_t va = 0;
    std::uint64_t size = 0;
    std::uint64_t file_off = 0;
};

// MEMORY_BASIC_INFORMATION as captured in MemoryInfoListStream. Absent from dumps
// taken without MiniDumpWithFullMemoryInfo.
struct MemInfo {
    std::uint64_t base = 0;
    std::uint64_t alloc_base = 0;
    std::uint64_t size = 0;
    std::uint32_t alloc_protect = 0;
    std::uint32_t protect = 0;
    std::uint32_t state = 0;
    std::uint32_t type = 0;
};

// Win32 memory constants, spelled locally so this parses dumps on any host.
//
// Deliberately NOT named MEM_COMMIT / PAGE_EXECUTE and friends: those are object-like
// MACROS in <windows.h>, and a macro does not care what namespace it is in. Any
// translation unit that included both this header and windows.h would expand
// `inline constexpr std::uint32_t MEM_COMMIT` into `... 0x1000 = 0x1000` and fail to
// parse -- which is exactly what happened the first time the IDA plugin, whose SDK
// header pulls in windows.h, tried to use this parser.
inline constexpr std::uint32_t kMemCommit = 0x1000;
inline constexpr std::uint32_t kMemReserve = 0x2000;
inline constexpr std::uint32_t kMemFree = 0x10000;
inline constexpr std::uint32_t kMemPrivate = 0x20000;
inline constexpr std::uint32_t kMemMapped = 0x40000;
inline constexpr std::uint32_t kMemImage = 0x1000000;

inline constexpr std::uint32_t kPageNoAccess = 0x01;
inline constexpr std::uint32_t kPageExecute = 0x10;
inline constexpr std::uint32_t kPageExecuteRead = 0x20;
inline constexpr std::uint32_t kPageExecuteReadWrite = 0x40;
inline constexpr std::uint32_t kPageExecuteWriteCopy = 0x80;
inline constexpr std::uint32_t kPageGuard = 0x100;

// The execute bits all live in the high nibble of the low byte.
inline bool protect_is_exec(std::uint32_t p) { return (p & 0xF0) != 0; }
std::string protect_str(std::uint32_t p);

// Is this region executable, as far as capa should care?
//
// For kMemImage only the current `Protect` counts: the loader maps every section of
// every module with AllocationProtect == kPageExecuteWriteCopy, so consulting it
// would mark a module's .rdata and .data executable too.
//
// For private and mapped memory both matter. A staged loader VirtualAllocs RW,
// writes its payload, then VirtualProtects to RX; a dump taken mid-stage shows the
// execute bit in only one of the two.
inline bool region_is_exec(std::uint32_t protect, std::uint32_t alloc_protect,
                           std::uint32_t type) {
    if (type == kMemImage) return protect_is_exec(protect);
    return protect_is_exec(protect) || protect_is_exec(alloc_protect);
}

// ---- modules and threads ----

struct Module {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint32_t checksum = 0;
    std::uint32_t timestamp = 0;
    std::string path;  // full path as recorded, UTF-8
    std::string name;  // basename, lowercased
};

struct ThreadCtx {
    std::uint32_t tid = 0;
    std::uint64_t teb = 0;
    std::uint64_t pc = 0;  // Rip / Eip
    std::uint64_t sp = 0;  // Rsp / Esp
    std::uint64_t stack_base = 0;
    std::uint64_t stack_size = 0;
    // Code-segment selector. On x64 Windows 0x33 means the thread was running
    // 64-bit code and 0x23 means 32-bit (WOW64) — the only reliable way to tell,
    // because a 64-bit dumper writes a 64-bit CONTEXT even for a WOW64 thread.
    std::uint16_t cs = 0;
    bool wow64_32 = false;
};

class Dump {
public:
    // Reads and validates `path`. Throws MdmpError with a specific diagnostic if the
    // file is not a minidump or is structurally unusable.
    static Dump open(const std::string& path);

    Cpu cpu() const { return cpu_; }
    std::uint32_t pid() const { return pid_; }
    std::uint32_t os_major() const { return os_major_; }
    std::uint32_t os_build() const { return os_build_; }

    // Sorted by VA, non-overlapping. Union of MemoryListStream and
    // Memory64ListStream (both can appear in one dump; the 64-bit list wins).
    const std::vector<MemRange>& ranges() const { return ranges_; }
    // Sorted by base. Empty when the dump carries no MemoryInfoListStream.
    const std::vector<MemInfo>& meminfo() const { return meminfo_; }
    const std::vector<Module>& modules() const { return modules_; }
    const std::vector<ThreadCtx>& threads() const { return threads_; }
    std::optional<std::uint64_t> exception_address() const { return exception_addr_; }

    // Total bytes of process memory the dump actually carries.
    std::uint64_t dumped_bytes() const;
    // True when the dump looks like MiniDumpNormal: stacks and headers only, no
    // module image memory. Such a dump cannot yield capabilities.
    bool looks_like_normal_dump() const;
    // True when a stream ran past the end of the file, i.e. the capture was cut
    // short. What was parsed before that point is still usable.
    bool truncated() const { return truncated_; }

    // Copy up to `n` bytes of process memory at `va`; returns how many were copied.
    // Stops at the end of the containing range (no straddling).
    std::size_t read_va(std::uint64_t va, std::uint8_t* out, std::size_t n) const;

    const std::uint8_t* file_data() const { return data_; }
    std::uint64_t file_size() const { return size_; }

    // An empty Dump, so a holder like ProcessImage can be default-constructed.
    Dump() = default;
    ~Dump();
    Dump(Dump&&) noexcept;
    Dump& operator=(Dump&&) noexcept;
    Dump(const Dump&) = delete;
    Dump& operator=(const Dump&) = delete;

private:
    // Unmap and close, leaving this Dump empty. Idempotent.
    void release() noexcept;

    void parse();
    void parse_system_info(std::uint32_t rva, std::uint32_t size);
    void parse_module_list(std::uint32_t rva, std::uint32_t size);
    void parse_memory_list(std::uint32_t rva, std::uint32_t size);
    void parse_memory64_list(std::uint32_t rva, std::uint32_t size);
    void parse_memory_info_list(std::uint32_t rva, std::uint32_t size);
    void parse_thread_list(std::uint32_t rva, std::uint32_t size, bool ex);
    void parse_misc_info(std::uint32_t rva, std::uint32_t size);
    void parse_exception(std::uint32_t rva, std::uint32_t size);

    // Bounds-checked accessors over the mapped file. `at` returns nullptr rather
    // than throwing so a malformed stream degrades to "absent".
    const std::uint8_t* at(std::uint64_t off, std::uint64_t len) const;
    std::string read_minidump_string(std::uint32_t rva) const;

    // platform handles for the mapping; opaque here
    void* file_handle_ = nullptr;
    void* map_handle_ = nullptr;
    std::vector<std::uint8_t> owned_;  // fallback when mapping is unavailable
    const std::uint8_t* data_ = nullptr;
    std::uint64_t size_ = 0;

    Cpu cpu_ = Cpu::Unknown;
    std::uint32_t pid_ = 0;
    std::uint32_t os_major_ = 0;
    std::uint32_t os_build_ = 0;
    std::vector<MemRange> ranges_;
    std::vector<MemInfo> meminfo_;
    std::vector<Module> modules_;
    std::vector<ThreadCtx> threads_;
    std::optional<std::uint64_t> exception_addr_;
    bool truncated_ = false;
};

// True if the first bytes of `path` are the 'MDMP' signature. Used for CLI mode
// dispatch, so that detection does not depend on the file extension.
bool looks_like_minidump(const std::string& path);

}  // namespace capa::mdmp
