#include "minidump/mdmp.h"

#include <algorithm>
#include <cstring>
#include <fstream>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace capa::mdmp {

namespace {

// ---------------------------------------------------------------------------
// MINIDUMP_* on-disk layouts
//
// DbgHelp declares all of these under `#pragma pack(4)`. Getting that wrong shifts
// every field after the first ULONG64 and yields a module list that looks plausible
// but is wrong, so each size is asserted below.
// ---------------------------------------------------------------------------
#pragma pack(push, 4)

struct MdHeader {
    std::uint32_t Signature;
    std::uint32_t Version;
    std::uint32_t NumberOfStreams;
    std::uint32_t StreamDirectoryRva;
    std::uint32_t CheckSum;
    std::uint32_t TimeDateStamp;
    std::uint64_t Flags;
};

struct MdLocation {
    std::uint32_t DataSize;
    std::uint32_t Rva;
};

struct MdDirectory {
    std::uint32_t StreamType;
    MdLocation Location;
};

struct MdMemoryDescriptor {
    std::uint64_t StartOfMemoryRange;
    MdLocation Memory;
};

struct MdMemoryDescriptor64 {
    std::uint64_t StartOfMemoryRange;
    std::uint64_t DataSize;
};

struct MdMemoryList {
    std::uint32_t NumberOfMemoryRanges;
    // MdMemoryDescriptor MemoryRanges[];
};

struct MdMemory64List {
    std::uint64_t NumberOfMemoryRanges;
    std::uint64_t BaseRva;
    // MdMemoryDescriptor64 MemoryRanges[];
};

struct MdMemoryInfo {
    std::uint64_t BaseAddress;
    std::uint64_t AllocationBase;
    std::uint32_t AllocationProtect;
    std::uint32_t __alignment1;
    std::uint64_t RegionSize;
    std::uint32_t State;
    std::uint32_t Protect;
    std::uint32_t Type;
    std::uint32_t __alignment2;
};

struct MdMemoryInfoList {
    std::uint32_t SizeOfHeader;
    std::uint32_t SizeOfEntry;
    std::uint64_t NumberOfEntries;
};

struct MdVsFixedFileInfo {
    std::uint32_t dwSignature;
    std::uint32_t dwStrucVersion;
    std::uint32_t dwFileVersionMS;
    std::uint32_t dwFileVersionLS;
    std::uint32_t dwProductVersionMS;
    std::uint32_t dwProductVersionLS;
    std::uint32_t dwFileFlagsMask;
    std::uint32_t dwFileFlags;
    std::uint32_t dwFileOS;
    std::uint32_t dwFileType;
    std::uint32_t dwFileSubtype;
    std::uint32_t dwFileDateMS;
    std::uint32_t dwFileDateLS;
};

struct MdModule {
    std::uint64_t BaseOfImage;
    std::uint32_t SizeOfImage;
    std::uint32_t CheckSum;
    std::uint32_t TimeDateStamp;
    std::uint32_t ModuleNameRva;
    MdVsFixedFileInfo VersionInfo;
    MdLocation CvRecord;
    MdLocation MiscRecord;
    std::uint64_t Reserved0;
    std::uint64_t Reserved1;
};

struct MdThread {
    std::uint32_t ThreadId;
    std::uint32_t SuspendCount;
    std::uint32_t PriorityClass;
    std::uint32_t Priority;
    std::uint64_t Teb;
    MdMemoryDescriptor Stack;
    MdLocation ThreadContext;
};

struct MdThreadEx {
    std::uint32_t ThreadId;
    std::uint32_t SuspendCount;
    std::uint32_t PriorityClass;
    std::uint32_t Priority;
    std::uint64_t Teb;
    MdMemoryDescriptor Stack;
    MdLocation ThreadContext;
    MdMemoryDescriptor BackingStore;
};

struct MdSystemInfo {
    std::uint16_t ProcessorArchitecture;
    std::uint16_t ProcessorLevel;
    std::uint16_t ProcessorRevision;
    std::uint8_t NumberOfProcessors;
    std::uint8_t ProductType;
    std::uint32_t MajorVersion;
    std::uint32_t MinorVersion;
    std::uint32_t BuildNumber;
    std::uint32_t PlatformId;
    std::uint32_t CSDVersionRva;
    std::uint32_t SuiteMask;  // + Reserved2
    // followed by a 24-byte CPU_INFORMATION union
};

struct MdMiscInfo {
    std::uint32_t SizeOfInfo;
    std::uint32_t Flags1;
    std::uint32_t ProcessId;
    std::uint32_t ProcessCreateTime;
    std::uint32_t ProcessUserTime;
    std::uint32_t ProcessKernelTime;
};

struct MdException {
    std::uint32_t ExceptionCode;
    std::uint32_t ExceptionFlags;
    std::uint64_t ExceptionRecord;
    std::uint64_t ExceptionAddress;
    std::uint32_t NumberParameters;
    std::uint32_t __unusedAlignment;
    std::uint64_t ExceptionInformation[15];
};

struct MdExceptionStream {
    std::uint32_t ThreadId;
    std::uint32_t __alignment;
    MdException ExceptionRecord;
    MdLocation ThreadContext;
};

#pragma pack(pop)

static_assert(sizeof(MdHeader) == 32, "MINIDUMP_HEADER layout");
static_assert(sizeof(MdLocation) == 8, "MINIDUMP_LOCATION_DESCRIPTOR layout");
static_assert(sizeof(MdDirectory) == 12, "MINIDUMP_DIRECTORY layout");
static_assert(sizeof(MdMemoryDescriptor) == 16, "MINIDUMP_MEMORY_DESCRIPTOR layout");
static_assert(sizeof(MdMemoryDescriptor64) == 16, "MINIDUMP_MEMORY_DESCRIPTOR64 layout");
static_assert(sizeof(MdMemory64List) == 16, "MINIDUMP_MEMORY64_LIST layout");
static_assert(sizeof(MdMemoryInfo) == 48, "MINIDUMP_MEMORY_INFO layout");
static_assert(sizeof(MdMemoryInfoList) == 16, "MINIDUMP_MEMORY_INFO_LIST layout");
static_assert(sizeof(MdVsFixedFileInfo) == 52, "VS_FIXEDFILEINFO layout");
static_assert(sizeof(MdModule) == 108, "MINIDUMP_MODULE layout");
static_assert(sizeof(MdThread) == 48, "MINIDUMP_THREAD layout");
static_assert(sizeof(MdThreadEx) == 64, "MINIDUMP_THREAD_EX layout");
static_assert(sizeof(MdException) == 152, "MINIDUMP_EXCEPTION layout");

// stream types (MINIDUMP_STREAM_TYPE)
enum : std::uint32_t {
    ThreadListStream = 3,
    ModuleListStream = 4,
    MemoryListStream = 5,
    ExceptionStream = 6,
    SystemInfoStream = 7,
    ThreadExListStream = 8,
    Memory64ListStream = 9,
    MiscInfoStream = 15,
    MemoryInfoListStream = 16,
};

constexpr std::uint32_t MINIDUMP_SIGNATURE = 0x504D444D;  // 'MDMP'
constexpr std::uint16_t MINIDUMP_VERSION = 0xA793;

// PROCESSOR_ARCHITECTURE_*
constexpr std::uint16_t PA_INTEL = 0;
constexpr std::uint16_t PA_ARM = 5;
constexpr std::uint16_t PA_AMD64 = 9;
constexpr std::uint16_t PA_ARM64 = 12;

// CONTEXT field offsets. These are ABI-fixed; the host's <winnt.h> only ever
// describes one architecture, and for a WOW64 thread a 64-bit dumper writes the
// 64-bit record, so both layouts have to be known here.
constexpr std::size_t CTX64_SIZE = 1232;
constexpr std::size_t CTX64_SEGCS = 0x38;
constexpr std::size_t CTX64_RSP = 0x98;
constexpr std::size_t CTX64_RIP = 0xF8;

constexpr std::size_t CTX32_SIZE = 716;
constexpr std::size_t CTX32_EIP = 0xB8;
constexpr std::size_t CTX32_SEGCS = 0xBC;
constexpr std::size_t CTX32_ESP = 0xC4;

// Overflow-safe count * stride.
//
// Every array in a minidump is located by a count the file supplies. Multiplying that
// count by the element size in uint64 arithmetic WRAPS for a crafted count, and a
// wrapped product sails through the bounds check that is supposed to reject it -- so
// the check passes and the loop then walks off the mapping. Returns nullopt when the
// product does not fit, which every caller treats as "this stream is unusable".
std::optional<std::uint64_t> checked_bytes(std::uint64_t count, std::uint64_t stride) {
    if (stride == 0) return std::uint64_t{0};
    if (count > UINT64_MAX / stride) return std::nullopt;
    return count * stride;
}

std::uint32_t rd32(const std::uint8_t* p) {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}
std::uint64_t rd64(const std::uint8_t* p) {
    std::uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}
std::uint16_t rd16(const std::uint8_t* p) {
    std::uint16_t v;
    std::memcpy(&v, p, 2);
    return v;
}

// UTF-16LE -> UTF-8. MINIDUMP_STRING is not necessarily NUL-terminated and its
// Length is in bytes, so the caller supplies the count.
std::string utf16_to_utf8(const std::uint8_t* p, std::size_t chars) {
    std::string out;
    out.reserve(chars);
    for (std::size_t i = 0; i < chars; ++i) {
        std::uint32_t c = rd16(p + i * 2);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < chars) {  // surrogate pair
            std::uint32_t lo = rd16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

std::string basename_lower(const std::string& path) {
    std::size_t p = path.find_last_of("\\/");
    std::string n = p == std::string::npos ? path : path.substr(p + 1);
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return n;
}

}  // namespace

const char* cpu_name(Cpu c) {
    switch (c) {
        case Cpu::X86: return "x86";
        case Cpu::Amd64: return "amd64";
        case Cpu::Arm64: return "arm64";
        default: return "unknown";
    }
}

std::string protect_str(std::uint32_t p) {
    // READONLY|READWRITE|WRITECOPY|EXECUTE_READ|EXECUTE_READWRITE|EXECUTE_WRITECOPY
    constexpr std::uint32_t READ_BITS = 0xEE;
    // READWRITE|WRITECOPY|EXECUTE_READWRITE|EXECUTE_WRITECOPY
    constexpr std::uint32_t WRITE_BITS = 0xCC;
    if (p == 0 || (p & kPageNoAccess)) return "---";
    std::string s;
    s += (p & READ_BITS) ? 'R' : '-';
    s += (p & WRITE_BITS) ? 'W' : '-';
    s += protect_is_exec(p) ? 'X' : '-';
    if (p & kPageGuard) s += 'g';
    return s;
}

// ---------------------------------------------------------------------------

void Dump::release() noexcept {
#if defined(_WIN32)
    if (data_ && !owned_.data()) UnmapViewOfFile(const_cast<std::uint8_t*>(data_));
    if (map_handle_) CloseHandle(map_handle_);
    if (file_handle_ && file_handle_ != INVALID_HANDLE_VALUE) CloseHandle(file_handle_);
#endif
    file_handle_ = nullptr;
    map_handle_ = nullptr;
    data_ = nullptr;
    size_ = 0;
}

Dump::~Dump() { release(); }

Dump::Dump(Dump&& o) noexcept { *this = std::move(o); }

Dump& Dump::operator=(Dump&& o) noexcept {
    if (this == &o) return *this;
    // Whatever this Dump already had is about to be overwritten, so it has to be let
    // go first -- otherwise assigning onto an open Dump leaks its mapping and both
    // handles, and the file stays locked for the life of the process.
    release();
    file_handle_ = o.file_handle_;
    map_handle_ = o.map_handle_;
    owned_ = std::move(o.owned_);
    data_ = o.data_;
    size_ = o.size_;
    cpu_ = o.cpu_;
    pid_ = o.pid_;
    os_major_ = o.os_major_;
    os_build_ = o.os_build_;
    ranges_ = std::move(o.ranges_);
    meminfo_ = std::move(o.meminfo_);
    modules_ = std::move(o.modules_);
    threads_ = std::move(o.threads_);
    exception_addr_ = o.exception_addr_;
    truncated_ = o.truncated_;
    o.file_handle_ = nullptr;
    o.map_handle_ = nullptr;
    o.data_ = nullptr;
    o.size_ = 0;
    return *this;
}

const std::uint8_t* Dump::at(std::uint64_t off, std::uint64_t len) const {
    if (off > size_ || len > size_ - off) return nullptr;
    return data_ + off;
}

Dump Dump::open(const std::string& path) {
    Dump d;

#if defined(_WIN32)
    HANDLE fh = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE)
        throw MdmpError("cannot open " + path);
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(fh, &li) || li.QuadPart == 0) {
        CloseHandle(fh);
        throw MdmpError("cannot size " + path);
    }
    HANDLE mh = CreateFileMappingA(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mh) {
        CloseHandle(fh);
        throw MdmpError("cannot map " + path);
    }
    void* view = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(mh);
        CloseHandle(fh);
        throw MdmpError("cannot view " + path);
    }
    // Mapping rather than reading keeps a multi-GB full-memory dump off the heap:
    // only the regions actually scanned get copied out.
    d.file_handle_ = fh;
    d.map_handle_ = mh;
    d.data_ = static_cast<const std::uint8_t*>(view);
    d.size_ = static_cast<std::uint64_t>(li.QuadPart);
#else
    std::ifstream in(path, std::ios::binary);
    if (!in) throw MdmpError("cannot open " + path);
    in.seekg(0, std::ios::end);
    std::streamoff sz = in.tellg();
    in.seekg(0, std::ios::beg);
    d.owned_.resize(sz > 0 ? static_cast<std::size_t>(sz) : 0);
    if (!d.owned_.empty())
        in.read(reinterpret_cast<char*>(d.owned_.data()),
                static_cast<std::streamsize>(d.owned_.size()));
    d.data_ = d.owned_.data();
    d.size_ = d.owned_.size();
#endif

    d.parse();
    return d;
}

void Dump::parse() {
    const std::uint8_t* hp = at(0, sizeof(MdHeader));
    if (!hp) throw MdmpError("file is smaller than a minidump header");
    MdHeader h{};
    std::memcpy(&h, hp, sizeof(h));

    if (h.Signature != MINIDUMP_SIGNATURE)
        throw MdmpError("not a minidump (bad signature)");
    if (static_cast<std::uint16_t>(h.Version & 0xFFFF) != MINIDUMP_VERSION)
        throw MdmpError("unsupported minidump version");

    const std::uint64_t dir_bytes = static_cast<std::uint64_t>(h.NumberOfStreams) * sizeof(MdDirectory);
    const std::uint8_t* dir = at(h.StreamDirectoryRva, dir_bytes);
    if (!dir)
        throw MdmpError("minidump stream directory is truncated (file is incomplete)");

    // SystemInfo first: the thread-context decode depends on the architecture.
    for (std::uint32_t i = 0; i < h.NumberOfStreams; ++i) {
        MdDirectory e{};
        std::memcpy(&e, dir + i * sizeof(MdDirectory), sizeof(e));
        if (e.StreamType == SystemInfoStream) parse_system_info(e.Location.Rva, e.Location.DataSize);
    }

    for (std::uint32_t i = 0; i < h.NumberOfStreams; ++i) {
        MdDirectory e{};
        std::memcpy(&e, dir + i * sizeof(MdDirectory), sizeof(e));
        const std::uint32_t rva = e.Location.Rva, sz = e.Location.DataSize;
        switch (e.StreamType) {
            case ModuleListStream: parse_module_list(rva, sz); break;
            case MemoryListStream: parse_memory_list(rva, sz); break;
            case Memory64ListStream: parse_memory64_list(rva, sz); break;
            case MemoryInfoListStream: parse_memory_info_list(rva, sz); break;
            case ThreadListStream: parse_thread_list(rva, sz, /*ex=*/false); break;
            case ThreadExListStream: parse_thread_list(rva, sz, /*ex=*/true); break;
            case MiscInfoStream: parse_misc_info(rva, sz); break;
            case ExceptionStream: parse_exception(rva, sz); break;
            default: break;
        }
    }

    // A dump can carry both memory lists, describing the same ground twice. Sort by
    // base and then by DESCENDING size, so that where two ranges start together the
    // larger is the one kept -- a plain `a.va < b.va` sort leaves the winner up to
    // std::sort's unspecified ordering of equivalent elements, and losing the toss
    // there means silently discarding the bigger of the two captures.
    std::sort(ranges_.begin(), ranges_.end(), [](const MemRange& a, const MemRange& b) {
        if (a.va != b.va) return a.va < b.va;
        return a.size > b.size;
    });
    std::vector<MemRange> uniq;
    uniq.reserve(ranges_.size());
    for (const MemRange& r : ranges_) {
        if (r.size == 0) continue;
        if (!uniq.empty() && r.va < uniq.back().va + uniq.back().size) continue;
        uniq.push_back(r);
    }
    ranges_.swap(uniq);

    std::sort(meminfo_.begin(), meminfo_.end(),
              [](const MemInfo& a, const MemInfo& b) { return a.base < b.base; });
    std::sort(modules_.begin(), modules_.end(),
              [](const Module& a, const Module& b) { return a.base < b.base; });
}

void Dump::parse_system_info(std::uint32_t rva, std::uint32_t size) {
    if (size < sizeof(MdSystemInfo)) return;
    const std::uint8_t* p = at(rva, sizeof(MdSystemInfo));
    if (!p) return;
    MdSystemInfo si{};
    std::memcpy(&si, p, sizeof(si));
    switch (si.ProcessorArchitecture) {
        case PA_INTEL: cpu_ = Cpu::X86; break;
        case PA_AMD64: cpu_ = Cpu::Amd64; break;
        case PA_ARM64: cpu_ = Cpu::Arm64; break;
        case PA_ARM: cpu_ = Cpu::Unknown; break;
        default: cpu_ = Cpu::Unknown; break;
    }
    os_major_ = si.MajorVersion;
    os_build_ = si.BuildNumber;
}

void Dump::parse_module_list(std::uint32_t rva, std::uint32_t size) {
    const std::uint8_t* p = at(rva, 4);
    if (!p || size < 4) return;
    std::uint32_t n = rd32(p);
    const std::uint8_t* arr = at(static_cast<std::uint64_t>(rva) + 4,
                                 static_cast<std::uint64_t>(n) * sizeof(MdModule));
    if (!arr) {  // truncated: keep what other streams gave us
        truncated_ = true;
        return;
    }
    modules_.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        MdModule m{};
        std::memcpy(&m, arr + static_cast<std::size_t>(i) * sizeof(MdModule), sizeof(m));
        Module out;
        out.base = m.BaseOfImage;
        out.size = m.SizeOfImage;
        out.checksum = m.CheckSum;
        out.timestamp = m.TimeDateStamp;
        out.path = read_minidump_string(m.ModuleNameRva);
        out.name = basename_lower(out.path);
        modules_.push_back(std::move(out));
    }
}

std::string Dump::read_minidump_string(std::uint32_t rva) const {
    const std::uint8_t* p = at(rva, 4);
    if (!p) return {};
    std::uint32_t len_bytes = rd32(p);  // bytes, excluding the terminating NUL
    const std::uint8_t* buf = at(static_cast<std::uint64_t>(rva) + 4, len_bytes);
    if (!buf) return {};
    return utf16_to_utf8(buf, len_bytes / 2);
}

void Dump::parse_memory_list(std::uint32_t rva, std::uint32_t size) {
    const std::uint8_t* p = at(rva, 4);
    if (!p || size < 4) return;
    std::uint32_t n = rd32(p);
    const std::uint8_t* arr = at(static_cast<std::uint64_t>(rva) + 4,
                                 static_cast<std::uint64_t>(n) * sizeof(MdMemoryDescriptor));
    if (!arr) return;
    for (std::uint32_t i = 0; i < n; ++i) {
        MdMemoryDescriptor md{};
        std::memcpy(&md, arr + static_cast<std::size_t>(i) * sizeof(md), sizeof(md));
        if (!at(md.Memory.Rva, md.Memory.DataSize)) continue;
        ranges_.push_back({md.StartOfMemoryRange, md.Memory.DataSize, md.Memory.Rva});
    }
}

void Dump::parse_memory64_list(std::uint32_t rva, std::uint32_t size) {
    if (size < sizeof(MdMemory64List)) return;
    const std::uint8_t* p = at(rva, sizeof(MdMemory64List));
    if (!p) return;
    MdMemory64List hdr{};
    std::memcpy(&hdr, p, sizeof(hdr));

    auto arr_bytes = checked_bytes(hdr.NumberOfMemoryRanges, sizeof(MdMemoryDescriptor64));
    if (!arr_bytes) {
        truncated_ = true;
        return;
    }
    const std::uint8_t* arr =
        at(static_cast<std::uint64_t>(rva) + sizeof(MdMemory64List), *arr_bytes);
    if (!arr) return;

    // The descriptors carry no RVA of their own: the bytes are one contiguous blob
    // starting at BaseRva, so each range's file offset is the running sum of the
    // sizes before it. Treating a descriptor as self-locating shifts all memory.
    std::uint64_t off = hdr.BaseRva;
    for (std::uint64_t i = 0; i < hdr.NumberOfMemoryRanges; ++i) {
        MdMemoryDescriptor64 md{};
        std::memcpy(&md, arr + static_cast<std::size_t>(i) * sizeof(md), sizeof(md));
        if (!at(off, md.DataSize)) {  // the capture was cut short; keep what we have
            truncated_ = true;
            break;
        }
        ranges_.push_back({md.StartOfMemoryRange, md.DataSize, off});
        off += md.DataSize;
    }
}

void Dump::parse_memory_info_list(std::uint32_t rva, std::uint32_t size) {
    if (size < sizeof(MdMemoryInfoList)) return;
    const std::uint8_t* p = at(rva, sizeof(MdMemoryInfoList));
    if (!p) return;
    MdMemoryInfoList hdr{};
    std::memcpy(&hdr, p, sizeof(hdr));
    if (hdr.SizeOfEntry < sizeof(MdMemoryInfo)) return;
    // SizeOfHeader locates the array; a value below the header itself would point the
    // array back into the header, and a wild one is caught by the bounds check below.
    if (hdr.SizeOfHeader < sizeof(MdMemoryInfoList)) return;

    // Stride by the dump's own SizeOfEntry, not sizeof(MdMemoryInfo): newer Windows
    // extends this record and a fixed stride would walk off alignment.
    auto arr_bytes = checked_bytes(hdr.NumberOfEntries, hdr.SizeOfEntry);
    if (!arr_bytes) {
        truncated_ = true;
        return;
    }
    const std::uint8_t* arr =
        at(static_cast<std::uint64_t>(rva) + hdr.SizeOfHeader, *arr_bytes);
    if (!arr) return;
    // reserve() only after the bounds check has proved the entries are really there:
    // NumberOfEntries is file-supplied, and reserving on it directly turned a crafted
    // dump into a length_error that took the whole process down.
    meminfo_.reserve(static_cast<std::size_t>(hdr.NumberOfEntries));
    for (std::uint64_t i = 0; i < hdr.NumberOfEntries; ++i) {
        MdMemoryInfo mi{};
        std::memcpy(&mi, arr + static_cast<std::size_t>(i * hdr.SizeOfEntry), sizeof(mi));
        meminfo_.push_back({mi.BaseAddress, mi.AllocationBase, mi.RegionSize, mi.AllocationProtect,
                            mi.Protect, mi.State, mi.Type});
    }
}

void Dump::parse_thread_list(std::uint32_t rva, std::uint32_t size, bool ex) {
    const std::size_t stride = ex ? sizeof(MdThreadEx) : sizeof(MdThread);
    const std::uint8_t* p = at(rva, 4);
    if (!p || size < 4) return;
    std::uint32_t n = rd32(p);
    const std::uint8_t* arr =
        at(static_cast<std::uint64_t>(rva) + 4, static_cast<std::uint64_t>(n) * stride);
    if (!arr) return;

    for (std::uint32_t i = 0; i < n; ++i) {
        MdThread t{};
        std::memcpy(&t, arr + static_cast<std::size_t>(i) * stride, sizeof(t));
        if (std::any_of(threads_.begin(), threads_.end(),
                        [&](const ThreadCtx& e) { return e.tid == t.ThreadId; }))
            continue;  // both ThreadList and ThreadExList present

        ThreadCtx out;
        out.tid = t.ThreadId;
        out.teb = t.Teb;
        out.stack_base = t.Stack.StartOfMemoryRange;
        out.stack_size = t.Stack.Memory.DataSize;

        const std::uint8_t* ctx = at(t.ThreadContext.Rva, t.ThreadContext.DataSize);
        if (ctx) {
            const std::uint32_t csz = t.ThreadContext.DataSize;
            if (cpu_ == Cpu::Amd64 && csz >= CTX64_SIZE) {
                out.pc = rd64(ctx + CTX64_RIP);
                out.sp = rd64(ctx + CTX64_RSP);
                out.cs = rd16(ctx + CTX64_SEGCS);
                // 0x23 is the 32-bit code selector: this is a WOW64 thread whose
                // context a 64-bit dumper still recorded in the 64-bit layout.
                out.wow64_32 = out.cs == 0x23;
            } else if (csz >= CTX32_SIZE) {
                out.pc = rd32(ctx + CTX32_EIP);
                out.sp = rd32(ctx + CTX32_ESP);
                out.cs = rd16(ctx + CTX32_SEGCS);
                out.wow64_32 = cpu_ != Cpu::X86;
            }
        }
        threads_.push_back(out);
    }
}

void Dump::parse_misc_info(std::uint32_t rva, std::uint32_t size) {
    const std::uint8_t* p = at(rva, 4);
    if (!p || size < 4) return;
    std::uint32_t info_size = rd32(p);
    // versioned record: only read ProcessId if this dump's version carries it
    if (info_size < sizeof(MdMiscInfo)) return;
    const std::uint8_t* q = at(rva, sizeof(MdMiscInfo));
    if (!q) return;
    MdMiscInfo mi{};
    std::memcpy(&mi, q, sizeof(mi));
    pid_ = mi.ProcessId;
}

void Dump::parse_exception(std::uint32_t rva, std::uint32_t size) {
    if (size < sizeof(MdExceptionStream)) return;
    const std::uint8_t* p = at(rva, sizeof(MdExceptionStream));
    if (!p) return;
    MdExceptionStream es{};
    std::memcpy(&es, p, sizeof(es));
    if (es.ExceptionRecord.ExceptionAddress) exception_addr_ = es.ExceptionRecord.ExceptionAddress;
}

std::uint64_t Dump::dumped_bytes() const {
    std::uint64_t n = 0;
    for (const MemRange& r : ranges_) n += r.size;
    return n;
}

bool Dump::looks_like_normal_dump() const {
    if (ranges_.empty()) return true;
    // With no module list there is nothing to measure image coverage against. Saying
    // "no code here" would be a guess, and the caller turns that guess into a refusal
    // to analyse -- so report the dump as usable and let the scan decide.
    if (modules_.empty()) return false;
    // A full-memory dump carries each module's image; a MiniDumpNormal dump carries
    // thread stacks and a handful of referenced pages. Ask whether any module's
    // image memory is actually present.
    for (const Module& m : modules_) {
        std::uint64_t covered = 0;
        for (const MemRange& r : ranges_) {
            if (r.va + r.size <= m.base) continue;
            if (r.va >= m.base + m.size) break;
            covered += std::min(r.va + r.size, m.base + m.size) - std::max(r.va, m.base);
        }
        if (covered > m.size / 2) return false;
    }
    return true;
}

std::size_t Dump::read_va(std::uint64_t va, std::uint8_t* out, std::size_t n) const {
    auto it = std::upper_bound(ranges_.begin(), ranges_.end(), va,
                               [](std::uint64_t v, const MemRange& r) { return v < r.va; });
    if (it == ranges_.begin()) return 0;
    --it;
    if (va < it->va || va - it->va >= it->size) return 0;
    std::uint64_t off = va - it->va;
    std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(n, it->size - off));
    const std::uint8_t* p = at(it->file_off + off, take);
    if (!p) return 0;
    std::memcpy(out, p, take);
    return take;
}

bool looks_like_minidump(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    char sig[4] = {};
    in.read(sig, 4);
    if (in.gcount() != 4) return false;
    return sig[0] == 'M' && sig[1] == 'D' && sig[2] == 'M' && sig[3] == 'P';
}

}  // namespace capa::mdmp
