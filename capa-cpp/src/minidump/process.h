// Turning a parsed minidump into something capa's static engine can analyse.
//
// Two jobs live here. First, assembling the dump's scattered memory ranges into a
// single shared `stat::MemoryImage`: each module becomes one contiguous
// SizeOfImage-sized buffer with the present ranges blitted in (so an RVA is just an
// offset and paged-out pages read as zeros), while non-module memory is mapped as a
// zero-copy view straight into the mapped .dmp file.
//
// Second, the symbol side: every module's exports keyed by VA and every module's
// import slots keyed by IAT address, across the whole process. That pair is what
// lets `call [rip+0x1234]` become `api: CreateFileW` — and, because a slot's *value*
// is also looked up in the export map, it works just as well for a function-pointer
// table a piece of shellcode built for itself with GetProcAddress.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "minidump/mdmp.h"
#include "minidump/pe.h"
#include "static/memory.h"
#include "static/symbol_map.h"

namespace capa::mdmp {

enum class RegionKind {
    MainExe,       // the process image itself
    Module,        // a mapped module outside the system directories
    SystemModule,  // \Windows\System32, SysWOW64 or WinSxS
    MappedModule,  // a valid PE in private/mapped memory with no module-list entry
    Private,       // kMemPrivate: classic shellcode territory
    Mapped,        // kMemMapped without a PE header
};

const char* region_kind_name(RegionKind k);

struct Region {
    RegionKind kind = RegionKind::Private;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name;  // "notepad.exe" / "private 0x1f0000"
    std::string path;  // full NT path, for modules
    stat::Arch arch = stat::Arch::X64;
    bool exec = false;
    std::uint32_t protect = 0;
    std::optional<PeImage> pe;

    bool is_module() const {
        return kind == RegionKind::MainExe || kind == RegionKind::Module ||
               kind == RegionKind::SystemModule || kind == RegionKind::MappedModule;
    }
    bool is_system() const { return kind == RegionKind::SystemModule; }
};

// The symbol side is shared with the TTD static path, which builds the same map from
// the module list its trace recorder wrote rather than from parsed PE headers.
using stat::SymRef;
using stat::SymbolMap;

// Index one parsed module: its exports by VA and its import slots by IAT address.
void add_module_symbols(SymbolMap& syms, const PeImage& pe, const std::string& dll_name);

// The whole dump, assembled.
struct ProcessImage {
    Dump dump;
    stat::MemoryImage memory;
    std::vector<Region> regions;  // sorted by base
    SymbolMap symbols;
    stat::Arch native_arch = stat::Arch::X64;

    // The region containing `va`, or nullptr.
    const Region* region_at(std::uint64_t va) const;
};

struct BuildOptions {
    // Parse every module's headers, including system DLLs. Always true in practice:
    // ntdll is not worth *scanning*, but its exports are exactly what makes calls
    // into it resolvable.
    bool parse_all_module_headers = true;
    // Scan private/mapped memory for manually-mapped (reflectively loaded) modules.
    bool find_mapped_modules = true;
};

// Assemble `dump`. Throws MdmpError if the dump cannot support analysis at all.
ProcessImage build_process_image(Dump dump, const BuildOptions& opts = {});

// Just the export and import maps, for a caller that has its own idea of the code but
// no idea of the names.
//
// That is exactly the IDA plugin's position on a database opened over a .dmp: IDA has
// disassembled the process but parsed no PE import directory and knows no export
// names, so `call [rip+0x1234]` stays anonymous and the ~500 capa rules written
// against `api:` can never match. The dump's own module headers have the answer.
//
// Assembles one module at a time and frees each before the next, so peak memory is the
// largest single module rather than the whole address space -- this runs inside IDA's
// process, where a spare gigabyte is not ours to take.
SymbolMap build_symbol_map(const Dump& dump);

// Is this path inside a Windows system directory? Used for the default scan filter.
bool is_system_path(const std::string& path);

}  // namespace capa::mdmp
