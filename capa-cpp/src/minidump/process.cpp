#include "minidump/process.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <unordered_map>
#include <utility>

#include "module_filter.h"

namespace capa::mdmp {

namespace {

// Cap on the module image buffers we materialize. SizeOfImage is attacker-controlled
// for a manually-mapped module, so it needs a ceiling.
constexpr std::uint64_t MAX_MODULE_IMAGE = 256ull * 1024 * 1024;
// Cap on the buffer materialized for a non-module allocation. An allocation group can
// span a sparse range, so this is deliberately tighter than MAX_MODULE_IMAGE; past it
// the region falls back to per-range views and only its first range is fully usable.
constexpr std::uint64_t MAX_GROUP_IMAGE = 64ull * 1024 * 1024;

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string hex(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

// Assemble a module's image: SizeOfImage bytes, zero-filled, with every dumped range
// that overlaps it blitted into place. This is what makes `data + rva` correct and
// lets a paged-out page read back as zeros instead of shifting everything after it.
std::vector<std::uint8_t> assemble_image(const Dump& dump, std::uint64_t base,
                                         std::uint64_t size, std::uint64_t cap) {
    if (size == 0 || size > cap) return {};
    std::vector<std::uint8_t> buf;
    try {
        buf.assign(static_cast<std::size_t>(size), 0);
    } catch (const std::bad_alloc&) {
        return {};
    }
    bool any = false;
    for (const MemRange& r : dump.ranges()) {
        if (r.va + r.size <= base) continue;
        if (r.va >= base + size) break;  // ranges are sorted
        std::uint64_t from = std::max(r.va, base);
        std::uint64_t to = std::min(r.va + r.size, base + size);
        if (to <= from) continue;
        std::size_t n = static_cast<std::size_t>(to - from);
        if (dump.read_va(from, buf.data() + (from - base), n) > 0) any = true;
    }
    if (!any) return {};
    return buf;
}

// Half-open [lo, hi) spans of address space already backed by an assembled buffer.
// Used to keep step 4 from mapping a raw range on top of one, which finalize() would
// resolve by dropping whichever segment starts higher -- i.e. by throwing away the
// assembled image.
using Spans = std::vector<std::pair<std::uint64_t, std::uint64_t>>;

// Does [lo, hi) touch any span? Linear, because it is called while `spans` is still
// being built and is only ever a few hundred entries long.
bool overlaps_any(const Spans& spans, std::uint64_t lo, std::uint64_t hi) {
    for (const auto& [a, b] : spans)
        if (lo < b && a < hi) return true;
    return false;
}

// Sort and merge `spans` in place, so they can be walked in one pass.
void normalize(Spans& spans) {
    std::sort(spans.begin(), spans.end());
    Spans out;
    for (const auto& s : spans) {
        if (!out.empty() && s.first <= out.back().second)
            out.back().second = std::max(out.back().second, s.second);
        else
            out.push_back(s);
    }
    spans.swap(out);
}

// Map [lo, hi) as views, minus whatever `spans` already covers. `spans` must be
// normalized. Clipping rather than dropping the whole range matters when a module's
// SizeOfImage disagrees with the extent the dump actually recorded: the part outside
// the image is ordinary process memory and a pointer may well point at it.
void add_view_minus(stat::MemoryImage& mem, const Spans& spans, std::uint64_t lo,
                    std::uint64_t hi, const std::uint8_t* data) {
    // first span that could reach past `lo`
    auto it = std::lower_bound(spans.begin(), spans.end(), lo,
                               [](const auto& s, std::uint64_t v) { return s.second <= v; });
    std::uint64_t at = lo;
    for (; it != spans.end() && it->first < hi && at < hi; ++it) {
        if (it->first > at) mem.add_view(at, data + (at - lo), it->first - at);
        at = std::max(at, it->second);
    }
    if (at < hi) mem.add_view(at, data + (at - lo), hi - at);
}

}  // namespace

const char* region_kind_name(RegionKind k) {
    switch (k) {
        case RegionKind::MainExe: return "exe";
        case RegionKind::Module: return "module";
        case RegionKind::SystemModule: return "system";
        case RegionKind::MappedModule: return "mapped-module";
        case RegionKind::Private: return "private";
        case RegionKind::Mapped: return "mapped";
    }
    return "?";
}

// Kept as the backend's spelling of the shared policy; see module_filter.h. Both this
// and the IDA plugin classify through the same code so they cannot drift.
bool is_system_path(const std::string& path) { return is_system_module_path(path); }

// ---------------------------------------------------------------------------
// SymbolMap population (the container itself lives in static/symbol_map.h)
// ---------------------------------------------------------------------------

void add_module_symbols(SymbolMap& syms, const PeImage& pe, const std::string& dll_name) {
    const SymbolMap::DllId dll = syms.dll_id(dll_name);

    for (const PeExport& e : pe.exports) {
        // A forwarder's "va" is a string inside the export directory, not code. The
        // real target is an export of the module it names, which we index separately.
        if (!e.forwarded.empty()) continue;
        syms.add_export(dll, e.va, e.name);
    }

    for (const PeImport& i : pe.imports)
        syms.add_import_slot(syms.dll_id(i.dll), i.slot_va, i.symbol);
}

// ---------------------------------------------------------------------------

const Region* ProcessImage::region_at(std::uint64_t va) const {
    auto it = std::upper_bound(regions.begin(), regions.end(), va,
                               [](std::uint64_t v, const Region& r) { return v < r.base; });
    if (it == regions.begin()) return nullptr;
    --it;
    if (va < it->base || va - it->base >= it->size) return nullptr;
    return &*it;
}

SymbolMap build_symbol_map(const Dump& dump) {
    SymbolMap syms;
    for (const Module& m : dump.modules()) {
        std::vector<std::uint8_t> buf = assemble_image(dump, m.base, m.size, MAX_MODULE_IMAGE);
        if (buf.empty()) continue;  // paged out entirely

        // A MemoryImage of exactly one module, discarded before the next is read.
        // parse_mapped_pe only ever looks inside the module it is pointed at, so it
        // does not need the rest of the process to be present.
        stat::MemoryImage mem;
        mem.add(m.base, std::move(buf));
        mem.finalize();
        if (std::optional<PeImage> pe = parse_mapped_pe(mem, m.base, m.size))
            add_module_symbols(syms, *pe, m.name);
    }
    syms.finalize();
    return syms;
}

ProcessImage build_process_image(Dump dump, const BuildOptions& opts) {
    if (dump.cpu() == Cpu::Arm64)
        throw MdmpError(
            "this is an ARM64 process dump; capa-cpp can only disassemble x86 and x86-64");
    if (dump.ranges().empty())
        throw MdmpError("this dump contains no process memory at all");

    ProcessImage img;
    img.native_arch = dump.cpu() == Cpu::X86 ? stat::Arch::X86 : stat::Arch::X64;

    // ---- 1. allocation groups from MemoryInfo ----
    //
    // Group by AllocationBase rather than by protection: one VirtualAlloc shows up as
    // several MemoryInfo entries once its protections diverge, and splitting them
    // would split functions too.
    //
    // This runs first because a group's extent decides how memory is mapped below: an
    // executable group is materialized as ONE contiguous buffer, exactly like a
    // module, rather than as one segment per dumped range.
    struct Group {
        std::uint64_t lo = ~0ull, hi = 0;
        bool exec = false;
        bool image = false;
        bool mapped = false;
        std::uint32_t protect = 0;
    };
    // Keyed by alloc_base. A hash map, not a linear scan: a browser or game process
    // routinely carries 10^5 MemoryInfo entries and the scan was quadratic in that.
    std::unordered_map<std::uint64_t, Group> groups;
    for (const MemInfo& mi : dump.meminfo()) {
        if (mi.state != kMemCommit) continue;
        Group& g = groups[mi.alloc_base ? mi.alloc_base : mi.base];
        g.lo = std::min(g.lo, mi.base);
        g.hi = std::max(g.hi, mi.base + mi.size);
        if (mi.type == kMemImage) g.image = true;
        if (mi.type == kMemMapped) g.mapped = true;
        if (region_is_exec(mi.protect, mi.alloc_protect, mi.type)) {
            g.exec = true;
            g.protect = mi.protect ? mi.protect : mi.alloc_protect;
        }
    }

    // Executable groups that no module-list entry covers. kMemImage is included on
    // purpose: a module unlinked from the PEB loader lists still has its image mapped
    // as kMemImage, and skipping those wholesale made the most routine kind of hiding
    // invisible to the scan.
    std::vector<std::pair<std::uint64_t, Group>> loose;
    for (const auto& [key, g] : groups) {
        if (!g.exec || g.hi <= g.lo) continue;
        bool claimed = false;
        for (const Module& m : dump.modules()) {
            if (g.lo < m.base + m.size && m.base < g.hi) {
                claimed = true;
                break;
            }
        }
        if (!claimed) loose.emplace_back(key, g);
    }
    std::sort(loose.begin(), loose.end(),
              [](const auto& a, const auto& b) { return a.second.lo < b.second.lo; });

    // ---- 2. assemble every region that will be scanned into one buffer ----
    //
    // Modules first: they are worth a buffer even when they are system DLLs, because
    // their export tables are what makes calls into them resolvable.
    Spans assembled;
    for (const Module& m : dump.modules()) {
        // A module whose extent overlaps one already taken gets no Region at all.
        // finalize() would drop its segment as an overlap, but the Region would
        // survive -- and then parse_mapped_pe would read the NEIGHBOUR's bytes at
        // this base and file its exports in SymbolMap under this module's name,
        // turning a stale or corrupt module list entry into confidently wrong `api:`
        // features. Region set and segment set have to agree.
        if (overlaps_any(assembled, m.base, m.base + m.size)) continue;

        std::vector<std::uint8_t> buf = assemble_image(dump, m.base, m.size, MAX_MODULE_IMAGE);
        if (buf.empty()) continue;  // paged out entirely

        Region reg;
        reg.base = m.base;
        reg.size = m.size;
        reg.name = m.name;
        reg.path = m.path;
        reg.kind = is_system_path(m.path) ? RegionKind::SystemModule : RegionKind::Module;

        assembled.emplace_back(m.base, m.base + m.size);
        img.memory.add(m.base, std::move(buf), stat::SEG_IMAGE | stat::SEG_EXEC);
        img.regions.push_back(std::move(reg));
    }

    // Then the loose executable allocations, on the same terms. Giving these one
    // contiguous buffer is what lets discovery see the WHOLE allocation: a dump
    // records an allocation whose pages have diverging protections as several memory
    // ranges, and a per-range mapping means a read -- and therefore the prologue scan,
    // the linear sweep, and the file-scope string/PE scan -- stops at the first range.
    // A staged loader that VirtualAllocs RW and VirtualProtects only its code page to
    // RX lands exactly there, and its code page was previously never scanned at all.
    for (const auto& [key, g] : loose) {
        std::vector<std::uint8_t> buf = assemble_image(dump, g.lo, g.hi - g.lo, MAX_GROUP_IMAGE);
        if (buf.empty()) continue;  // committed but not dumped, or too large to hold
        assembled.emplace_back(g.lo, g.hi);
        img.memory.add(g.lo, std::move(buf), g.exec ? stat::SEG_EXEC : 0u);
    }

    // ---- 3. everything else, as zero-copy views into the mapped file ----
    //
    // Heap and stack are worth mapping even though they hold no code: they are where
    // a string or a resolved function pointer a code region references actually
    // lives. A range that overlaps an assembled buffer at all is skipped -- finalize()
    // resolves an overlap by keeping the lower-based segment, so leaving one in could
    // silently discard a module image.
    normalize(assembled);
    for (const MemRange& r : dump.ranges()) {
        if (r.size == 0) continue;
        if (r.file_off + r.size > dump.file_size()) continue;
        add_view_minus(img.memory, assembled, r.va, r.va + r.size,
                       dump.file_data() + r.file_off);
    }
    img.memory.finalize();

    // ---- 4. parse each module's headers ----
    for (Region& reg : img.regions) {
        reg.pe = parse_mapped_pe(img.memory, reg.base, reg.size);
        // A 32-bit module inside a WOW64 dump decodes as x86 regardless of what
        // SystemInfo says the process's native architecture is.
        reg.arch = reg.pe ? reg.pe->arch : img.native_arch;
    }

    // The main executable is the module whose PE says it is not a DLL. The COFF
    // characteristics are the authority here, not the file extension: a dump can carry
    // more than one module named *.exe -- a packaged app under a host stub, or an
    // injected image -- and picking the wrong one seeds the WindowsApps comparison
    // below, which can then flip the sample's own DLLs to SystemModule.
    Region* main_exe = nullptr;
    for (Region& reg : img.regions) {
        if (reg.pe && !reg.pe->is_dll) {
            main_exe = &reg;
            break;
        }
    }
    // No readable header anywhere: fall back to the name.
    if (main_exe == nullptr) {
        for (Region& reg : img.regions) {
            std::string n = lower(reg.name);
            if (n.size() > 4 && n.compare(n.size() - 4, 4, ".exe") == 0) {
                main_exe = &reg;
                break;
            }
        }
    }
    if (main_exe) main_exe->kind = RegionKind::MainExe;

    // Packaged apps: everything under \Program Files\WindowsApps\ that belongs to a
    // *different* package than the main executable is framework code the app merely
    // binds -- WindowsAppRuntime, VCLibs, the XAML stack. Tens of megabytes of
    // Microsoft binaries that say nothing about the sample, and on a stock Windows 11
    // app they are the bulk of the module list.
    if (main_exe) {
        const std::string own = windowsapps_package(main_exe->path);
        for (Region& reg : img.regions) {
            if (&reg == main_exe || reg.kind != RegionKind::Module) continue;
            std::string pkg = windowsapps_package(reg.path);
            if (!pkg.empty() && pkg != own) reg.kind = RegionKind::SystemModule;
        }
    }

    // ---- 5. region entries for the loose executable allocations ----
    for (const auto& [key, g] : loose) {
        if (!img.memory.is_mapped(g.lo)) continue;  // committed but not dumped

        Region reg;
        reg.base = g.lo;
        reg.size = g.hi - g.lo;
        reg.exec = true;
        reg.protect = g.protect;
        reg.arch = img.native_arch;
        reg.kind = g.mapped && !g.image ? RegionKind::Mapped : RegionKind::Private;

        // A valid PE here with no module-list entry is a manually mapped
        // (reflectively loaded) or unlinked module -- the single most interesting
        // thing a memory-forensics tool can find, and it parses like any other module.
        if ((opts.find_mapped_modules || g.image) && has_pe_header(img.memory, g.lo)) {
            reg.pe = parse_mapped_pe(img.memory, g.lo, reg.size);
            if (reg.pe) {
                reg.kind = RegionKind::MappedModule;
                reg.arch = reg.pe->arch;
            }
        }
        reg.name = std::string(region_kind_name(reg.kind)) + " " + hex(g.lo);
        img.regions.push_back(std::move(reg));
    }

    // Executable module regions: a module is scannable if its image is present.
    for (Region& reg : img.regions)
        if (reg.is_module()) reg.exec = true;

    std::sort(img.regions.begin(), img.regions.end(),
              [](const Region& a, const Region& b) { return a.base < b.base; });

    // ---- 5. the symbol maps ----
    for (const Region& reg : img.regions) {
        if (!reg.pe) continue;
        if (!opts.parse_all_module_headers && reg.is_system()) continue;
        add_module_symbols(img.symbols, *reg.pe, reg.name.empty() ? hex(reg.base) : reg.name);
    }
    img.symbols.finalize();

    img.dump = std::move(dump);
    return img;
}

}  // namespace capa::mdmp
