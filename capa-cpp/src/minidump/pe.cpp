#include "minidump/pe.h"

#include <algorithm>
#include <cstring>

namespace capa::mdmp {

namespace {

constexpr std::uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;      // 'MZ'
constexpr std::uint32_t IMAGE_NT_SIGNATURE = 0x00004550;   // 'PE\0\0'
constexpr std::uint16_t PE32_MAGIC = 0x10B;
constexpr std::uint16_t PE32PLUS_MAGIC = 0x20B;

constexpr std::uint16_t MACHINE_I386 = 0x014C;
constexpr std::uint16_t MACHINE_AMD64 = 0x8664;
constexpr std::uint16_t MACHINE_ARM64 = 0xAA64;

constexpr int DIR_EXPORT = 0;
constexpr int DIR_IMPORT = 1;
constexpr int DIR_EXCEPTION = 3;
constexpr int DIR_DEBUG = 6;
constexpr int DIR_TLS = 9;
constexpr int DIR_DELAY_IMPORT = 13;
constexpr int DIR_COM_DESCRIPTOR = 14;

constexpr std::uint32_t IMAGE_DEBUG_TYPE_CODEVIEW = 2;
constexpr std::uint32_t UNW_FLAG_CHAININFO = 0x4;

// PE headers cap this at 96; anything larger is a crafted or corrupt image.
constexpr std::uint32_t MAX_SECTIONS = 96;
// Sanity ceilings, so a corrupt count cannot turn into a multi-GB allocation.
constexpr std::uint32_t MAX_EXPORTS = 200000;
constexpr std::uint32_t MAX_IMPORTS_PER_DLL = 20000;
constexpr std::uint32_t MAX_IMPORT_DESCRIPTORS = 4096;
constexpr std::uint32_t MAX_PDATA_ENTRIES = 500000;
constexpr std::uint32_t MAX_TLS_CALLBACKS = 64;

// A bounds-checked reader over one mapped module. Every accessor returns a default
// on a miss, because pages really are absent from real dumps.
class Reader {
public:
    Reader(const stat::MemoryImage& mem, std::uint64_t base) : mem_(mem), base_(base) {}

    bool u8(std::uint64_t rva, std::uint8_t& out) const { return raw(rva, &out, 1); }
    bool u16(std::uint64_t rva, std::uint16_t& out) const { return raw(rva, &out, 2); }
    bool u32(std::uint64_t rva, std::uint32_t& out) const { return raw(rva, &out, 4); }
    bool u64(std::uint64_t rva, std::uint64_t& out) const { return raw(rva, &out, 8); }

    std::uint32_t u32_or(std::uint64_t rva, std::uint32_t dflt = 0) const {
        std::uint32_t v = dflt;
        u32(rva, v);
        return v;
    }

    // A NUL-terminated ASCII string at `rva`, capped at `max`.
    std::string cstr(std::uint64_t rva, std::size_t max = 512) const {
        std::span<const std::uint8_t> v = mem_.view(base_ + rva);
        std::size_t n = std::min<std::size_t>(max, v.size());
        std::string s;
        for (std::size_t i = 0; i < n; ++i) {
            if (v[i] == 0) return s;
            s.push_back(static_cast<char>(v[i]));
        }
        return {};  // unterminated within the cap: treat as absent
    }

    bool mapped(std::uint64_t rva, std::uint64_t len) const {
        return mem_.view(base_ + rva).size() >= len;
    }

private:
    bool raw(std::uint64_t rva, void* out, std::size_t n) const {
        std::span<const std::uint8_t> v = mem_.view(base_ + rva);
        if (v.size() < n) return false;
        std::memcpy(out, v.data(), n);
        return true;
    }
    const stat::MemoryImage& mem_;
    std::uint64_t base_;
};

struct DataDir {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

// Locate the NT headers. Returns the e_lfanew offset, or 0 if this is not a PE.
std::uint32_t find_nt_headers(const Reader& r) {
    std::uint16_t mz = 0;
    if (!r.u16(0, mz) || mz != IMAGE_DOS_SIGNATURE) return 0;
    std::uint32_t e_lfanew = 0;
    if (!r.u32(0x3C, e_lfanew)) return 0;
    // Crafted images put wild values here; the header must be within the first
    // page or two of a real image.
    if (e_lfanew < 0x40 || e_lfanew > 0x10000) return 0;
    std::uint32_t sig = 0;
    if (!r.u32(e_lfanew, sig) || sig != IMAGE_NT_SIGNATURE) return 0;
    return e_lfanew;
}

}  // namespace

bool has_pe_header(const stat::MemoryImage& mem, std::uint64_t base) {
    return find_nt_headers(Reader(mem, base)) != 0;
}

namespace {

// Names in a PE are ASCII by construction. A packer picks strange ones, but it picks
// characters; bytes outside the printable range mean we are reading something that is
// not a name table.
bool printable(const std::string& s) {
    for (unsigned char c : s)
        if (c < 0x20 || c > 0x7E) return false;
    return true;
}

}  // namespace

bool looks_mapped_here(const PeImage& pe, std::uint64_t available) {
    if (available != 0 && pe.size > available) return false;
    if (pe.sections.empty()) return false;

    const std::uint64_t end = pe.base + pe.size;
    for (const PeSection& s : pe.sections) {
        if (!printable(s.name)) return false;
        if (s.va < pe.base || s.va >= end) return false;
    }
    // The directories are reached through RVAs, so they are the test that catches an
    // image whose *header* is the only plaintext left: the section table can be
    // perfectly well-formed while everything it points at is still ciphertext, and
    // then the import descriptors decode into names made of noise.
    for (const PeImport& i : pe.imports)
        if (!printable(i.dll) || !printable(i.symbol)) return false;
    for (const PeExport& e : pe.exports)
        if (!printable(e.name) || !printable(e.forwarded)) return false;
    return true;
}

std::optional<PeImage> parse_mapped_pe(const stat::MemoryImage& mem, std::uint64_t base,
                                       std::uint64_t size_hint) {
    Reader r(mem, base);
    const std::uint32_t nt = find_nt_headers(r);
    if (!nt) return std::nullopt;

    PeImage img;
    img.base = base;

    // ---- COFF file header ----
    const std::uint32_t fh = nt + 4;
    std::uint16_t machine = 0, nsections = 0, opt_size = 0, characteristics = 0;
    if (!r.u16(fh + 0, machine)) return std::nullopt;
    r.u16(fh + 2, nsections);
    r.u16(fh + 16, opt_size);
    r.u16(fh + 18, characteristics);
    constexpr std::uint16_t IMAGE_FILE_DLL = 0x2000;
    img.is_dll = (characteristics & IMAGE_FILE_DLL) != 0;

    switch (machine) {
        case MACHINE_I386: img.arch = stat::Arch::X86; break;
        case MACHINE_AMD64: img.arch = stat::Arch::X64; break;
        case MACHINE_ARM64: img.is_arm64 = true; break;
        default: break;  // leave the x64 default; the caller can still see `machine`
    }

    // ---- optional header ----
    const std::uint32_t oh = fh + 20;
    std::uint16_t magic = 0;
    if (!r.u16(oh, magic)) return std::nullopt;
    if (magic != PE32_MAGIC && magic != PE32PLUS_MAGIC) return std::nullopt;
    img.pe32plus = magic == PE32PLUS_MAGIC;

    std::uint32_t entry_rva = r.u32_or(oh + 16);
    std::uint32_t size_of_image = 0;
    std::uint32_t nrvas = 0;
    if (img.pe32plus) {
        r.u64(oh + 24, img.preferred_base);
        size_of_image = r.u32_or(oh + 56);
        nrvas = r.u32_or(oh + 108);
    } else {
        img.preferred_base = r.u32_or(oh + 28);
        size_of_image = r.u32_or(oh + 56);
        nrvas = r.u32_or(oh + 92);
    }
    img.size = size_of_image ? size_of_image : size_hint;
    if (img.size == 0) img.size = size_hint;
    if (entry_rva) img.entry_point = base + entry_rva;

    // The directory count really can be below 16; indexing past it reads whatever
    // follows the header. A count ABOVE 16 is nonsense too, but the first 16 entries
    // are still where they always are -- clamping keeps a crafted count from costing
    // us the export and import tables, which is every feature this backend produces.
    if (nrvas > 16) nrvas = 16;
    const std::uint32_t dir_base = oh + (img.pe32plus ? 112 : 96);
    auto dir = [&](int i) -> DataDir {
        DataDir d;
        if (static_cast<std::uint32_t>(i) >= nrvas) return d;
        d.rva = r.u32_or(dir_base + static_cast<std::uint32_t>(i) * 8);
        d.size = r.u32_or(dir_base + static_cast<std::uint32_t>(i) * 8 + 4);
        return d;
    };

    img.is_dotnet = dir(DIR_COM_DESCRIPTOR).rva != 0;

    // ---- sections ----
    const std::uint32_t sec_base = oh + opt_size;
    const std::uint32_t nsec = std::min<std::uint32_t>(nsections, MAX_SECTIONS);
    for (std::uint32_t i = 0; i < nsec; ++i) {
        const std::uint32_t s = sec_base + i * 40;
        if (!r.mapped(s, 40)) break;
        char raw_name[9] = {};
        for (int k = 0; k < 8; ++k) {
            std::uint8_t c = 0;
            r.u8(s + static_cast<std::uint32_t>(k), c);
            raw_name[k] = static_cast<char>(c);
        }
        // Section names are 8 bytes and are NOT NUL-terminated when full.
        PeSection ps;
        ps.name.assign(raw_name, raw_name + 8);
        ps.name.erase(std::find(ps.name.begin(), ps.name.end(), '\0'), ps.name.end());
        ps.vsize = r.u32_or(s + 8);
        ps.va = base + r.u32_or(s + 12);
        ps.characteristics = r.u32_or(s + 36);
        img.sections.push_back(std::move(ps));
    }

    // ---- exports ----
    if (DataDir ed = dir(DIR_EXPORT); ed.rva && ed.size) {
        const std::uint32_t base_ord = r.u32_or(ed.rva + 16, 1);
        const std::uint32_t nfuncs = r.u32_or(ed.rva + 20);
        const std::uint32_t nnames = r.u32_or(ed.rva + 24);
        const std::uint32_t funcs_rva = r.u32_or(ed.rva + 28);
        const std::uint32_t names_rva = r.u32_or(ed.rva + 32);
        const std::uint32_t ords_rva = r.u32_or(ed.rva + 36);

        if (nfuncs <= MAX_EXPORTS && nnames <= nfuncs && funcs_rva) {
            // ordinal index -> name, from the parallel name/ordinal arrays
            std::vector<std::string> names(nfuncs);
            for (std::uint32_t j = 0; j < nnames; ++j) {
                std::uint16_t idx = 0;
                if (!r.u16(ords_rva + j * 2, idx) || idx >= nfuncs) continue;
                // AddressOfNameOrdinals holds an *index into AddressOfFunctions*,
                // not an ordinal; the ordinal is Base + that index.
                std::uint32_t name_rva = r.u32_or(names_rva + j * 4);
                if (!name_rva) continue;
                names[idx] = r.cstr(name_rva);
            }

            img.exports.reserve(nfuncs);
            for (std::uint32_t i = 0; i < nfuncs; ++i) {
                std::uint32_t frva = r.u32_or(funcs_rva + i * 4);
                if (!frva) continue;  // an unused ordinal slot
                PeExport pe;
                pe.ordinal = base_ord + i;
                pe.name = names[i].empty() ? ("#" + std::to_string(pe.ordinal)) : names[i];
                // A function RVA landing inside the export directory itself is not
                // code: it points at a "TARGETDLL.Symbol" forwarder string.
                if (frva >= ed.rva && frva < ed.rva + ed.size) {
                    pe.forwarded = r.cstr(frva);
                    if (pe.forwarded.empty()) continue;
                } else {
                    pe.va = base + frva;
                }
                img.exports.push_back(std::move(pe));
            }
        }
    }

    const std::uint32_t thunk_size = img.pe32plus ? 8 : 4;
    const std::uint64_t ordinal_flag = img.pe32plus ? 0x8000000000000000ull : 0x80000000ull;

    auto read_thunk = [&](std::uint64_t rva, std::uint64_t& out) {
        if (img.pe32plus) return r.u64(rva, out);
        std::uint32_t v = 0;
        if (!r.u32(rva, v)) return false;
        out = v;
        return true;
    };

    // Walk one import name table / IAT pair. `int_rva` may be 0 (bound or stripped
    // imports), in which case names are unavailable here and only the resolved slot
    // value can identify the target -- which the export map handles.
    auto walk_imports = [&](std::uint32_t int_rva, std::uint32_t iat_rva,
                            const std::string& dll, bool delay, bool have_int) {
        if (!int_rva || !iat_rva) return;
        for (std::uint32_t k = 0; k < MAX_IMPORTS_PER_DLL; ++k) {
            std::uint64_t t = 0;
            if (!read_thunk(int_rva + k * thunk_size, t) || t == 0) break;
            PeImport pi;
            pi.slot_va = base + iat_rva + k * thunk_size;
            pi.dll = dll;
            pi.delay_load = delay;
            if (t & ordinal_flag) {
                // Only believable when this really is the import name table. Without
                // an INT we are reading the IAT, whose entries are resolved code
                // addresses by dump time -- and a 32-bit address above 0x80000000
                // sets the very bit that marks an ordinal import, which invented
                // imports like "#1234" out of ordinary function pointers.
                if (!have_int) continue;
                pi.symbol = "#" + std::to_string(static_cast<std::uint32_t>(t & 0xFFFF));
            } else {
                // IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name. The RVA has to
                // land inside the image; when reading a resolved IAT it usually does
                // not, which is what keeps a bound import from yielding nonsense.
                const std::uint64_t hint_rva = static_cast<std::uint32_t>(t);
                if (img.size && hint_rva + 2 >= img.size) continue;
                pi.symbol = r.cstr(static_cast<std::uint32_t>(hint_rva) + 2);
                if (pi.symbol.empty()) continue;
            }
            img.imports.push_back(std::move(pi));
        }
    };

    // ---- imports ----
    if (DataDir id = dir(DIR_IMPORT); id.rva) {
        for (std::uint32_t i = 0; i < MAX_IMPORT_DESCRIPTORS; ++i) {
            const std::uint32_t d = id.rva + i * 20;
            std::uint32_t oft = r.u32_or(d + 0);
            std::uint32_t name_rva = r.u32_or(d + 12);
            std::uint32_t ft = r.u32_or(d + 16);
            if (!oft && !name_rva && !ft) break;  // the all-zero terminator
            std::string dll = r.cstr(name_rva, 256);
            if (dll.empty()) continue;
            std::transform(dll.begin(), dll.end(), dll.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            // Prefer the INT for names; it is never overwritten by the loader,
            // unlike the IAT. Fall back to the IAT when the INT is absent.
            walk_imports(oft ? oft : ft, ft, dll, /*delay=*/false, /*have_int=*/oft != 0);
        }
    }

    // ---- delay-load imports ----
    // Common for WININET / WS2_32 / CRYPT32, and by dump time the slots are usually
    // already resolved.
    if (DataDir dd = dir(DIR_DELAY_IMPORT); dd.rva) {
        for (std::uint32_t i = 0; i < MAX_IMPORT_DESCRIPTORS; ++i) {
            const std::uint32_t d = dd.rva + i * 32;
            std::uint32_t attrs = r.u32_or(d + 0);
            std::uint32_t name_field = r.u32_or(d + 4);
            std::uint32_t iat_field = r.u32_or(d + 12);
            std::uint32_t int_field = r.u32_or(d + 16);
            if (!name_field && !iat_field && !int_field) break;

            // Attributes bit 0 (dlattrRva) says the fields are RVAs. Old linkers
            // emit absolute VAs based on the *preferred* base instead, so those
            // need the ASLR delta backed out.
            auto to_rva = [&](std::uint32_t v) -> std::uint32_t {
                if (attrs & 1) return v;
                if (!v) return 0;
                std::uint64_t va = v;
                if (va < img.preferred_base) return 0;
                return static_cast<std::uint32_t>(va - img.preferred_base);
            };
            std::string dll = r.cstr(to_rva(name_field), 256);
            if (dll.empty()) continue;
            std::transform(dll.begin(), dll.end(), dll.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            walk_imports(to_rva(int_field), to_rva(iat_field), dll, /*delay=*/true,
                         /*have_int=*/to_rva(int_field) != 0);
        }
    }

    // ---- .pdata: the best x64 function-start source there is ----
    if (DataDir xd = dir(DIR_EXCEPTION); xd.rva && xd.size && !img.is_arm64) {
        const std::uint32_t n = std::min(xd.size / 12, MAX_PDATA_ENTRIES);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint32_t e = xd.rva + i * 12;
            std::uint32_t begin = 0, unwind = 0;
            if (!r.u32(e + 0, begin) || !begin) continue;
            r.u32(e + 8, unwind);

            // A chained entry describes a *fragment* of another function, not a
            // function of its own. The low bit of UnwindInfoAddress marks one form;
            // UNW_FLAG_CHAININFO in the UNWIND_INFO the other.
            bool chained = (unwind & 1) != 0;
            if (!chained && unwind) {
                std::uint8_t ver_flags = 0;
                if (r.u8(unwind & ~1u, ver_flags) && ((ver_flags >> 3) & UNW_FLAG_CHAININFO))
                    chained = true;
            }
            (chained ? img.pdata_fragments : img.pdata_starts).push_back(base + begin);
        }
        std::sort(img.pdata_starts.begin(), img.pdata_starts.end());
        img.pdata_starts.erase(std::unique(img.pdata_starts.begin(), img.pdata_starts.end()),
                               img.pdata_starts.end());
    }

    // ---- TLS callbacks ----
    // AddressOfCallBacks is a VA against the preferred base, not an RVA.
    if (DataDir td = dir(DIR_TLS); td.rva) {
        std::uint64_t cb_va = 0;
        bool ok = img.pe32plus ? r.u64(td.rva + 24, cb_va)
                               : [&] {
                                     std::uint32_t v = 0;
                                     bool o = r.u32(td.rva + 12, v);
                                     cb_va = v;
                                     return o;
                                 }();
        if (ok && cb_va) {
            std::uint64_t cb_rva = cb_va - img.preferred_base;
            if (cb_va >= img.preferred_base && cb_rva < img.size) {
                for (std::uint32_t k = 0; k < MAX_TLS_CALLBACKS; ++k) {
                    std::uint64_t fn = 0;
                    if (!read_thunk(cb_rva + k * thunk_size, fn) || fn == 0) break;
                    img.tls_callbacks.push_back(
                        static_cast<std::uint64_t>(static_cast<std::int64_t>(fn) + img.aslr_delta()));
                }
            }
        }
    }

    // ---- debug directory: the CodeView PDB path, for identifying the module ----
    if (DataDir dbg = dir(DIR_DEBUG); dbg.rva && dbg.size) {
        const std::uint32_t n = std::min<std::uint32_t>(dbg.size / 28, 32);
        for (std::uint32_t i = 0; i < n; ++i) {
            const std::uint32_t e = dbg.rva + i * 28;
            if (r.u32_or(e + 12) != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
            std::uint32_t cv_rva = r.u32_or(e + 20);
            if (!cv_rva) continue;
            if (r.u32_or(cv_rva) != 0x53445352) continue;  // 'RSDS'
            img.pdb_path = r.cstr(cv_rva + 24);
            break;
        }
    }

    return img;
}

}  // namespace capa::mdmp
