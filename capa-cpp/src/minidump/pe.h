// PE parsing over a *mapped* image, for capa-cpp's minidump path.
//
// This is not on-disk PE parsing. In a process dump the loader has already mapped
// the file, so an RVA is simply an offset from the module's base and
// PointerToRawData/SizeOfRawData are meaningless. The load base also usually differs
// from OptionalHeader.ImageBase because of ASLR, so every RVA resolves against the
// base the dump reports, and only the handful of fields that store *VAs* (TLS, and
// old-style delay-load descriptors) need the relocation delta applied.
//
// Everything here is independently fallible: pages are routinely missing from a
// dump, so a module whose export directory was paged out yields empty exports rather
// than a failure. What matters most is the export and import tables, because they are
// what turns `call [rip+0x1234]` into `api: CreateFileW`.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "static/disasm.h"
#include "static/memory.h"

namespace capa::mdmp {

struct PeSection {
    std::string name;
    std::uint64_t va = 0;
    std::uint32_t vsize = 0;
    std::uint32_t characteristics = 0;
};

struct PeExport {
    std::uint64_t va = 0;  // absolute; meaningless when `forwarded` is set
    std::uint32_t ordinal = 0;
    std::string name;       // "CreateFileW", or "#123" for an unnamed ordinal export
    std::string forwarded;  // e.g. "ntdll.RtlAllocateHeap"; empty for a normal export
};

struct PeImport {
    std::uint64_t slot_va = 0;  // the IAT slot, which is what a `call [mem]` names
    std::string dll;
    std::string symbol;  // "CreateFileW", or "#123" for an ordinal import
    bool delay_load = false;
};

struct PeImage {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    stat::Arch arch = stat::Arch::X64;
    bool pe32plus = false;
    bool is_dotnet = false;      // COM descriptor present: .text holds IL, not x86
    bool is_arm64 = false;       // Zydis cannot decode this
    bool is_dll = false;         // COFF IMAGE_FILE_DLL: not the process image
    std::uint64_t preferred_base = 0;  // OptionalHeader.ImageBase
    std::uint64_t entry_point = 0;     // absolute; 0 if none

    std::vector<PeSection> sections;
    std::vector<PeExport> exports;
    std::vector<PeImport> imports;

    // .pdata (x64 only). `starts` are function entries; `fragments` are the
    // BeginAddress of chained unwind entries, which are *parts* of another function
    // — seeding those as entries would split real functions apart under
    // Workspace's [entry, next_entry) attribution.
    std::vector<std::uint64_t> pdata_starts;
    std::vector<std::uint64_t> pdata_fragments;

    std::vector<std::uint64_t> tls_callbacks;
    std::string pdb_path;

    // The relocation delta to apply to a field that stores a preferred-base VA.
    std::int64_t aslr_delta() const {
        return static_cast<std::int64_t>(base) - static_cast<std::int64_t>(preferred_base);
    }
};

// Parse the image mapped at `base`. `size_hint` is the module list's SizeOfImage,
// used only when the optional header's own SizeOfImage is unusable. Returns nullopt
// when there is no valid MZ/PE at `base`.
std::optional<PeImage> parse_mapped_pe(const stat::MemoryImage& mem, std::uint64_t base,
                                       std::uint64_t size_hint);

// Cheap test for "is there a PE mapped here?", for spotting a manually-mapped module
// in private memory that has no entry in the dump's module list.
bool has_pe_header(const stat::MemoryImage& mem, std::uint64_t base);

// Does a parse describe an image really *mapped* at this address?
//
// A valid PE header does not say so on its own, and two common cases prove it. A
// region can hold the DLL exactly as it came off disk -- a packer's payload, a stage
// downloaded and held in memory -- and in that layout every RVA in the header
// addresses something else entirely, so the sections and imports read back out are
// assembled from unrelated bytes. And a header can be the only part of an image that
// is not encrypted yet, which is routine for a beacon: MZ and PE are in place while
// everything the directories point at is still ciphertext.
//
// Either way the parse yields import and section features made of noise, which is
// worse than no features at all.
//
// Three cheap tests, and it takes all three. An image mapped here occupies its whole
// SizeOfImage, which is what catches the on-disk layout: its header says more than
// the region holds. Section VAs land inside the image. And every name -- section,
// import, export -- is printable, because names in a PE are ASCII by construction; a
// packer picks strange ones, but it picks characters. The name test has to reach the
// directories and not just the section table, because an image decrypted lazily can
// have a perfectly well-formed section table pointing at ciphertext.
//
// `available` is how many bytes of memory back this base; 0 means unknown, and then
// the size test is skipped.
bool looks_mapped_here(const PeImage& pe, std::uint64_t available);

}  // namespace capa::mdmp
