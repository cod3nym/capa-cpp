// Address -> (dll, symbol) for a whole process, for capa-cpp's static backends.
//
// Two lookups, and the difference between them is the whole point:
//   - export_at(va)  names the function that LIVES at an address. It is what
//     identifies a call target, whether the caller reached it through a real IAT, a
//     bound delay-load slot, or a table of pointers shellcode built for itself with
//     GetProcAddress.
//   - iat_slot(va)   names an import *slot*, which is what `call [mem]` actually
//     spells. Its name comes from the import directory, so it survives a slot the
//     loader has not filled in yet, and it says kernel32.HeapAlloc where the
//     resolved pointer would say ntdll.RtlAllocateHeap -- and the rules are written
//     against the former.
//
// This lives in static/ rather than with either backend because every backend that
// can see process memory needs the same thing: the minidump path fills it from each
// module's parsed PE, and the TTD path fills it from the module list the trace
// recorder wrote into the scan-code manifest.
//
// A full process yields ~200k pairs, so names are interned: a SymRef is two 32-bit
// pool indices rather than two std::strings.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace capa::stat {

struct SymRef {
    std::uint32_t dll = 0;
    std::uint32_t symbol = 0;
};

class SymbolMap {
public:
    // An interned, lower-cased DLL name. Every symbol of one module shares it, so a
    // caller adding a module's 2,400 exports pays for the name once.
    using DllId = std::uint32_t;

    DllId dll_id(const std::string& dll_name);

    // `va` is absolute and must be the function's entry, not an RVA: this map is
    // consulted with addresses read out of memory.
    void add_export(DllId dll, std::uint64_t va, const std::string& symbol);
    void add_import_slot(DllId dll, std::uint64_t slot_va, const std::string& symbol);

    // Sorts and de-duplicates the export index. Lookups before this are undefined.
    void finalize();

    const SymRef* export_at(std::uint64_t va) const;
    const SymRef* iat_slot(std::uint64_t slot_va) const;

    const std::string& dll(SymRef s) const { return pool_[s.dll]; }
    const std::string& symbol(SymRef s) const { return pool_[s.symbol]; }

    bool empty() const { return export_by_va_.empty() && iat_.empty(); }
    std::size_t export_count() const { return export_by_va_.size(); }
    std::size_t import_count() const { return iat_.size(); }

private:
    std::uint32_t intern(const std::string& s);

    std::vector<std::string> pool_;
    std::unordered_map<std::string, std::uint32_t> pool_index_;
    std::vector<std::pair<std::uint64_t, SymRef>> export_by_va_;  // sorted by VA
    std::unordered_map<std::uint64_t, SymRef> iat_;
};

}  // namespace capa::stat
