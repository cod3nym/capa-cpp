#include "static/symbol_map.h"

#include <algorithm>
#include <cctype>

namespace capa::stat {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}  // namespace

std::uint32_t SymbolMap::intern(const std::string& s) {
    auto it = pool_index_.find(s);
    if (it != pool_index_.end()) return it->second;
    std::uint32_t id = static_cast<std::uint32_t>(pool_.size());
    pool_.push_back(s);
    pool_index_.emplace(s, id);
    return id;
}

// DLL names arrive in whatever casing their source used -- an import descriptor says
// "KERNEL32.dll", a trace's module list says "kernel32.dll" -- and both feed the same
// map, so the case is normalised here rather than at each call site.
SymbolMap::DllId SymbolMap::dll_id(const std::string& dll_name) {
    return intern(lower(dll_name));
}

void SymbolMap::add_export(DllId dll, std::uint64_t va, const std::string& symbol) {
    if (va == 0 || symbol.empty()) return;
    export_by_va_.emplace_back(va, SymRef{dll, intern(symbol)});
}

void SymbolMap::add_import_slot(DllId dll, std::uint64_t slot_va, const std::string& symbol) {
    if (slot_va == 0 || symbol.empty()) return;
    iat_.emplace(slot_va, SymRef{dll, intern(symbol)});
}

void SymbolMap::finalize() {
    // Stable, so "the first added wins" below is a real rule rather than whatever
    // ordering std::sort happens to leave equivalent elements in. It has to be: a map
    // gets finalized again after a region's own export table is appended to it, and
    // when that region IS one of the modules already indexed -- which is exactly what
    // a reconstructed module image is -- every VA collides. The module's real name
    // must win over the placeholder the region was added under.
    std::stable_sort(export_by_va_.begin(), export_by_va_.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    // Several names can share one VA (aliases). Keep the first; capa only needs one
    // name per call site, and generate_symbols over-generates anyway.
    export_by_va_.erase(
        std::unique(export_by_va_.begin(), export_by_va_.end(),
                    [](const auto& a, const auto& b) { return a.first == b.first; }),
        export_by_va_.end());
}

const SymRef* SymbolMap::export_at(std::uint64_t va) const {
    auto it = std::lower_bound(export_by_va_.begin(), export_by_va_.end(), va,
                               [](const auto& e, std::uint64_t v) { return e.first < v; });
    if (it == export_by_va_.end() || it->first != va) return nullptr;
    return &it->second;
}

const SymRef* SymbolMap::iat_slot(std::uint64_t slot_va) const {
    auto it = iat_.find(slot_va);
    return it == iat_.end() ? nullptr : &it->second;
}

}  // namespace capa::stat
