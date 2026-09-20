#include "static/capabilities.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <optional>
#include <set>

// The PE reader, the symbol-fed ModuleContext and its API-resolution ladder were
// written for the minidump backend and still live with it, but none of them knows
// what a minidump is: each one wants memory, a symbol map and (optionally) the PE
// behind a region, which is exactly what a reconstructed TTD region can supply.
#include "minidump/context.h"
#include "minidump/pe.h"
#include "minidump/process.h"

namespace capa::stat {

namespace {

std::string region_symbol_name(std::uint64_t base) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "region_0x%llx", static_cast<unsigned long long>(base));
    return buf;
}

// Does `va` land in a section marked executable?
//
// A PE exports data as readily as it exports code -- CRT locale tables, COM class
// objects, plain globals -- and an address is a function entry only if it is code.
// Workspace gives a function *every* executed address in [entry, next_entry), so a
// data export sitting between a function's start and its body does not merely add a
// spurious function: it cuts a real one in half and splits its features across the
// two halves.
bool in_executable_section(const mdmp::PeImage& pe, std::uint64_t va) {
    constexpr std::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        std::uint64_t end = pe.sections[i].va + pe.sections[i].vsize;
        // Same VirtualSize == 0 fallback RegionContext uses for section extents.
        if (pe.sections[i].vsize == 0)
            end = (i + 1 < pe.sections.size()) ? pe.sections[i + 1].va : pe.base + pe.size;
        if (va >= pe.sections[i].va && va < end)
            return (pe.sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    return false;  // outside every section: not code we can vouch for
}

// Function starts a mapped PE names outright. The manifest's `executed` seeds only
// cover code that actually ran in the window the recorder watched, so an injected
// module's untaken branches -- its error paths, its unused exports -- are invisible
// without these.
void add_pe_entries(const mdmp::PeImage& pe, std::vector<std::uint64_t>& entries) {
    if (pe.entry_point != 0) entries.push_back(pe.entry_point);
    for (const mdmp::PeExport& e : pe.exports)
        if (e.forwarded.empty() && e.va != 0 && in_executable_section(pe, e.va))
            entries.push_back(e.va);
    for (std::uint64_t va : pe.tls_callbacks) entries.push_back(va);
    // pdata_starts only: a chained unwind entry is part of another function, and
    // seeding it would split that function under Workspace's [entry, next) rule.
    for (std::uint64_t va : pe.pdata_starts) entries.push_back(va);

    std::sort(entries.begin(), entries.end());
    entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
}

// Does a feature name a concrete site, or does it just happen to be true here?
//
// `api: VirtualAlloc`, a string reference, a `match:` of another rule -- each of those
// occurs at the handful of addresses that are recognisably the behaviour the rule
// describes. `mnemonic: mov`, `number: 0`, `characteristic: loop` are true at a great
// many addresses in any function that has them at all, and the earliest of those is
// usually indistinguishable from the function's prologue. Both kinds are collected,
// but the specific ones win outright when a rule has any (see gather_feature_vas).
bool is_specific_feature(FeatureType t) {
    switch (t) {
        case FeatureType::API:
        case FeatureType::Import:
        case FeatureType::Export:
        case FeatureType::FunctionName:
        case FeatureType::String:
        case FeatureType::Substring:
        case FeatureType::Regex:
        case FeatureType::Bytes:
        case FeatureType::Property:
        case FeatureType::Class:
        case FeatureType::Namespace:
        case FeatureType::MatchedRule:
            return true;
        default:
            return false;
    }
}

// os/arch/format are global facts about the whole scan; whatever address they carry
// says nothing about where a rule matched. `basic block` is a structural counter.
bool is_locating_feature(FeatureType t) {
    switch (t) {
        case FeatureType::OS:
        case FeatureType::Arch:
        case FeatureType::Format:
        case FeatureType::BasicBlock:
            return false;
        default:
            return true;
    }
}

// Every match in the scan, addressable as (rule name, match address).
//
// Needed because a `match:` feature is a dead end on its own: its locations are the
// *other* rule's match addresses, which are that rule's containers, not its features.
// Most rules bottom out in one -- capa lowers every `basic block:` / `instruction:`
// block into a synthetic subscope rule, so `allocate or change RWX memory` is, at the
// top, nothing but `match: <its own basic block subscope>` located at the block's
// entry. Following the link is what turns that back into the VirtualAlloc call.
using MatchIndex = std::map<std::string, std::map<std::uint64_t, const Result*>>;

MatchIndex index_matches(const MatchResults& matches) {
    MatchIndex index;
    for (const auto& [name, results] : matches) {
        std::map<std::uint64_t, const Result*>& at = index[name];
        for (const auto& [addr, evidence] : results) {
            if (addr.type != AddressType::ABSOLUTE) continue;
            // The static path never caps evidence, so `evidence` is always present here;
            // indexing a null would silently give the descent nothing to follow.
            if (!evidence) continue;
            at.try_emplace(addr.value, evidence.get());
        }
    }
    return index;
}

// Rules nest a few levels at most (rule -> rule -> subscope -> instruction subscope);
// this only has to stop a pathological ruleset from walking forever.
constexpr int kMaxMatchDepth = 8;

// Walk one match tree and collect the addresses its *features* matched at.
//
// The tree handed here was re-evaluated without short-circuiting (engine::match), so
// it contains failed branches too -- an `or` records every alternative it tried, and
// `optional:` records the children it did without. Only successful nodes are
// descended, so nothing that did not contribute a reason for the match can contribute
// an address for it.
//
// `not:` is the one node whose success means the opposite: it holds because its child
// *failed*, and that child's subtree describes something the rule requires be absent.
// Nothing under it located anything.
void walk_feature_locations(const Result& res, std::uint64_t base, std::uint64_t end,
                            const MatchIndex& index,
                            std::set<std::pair<std::string, std::uint64_t>>& seen, int depth,
                            std::set<std::uint64_t>& specific, std::set<std::uint64_t>& broad) {
    if (!res.success) return;

    // A `match:` feature can name another rule's match, whose locations sit wherever
    // that rule matched -- filter to the region actually being scanned so a position
    // never points outside it.
    auto in_region = [&](const Address& a) {
        return a.type == AddressType::ABSOLUTE && a.value >= base && a.value < end;
    };
    auto take = [&](FeatureType t, const AddressSet& locs) {
        if (!is_locating_feature(t)) return;
        std::set<std::uint64_t>& dst = is_specific_feature(t) ? specific : broad;
        for (const Address& a : locs)
            if (in_region(a)) dst.insert(a.value);
    };

    if (!res.node_is_statement) {
        if (res.feature.type != FeatureType::MatchedRule) {
            take(res.feature.type, res.locations);
            return;  // a leaf has no children
        }
        // Follow the link into the named rule's own match at this address. `match:` on
        // a namespace names no single rule and simply misses, as does a rule whose
        // match this scan does not hold; either way the location itself is kept, which
        // is what this did before the descent existed.
        auto rule_at = index.find(res.feature.s);
        for (const Address& a : res.locations) {
            if (!in_region(a)) continue;
            const Result* inner = nullptr;
            if (rule_at != index.end()) {
                auto it = rule_at->second.find(a.value);
                if (it != rule_at->second.end()) inner = it->second;
            }
            const bool descend = inner != nullptr && depth < kMaxMatchDepth &&
                                 seen.emplace(res.feature.s, a.value).second;
            if (!descend) {
                specific.insert(a.value);
                continue;
            }
            const std::size_t before = specific.size() + broad.size();
            walk_feature_locations(*inner, base, end, index, seen, depth + 1, specific, broad);
            // The inner rule may be built entirely of features that name no site. Then
            // its own match address is still the best answer available.
            if (specific.size() + broad.size() == before) specific.insert(a.value);
        }
        return;
    }
    if (res.stmt == nullptr) return;
    if (res.stmt->type == StatementType::Not) return;
    // `count(api(VirtualAlloc)): 2 or more` keeps the counted feature on the statement
    // rather than as a child node, and its locations on the Result.
    if (res.stmt->type == StatementType::Range) take(res.stmt->range_child.type, res.locations);
    for (const Result& child : res.children)
        walk_feature_locations(child, base, end, index, seen, depth, specific, broad);
}

// Tracing cost is one execute watchpoint per address, so the broad fallback is
// bounded. Specific features never come close to this; a function full of `mov`s can.
constexpr std::size_t kMaxFeatureVas = 64;

// The addresses to offer as "where this match actually is", for one match tree.
std::vector<std::uint64_t> gather_feature_vas(const Result& res, std::uint64_t base,
                                              std::uint64_t end, const MatchIndex& index) {
    std::set<std::uint64_t> specific, broad;
    std::set<std::pair<std::string, std::uint64_t>> seen;
    walk_feature_locations(res, base, end, index, seen, 0, specific, broad);
    // Prefer the specific set whole: mixing in every `mov` address would just hand the
    // earliest-executing choice back to the prologue the container already points at.
    const std::set<std::uint64_t>& use = specific.empty() ? broad : specific;
    std::vector<std::uint64_t> out(use.begin(), use.end());
    if (out.size() > kMaxFeatureVas) out.resize(kMaxFeatureVas);  // lowest addresses first
    return out;
}

std::map<std::string, DumpHit> collect(const RuleSet& ruleset,
                                       const StaticFeatureExtractor& ex, std::uint64_t base,
                                       std::uint64_t size, const FeatureFilter& filter) {
    StaticCapabilities caps = find_static_capabilities(ruleset, ex, filter);
    const std::uint64_t end = base + size;
    // Built over *every* match, subscope and library rules included: those are exactly
    // the ones a user-facing rule's `match:` features point at.
    const MatchIndex index = index_matches(caps.matches);

    std::map<std::string, DumpHit> found;
    for (const auto& [name, results] : caps.matches) {
        auto rule = ruleset.get(name);
        if (!rule) continue;
        if (rule->is_subscope) continue;  // synthetic helper rules
        const std::string& ns = rule->namespace_;
        if (ns.rfind("internal/", 0) == 0 || rule->is_lib) continue;  // capa-internal / library

        DumpHit hit;
        hit.namespace_ = ns;
        hit.scope = rule->scopes.static_scope ? scope_to_string(*rule->scopes.static_scope)
                                              : std::string();
        hit.count = static_cast<int>(results.size());
        std::int64_t best = std::numeric_limits<std::int64_t>::max();
        std::set<std::uint64_t> va_set;
        for (const auto& [addr, evidence] : results) {
            if (addr.type != AddressType::ABSOLUTE) continue;  // only int-able locations
            va_set.insert(addr.value);
            std::int64_t off =
                static_cast<std::int64_t>(addr.value) - static_cast<std::int64_t>(base);
            if (off < best) best = off;
            hit.has_offset = true;

            // The same rule can match twice at one container across the scope walk
            // (once at instruction scope, once bubbled up); union rather than replace.
            if (!evidence) continue;  // no tree to read feature addresses out of
            std::vector<std::uint64_t> fvas =
                gather_feature_vas(*evidence, base, end, index);
            if (fvas.empty()) continue;
            std::vector<std::uint64_t>& dst = hit.feature_vas[addr.value];
            dst.insert(dst.end(), fvas.begin(), fvas.end());
        }
        if (hit.has_offset) hit.offset = best;
        hit.vas.assign(va_set.begin(), va_set.end());  // sorted + unique
        for (auto& [_, fvas] : hit.feature_vas) {
            std::sort(fvas.begin(), fvas.end());
            fvas.erase(std::unique(fvas.begin(), fvas.end()), fvas.end());
        }
        found[name] = std::move(hit);
    }
    return found;
}

}  // namespace

struct RegionScan::Impl {
    Arch arch = Arch::X64;
    std::optional<mdmp::PeImage> pe;
    SymbolMap with_region;  // the trace's map plus this region's own import directory
    std::optional<mdmp::RegionContext> ctx;
    std::optional<StaticExtractor> ex;
};

RegionScan::RegionScan(const MemoryImage& mem, std::uint64_t base, std::uint64_t size,
                       std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
                       Arch arch, const SymbolMap* symbols, const FeatureFilter* filter)
    : impl_(std::make_unique<Impl>()) {
    if (mdmp::has_pe_header(mem, base)) impl_->pe = mdmp::parse_mapped_pe(mem, base, size);
    // A region is a container only if the image really is mapped across it -- a
    // staged copy of the file on disk, or a beacon whose body is still encrypted,
    // parses into sections and imports made of noise. And .NET assemblies hold IL
    // where Zydis expects x86, while ARM64 it cannot decode at all; treat those as
    // the flat blobs they are to this scanner.
    if (impl_->pe && (impl_->pe->is_dotnet || impl_->pe->is_arm64 ||
                      !mdmp::looks_mapped_here(*impl_->pe, size)))
        impl_->pe.reset();

    // The manifest names one architecture for the whole trace: the recorded process's
    // own. A region can disagree -- a WOW64 process runs 32-bit code beside 64-bit
    // modules, and either width gets injected into the other -- and decoding 32-bit
    // code as x64 does not fail, it produces plausible nonsense. A COFF machine field
    // is a direct answer where a blob offers none, so take it where it exists.
    impl_->arch = impl_->pe ? impl_->pe->arch : arch;
    arch = impl_->arch;

    // A region that is itself a mapped image contributes its own import directory,
    // which names slots the loader may not even have filled in yet -- and names them
    // the way the rules are written (kernel32.HeapAlloc, not ntdll.RtlAllocateHeap).
    //
    // That is per-region knowledge, so it goes into a copy: a snapshot must not leave
    // its own symbols in a map every other region reads. The copy is a real one -- the
    // string pool and both indices, ~3 MB on a trace with 19,000 exports -- and it is
    // paid per snapshot of a PE region, which measures at a few tens of milliseconds
    // over a whole scan. Non-PE regions, the majority, read the shared map in place.
    // Appending after the trace's own entries is what makes the module's real name win
    // at a colliding VA; see SymbolMap::finalize.
    const SymbolMap* use = symbols;
    if (impl_->pe) {
        if (symbols != nullptr) impl_->with_region = *symbols;
        mdmp::add_module_symbols(impl_->with_region, *impl_->pe, region_symbol_name(base));
        impl_->with_region.finalize();
        use = &impl_->with_region;
        add_pe_entries(*impl_->pe, entries);
    }

    // No container and no symbols is the original scan: a flat buffer, no api:.
    if (use != nullptr)
        impl_->ctx.emplace(mem, *use, arch, base, impl_->pe ? &*impl_->pe : nullptr);
    impl_->ex.emplace(mem, base, size, std::move(entries), std::move(executed), arch,
                      impl_->ctx ? &*impl_->ctx : nullptr, filter);
}

RegionScan::~RegionScan() = default;

const StaticExtractor& RegionScan::extractor() const { return *impl_->ex; }

bool RegionScan::is_pe() const { return impl_->pe.has_value(); }

Arch RegionScan::arch() const { return impl_->arch; }

SymbolMap build_symbol_map(const Manifest& manifest) {
    SymbolMap syms;
    for (const ModuleInfo& m : manifest.modules) {
        if (m.base == 0 || m.exports.empty()) continue;
        const SymbolMap::DllId dll = syms.dll_id(m.name.empty() ? m.path : m.name);
        for (const auto& [rva, name] : m.exports) syms.add_export(dll, m.base + rva, name);
    }
    syms.finalize();
    return syms;
}

std::map<std::string, DumpHit> scan_dump(const RuleSet& ruleset, const MemoryImage& mem,
                                         std::uint64_t base, std::uint64_t size,
                                         std::vector<std::uint64_t> entries,
                                         std::vector<std::uint64_t> executed, Arch arch,
                                         const SymbolMap* symbols,
                                         const FeatureFilter* filter) {
    // A default-constructed filter keeps everything: it has collected no rule features,
    // but `enabled()` alone does not gate keep(), so an absent filter has to be an
    // explicitly disabled one rather than an empty one.
    static const FeatureFilter keep_everything = [] {
        FeatureFilter f;
        f.disable();
        return f;
    }();
    const FeatureFilter& use = filter != nullptr ? *filter : keep_everything;

    RegionScan scan(mem, base, size, std::move(entries), std::move(executed), arch, symbols,
                    &use);
    return collect(ruleset, scan.extractor(), base, size, use);
}

}  // namespace capa::stat
