// Per-dump scanning for capa-cpp's reconstructed-region (TTD `--scan-code`) path.
//
// The scope walk itself is backend-neutral and lives in static_caps.h; this header
// only covers what is specific to scanning one reconstructed memory snapshot.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rules.h"
#include "static/extractor.h"
#include "static/manifest.h"
#include "static/symbol_map.h"
#include "static_caps.h"

namespace capa::stat {

// Index every module the manifest recorded, so a call into one can be named.
//
// Without this a reconstructed region is scanned in the dark: its calls out are
// `call [rbx+0x28]` through a table of addresses that mean nothing on their own, and
// the ~500 capa rules written against `api:` cannot fire. With it, that same table
// reads as GetTokenInformation / CreateNamedPipeA / CreateProcessAsUserA.
//
// Returns an empty map when the manifest predates `modules`, and scan_dump then
// behaves exactly as it did before.
SymbolMap build_symbol_map(const Manifest& manifest);

// One region snapshot, prepared for scanning.
//
// Owns the PE parsed out of the region if it is one, the per-region symbol map and
// the ModuleContext tying them together -- so it has to outlive any use of the
// extractor it hands out. Both the rule scan and --scan-dump-features go through it,
// which is what keeps the feature dump an honest account of what the scan itself sees.
//
// Held behind a pointer so this header stays free of the PE and ModuleContext types,
// which live with the minidump backend.
class RegionScan {
public:
    // `mem` is the whole trace's address space as of this snapshot (see TraceImage)
    // and must outlive this object; [base, base + size) is the region to scan within
    // it. `symbols` may be null, and then only a PE the region carries itself can
    // name anything.
    RegionScan(const MemoryImage& mem, std::uint64_t base, std::uint64_t size,
               std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
               Arch arch, const SymbolMap* symbols, const FeatureFilter* filter = nullptr);
    ~RegionScan();
    RegionScan(const RegionScan&) = delete;
    RegionScan& operator=(const RegionScan&) = delete;

    const StaticExtractor& extractor() const;
    // Whether the snapshot parsed as a mapped PE -- an injected or reflectively
    // loaded module, which brings its own imports, sections and entry points.
    bool is_pe() const;
    // The mode the region was actually decoded in. The manifest names one architecture
    // for the whole trace -- the recorded process's own -- but a region can disagree
    // with it: a WOW64 process holds 32-bit code alongside 64-bit modules, and either
    // width can be injected into the other. A PE says which it is, and is believed.
    Arch arch() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// One user-facing rule hit within a single scanned dump.
struct DumpHit {
    std::string namespace_;
    // The rule's static scope ("function" / "basic block" / "instruction" / "file"),
    // which is what every VA in `vas` is an address *of*. Empty when the rule declares
    // no static scope. Without this a consumer cannot tell a precise match from a
    // function entry that merely contains one.
    std::string scope;
    bool has_offset = false;
    std::int64_t offset = 0;  // min match VA - base (offset into the dump)
    int count = 0;
    std::vector<std::uint64_t> vas;  // all absolute executable match VAs, sorted/unique
    // Where the rule's own features matched, keyed by the container VA in `vas` the
    // match is filed under. A container address answers "when did the thing holding
    // this start running"; these answer "where is the thing". Grouped rather than
    // flat because one rule commonly matches in many functions across a region, and a
    // feature address is only meaningful against the container it was found in.
    //
    // Values are sorted/unique and always inside the scanned region. May be empty for
    // a container whose rule matched only on features that carry no useful site.
    std::map<std::uint64_t, std::vector<std::uint64_t>> feature_vas;
};

// capa-static one reconstructed region snapshot: returns {rule -> hit}, filtered to
// user-facing rules (drops subscope, internal/*, and library rules). Mirrors
// ttd_static_scan.py::scan_dump.
//
// `mem` is the trace's address space as of this snapshot; only [base, base + size) is
// scanned, but calls and pointers may reach anywhere in it. `symbols` is the trace's
// export map, or null.
std::map<std::string, DumpHit> scan_dump(const RuleSet& ruleset, const MemoryImage& mem,
                                         std::uint64_t base, std::uint64_t size,
                                         std::vector<std::uint64_t> entries,
                                         std::vector<std::uint64_t> executed, Arch arch,
                                         const SymbolMap* symbols = nullptr,
                                         const FeatureFilter* filter = nullptr);

}  // namespace capa::stat
