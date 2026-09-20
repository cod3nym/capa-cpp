// Driving capa's static engine over a process minidump.
//
// Each selected region is analysed on its own: its own code discovery, its own
// Workspace, its own ModuleContext, and its own pass through the shared
// find_static_capabilities driver. Memory, and the export/IAT maps, are shared
// across all of them, which is what lets a call in a shellcode region resolve
// against ntdll's export table.
//
// File scope is therefore per region rather than dump-wide, which is both what the
// region-attributed output wants and the only tractable option: merging the
// FeatureSets of forty modules would mean holding every string in every image at
// once.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "engine.h"
#include "minidump/discover.h"
#include "minidump/process.h"
#include "render.h"
#include "rules.h"
#include "static_caps.h"

namespace capa::mdmp {

struct ScanOptions {
    // Include modules under \Windows\System32, SysWOW64 and WinSxS. Off by default:
    // they are tens of MB of Microsoft code that will match rules without telling
    // you anything about the sample.
    bool all_modules = false;
    std::optional<std::uint64_t> only_region;  // --region <hex>
    std::string only_module;                   // --module <name>
    bool linear_sweep = false;
    std::optional<stat::Arch> force_arch;  // --region-arch, for headerless regions
    // Regions larger than this are skipped with a warning rather than silently
    // costing minutes.
    std::uint64_t max_region_size = 64ull * 1024 * 1024;
    bool progress = true;  // per-region progress on stderr
    // Drop extracted features no rule can read before they reach a scope-wide feature
    // set. On by default because it cannot change a match (see feature_filter.h) and
    // because without it a mapped module image contributes one `string:` feature per
    // printable run in it; --no-feature-filter turns it off for parity runs.
    bool feature_filter = true;
};

struct MinidumpCapabilities {
    MatchResults matches;  // merged across every scanned region

    // ResultDocument material, already in capa's static shape.
    std::vector<render::StaticFunction> layout;
    std::vector<std::pair<Address, std::size_t>> function_feature_counts;
    std::size_t file_feature_count = 0;
    std::vector<render::RegionInfo> region_infos;
    std::size_t function_count = 0;
    std::size_t scanned_regions = 0;
    std::size_t skipped_regions = 0;
};

// Which regions `opts` selects, in address order. Exposed so the CLI can report the
// plan without running it.
std::vector<const Region*> select_regions(const ProcessImage& img, const ScanOptions& opts);

MinidumpCapabilities scan(const RuleSet& rules, const ProcessImage& img,
                          const ScanOptions& opts);

// Build the renderer's Doc for a completed scan.
render::Doc build_doc(const ProcessImage& img, const MinidumpCapabilities& caps,
                      const std::vector<std::string>& argv);

}  // namespace capa::mdmp
