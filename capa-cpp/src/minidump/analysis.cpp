#include "minidump/analysis.h"

#include "feature_filter.h"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <iterator>

#include "hashes.h"
#include "minidump/context.h"
#include "static/extractor.h"

namespace capa::mdmp {

namespace {

constexpr std::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

std::string hexs(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

bool name_matches(const Region& r, const std::string& want) {
    if (want.empty()) return true;
    std::string a = r.name, b = want;
    std::transform(a.begin(), a.end(), a.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(b.begin(), b.end(), b.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return a.find(b) != std::string::npos;
}

}  // namespace

std::vector<const Region*> select_regions(const ProcessImage& img, const ScanOptions& opts) {
    std::vector<const Region*> out;
    for (const Region& r : img.regions) {
        if (!r.exec) continue;
        if (opts.only_region && r.base != *opts.only_region) continue;
        if (!name_matches(r, opts.only_module)) continue;
        // System DLLs are excluded by default: their exports are what make calls
        // resolvable, but scanning their code finds Microsoft's capabilities, not
        // the sample's.
        if (r.is_system() && !opts.all_modules && !opts.only_region &&
            opts.only_module.empty())
            continue;
        // A .NET module's .text holds IL, which Zydis would decode into confident
        // nonsense. The JIT'd native code lives in private RWX regions, which the
        // shellcode path picks up anyway.
        if (r.pe && r.pe->is_dotnet) continue;
        if (r.pe && r.pe->is_arm64) continue;
        out.push_back(&r);
    }
    return out;
}

MinidumpCapabilities scan(const RuleSet& rules, const ProcessImage& img,
                          const ScanOptions& opts) {
    MinidumpCapabilities out;
    std::vector<const Region*> regions = select_regions(img, opts);

    // Built once for the whole dump: it depends only on the rules, and every region
    // scan below consults it. Without it a region's file-scope features are one
    // `string:` per printable run in a mapped module image, and its function-scope
    // features are one `number:` per distinct operand -- neither bounded by anything
    // the ruleset can read. See feature_filter.h.
    FeatureFilter filter = FeatureFilter::from_ruleset(rules);
    if (!opts.feature_filter) filter.disable();

    // Read the thread stacks once for the whole dump. Each region then takes the slice
    // of the sorted result that falls inside it; doing this per region meant rescanning
    // every stack for every region, which on a dump with forty regions and thirty
    // threads was the single most expensive thing a scan did.
    const std::vector<std::uint64_t> stack_words =
        collect_stack_words(img.memory, img.dump.threads(), img.native_arch);

    for (const Region* r : regions) {
        if (r->size > opts.max_region_size) {
            if (opts.progress)
                std::fprintf(stderr, "[capa] skipping %s: %llu MiB exceeds --max-region-size\n",
                             r->name.c_str(),
                             static_cast<unsigned long long>(r->size / (1024 * 1024)));
            ++out.skipped_regions;
            continue;
        }

        const stat::Arch arch = opts.force_arch && !r->pe ? *opts.force_arch : r->arch;

        DiscoverOptions dopts;
        dopts.linear_sweep = opts.linear_sweep;
        dopts.stack_words = &stack_words;
        // An x64 module's .pdata already enumerates every function, so guessing at
        // prologues would only add noise. Everything else needs the scan: 32-bit
        // modules have no .pdata, and shellcode has no metadata at all.
        dopts.use_prologue_scan =
            !r->pe || r->pe->pdata_starts.empty() || arch == stat::Arch::X86;
        // Same condition, same reason: where .pdata already names every function, a
        // swept run is part of one of them rather than a new one.
        dopts.sweep_seeds_are_entries = dopts.use_prologue_scan;
        if (r->pe) {
            for (const PeSection& s : r->pe->sections)
                if (s.characteristics & IMAGE_SCN_MEM_EXECUTE)
                    dopts.exec_ranges.emplace_back(s.va, s.va + s.vsize);
        }

        // A region is analysed on its own, so a region that cannot be analysed should
        // cost that region and nothing else. Without this an allocation failure part
        // way through a 40-region dump aborted the process and produced no output at
        // all -- the worst possible outcome for a tool whose input size is not under
        // the analyst's control.
        Seeds seeds;
        try {
            seeds = discover(img.memory, r->base, r->size, arch, r->pe, img.dump.threads(),
                             dopts);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[capa] skipping %s: code discovery failed (%s)\n",
                         r->name.c_str(), e.what());
            ++out.skipped_regions;
            continue;
        }

        if (opts.progress)
            std::fprintf(stderr,
                         "[capa] %-34s %-14s %s  %zu insn(s), %zu entry(ies), %.0f%% of region"
                         "%s\n",
                         r->name.c_str(), region_kind_name(r->kind),
                         arch == stat::Arch::X86 ? "x86" : "x64", seeds.executed.size(),
                         seeds.entries.size(), 100.0 * seeds.coverage(),
                         seeds.rejected_walks ? "  (some seeds rejected)" : "");

        if (seeds.executed.empty()) continue;

        StaticCapabilities caps;
        try {
            RegionContext ctx(img, *r);
            // Moved, not copied: these parameters are by-value, so passing lvalues
            // handed the Workspace its own copy of `executed` -- tens of megabytes on
            // a large module -- and left the original alive right through
            // find_static_capabilities, which is the peak phase. Nothing below reads
            // the seeds again.
            stat::StaticExtractor ex(img.memory, r->base, r->size, std::move(seeds.entries),
                                     std::move(seeds.executed), arch, &ctx, &filter);
            caps = find_static_capabilities(rules, ex, filter);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[capa] skipping %s: analysis failed (%s)\n", r->name.c_str(),
                         e.what());
            ++out.skipped_regions;
            continue;
        }

        // ---- merge ----
        // Moved, not copied: `caps` dies at the end of this iteration, and a match
        // tree is expensive enough that briefly holding two copies of every region's
        // matches is a large fraction of a scan's peak memory.
        for (auto& [name, results] : caps.matches) {
            auto& d = out.matches[name];
            d.insert(d.end(), std::make_move_iterator(results.begin()),
                     std::make_move_iterator(results.end()));
        }
        caps.matches.clear();
        for (const FunctionInfo& fi : caps.functions) {
            out.layout.push_back({fi.address, fi.matched_basic_blocks, r->name});
            out.function_feature_counts.emplace_back(fi.address, fi.feature_count);
        }
        out.function_count += caps.function_count;
        // Per-region file scope; the document reports the largest, which is the
        // closest single number to "how much did the file-scope pass see".
        out.file_feature_count = std::max(out.file_feature_count, caps.feature_count);
        ++out.scanned_regions;

        render::RegionInfo ri;
        ri.base = r->base;
        ri.size = r->size;
        ri.name = r->name;
        ri.kind = region_kind_name(r->kind);
        ri.path = r->path;
        ri.arch = arch == stat::Arch::X86 ? ARCH_I386 : ARCH_AMD64;
        out.region_infos.push_back(std::move(ri));
    }

    return out;
}

render::Doc build_doc(const ProcessImage& img, const MinidumpCapabilities& caps,
                      const std::vector<std::string>& argv) {
    render::Doc doc;
    doc.flavor = render::Flavor::Static;
    doc.extractor_name = "MinidumpExtractor";
    // What was analysed is the dump file, so that is what meta.sample identifies.
    // Without this every minidump report opened with three blank hash rows and the
    // JSON carried empty strings -- a result document that cannot say what produced
    // it is of limited use as evidence.
    if (const std::uint8_t* p = img.dump.file_data(); p && img.dump.file_size()) {
        // One pass, not three: `p` is the mapped dump and can be gigabytes.
        hashes::Digests d = hashes::all(p, static_cast<std::size_t>(img.dump.file_size()));
        doc.hashes = SampleHashes{std::move(d.md5), std::move(d.sha1), std::move(d.sha256)};
    }
    doc.os = OS_WINDOWS;
    doc.arch = img.native_arch == stat::Arch::X86 ? ARCH_I386 : ARCH_AMD64;
    // A process dump spans several containers at once. `pe` is the honest answer for
    // a run that scanned any mapped module, which is the normal case; a run that
    // only found unbacked code reports shellcode instead.
    bool any_pe = false;
    for (const render::RegionInfo& r : caps.region_infos)
        if (r.kind == std::string("exe") || r.kind == std::string("module") ||
            r.kind == std::string("system") || r.kind == std::string("mapped-module"))
            any_pe = true;
    doc.format = any_pe ? FORMAT_PE
                        : (img.native_arch == stat::Arch::X86 ? FORMAT_SC32 : FORMAT_SC64);

    doc.static_layout = caps.layout;
    doc.scope_feature_counts = caps.function_feature_counts;
    doc.file_feature_count = caps.file_feature_count;
    doc.regions = caps.region_infos;

    for (std::size_t k = 0; k + 1 < argv.size(); ++k)
        if (argv[k] == "-r" || argv[k] == "--rules-dir") doc.rule_paths.push_back(argv[k + 1]);

    // doc.base_address and doc.library_functions stay at their defaults (NO_ADDRESS,
    // empty): a multi-region scan has no single base address, and MinidumpCapabilities
    // does not track library functions of its own. See the fields' comment in render.h.

    return doc;
}

}  // namespace capa::mdmp
