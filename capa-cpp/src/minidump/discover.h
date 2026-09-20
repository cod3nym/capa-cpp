// Code discovery for a minidump region.
//
// The TTD static path is handed the exact set of addresses that executed. A dump has
// no such record, so the equivalent has to be reconstructed — and the output feeds
// the very same `Workspace` contract, so no new CFG machinery is needed downstream.
//
// That contract is strict and unforgiving. `Workspace::recover()` treats every
// address in `executed` as an instruction *start*, and defines a function as owning
// every executed address in `[entry, next_entry)`. It performs no overlap check. One
// address that is not really an instruction boundary therefore does not just add a
// bogus instruction: it splices phantom instructions into the basic blocks of a
// legitimate function, and those produce features that go on to match rules.
//
// So the invariant here is that the emitted `executed` set is a self-consistent
// instruction stream — no two entries overlap. Discovery walks speculatively into a
// scratch buffer and commits a walk only if it agrees with everything already
// committed; on any collision the entire walk is discarded along with the seed that
// produced it. That is what makes the prologue scan (which is inherently guessy)
// safe to run at all.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "minidump/mdmp.h"
#include "minidump/pe.h"
#include "static/disasm.h"
#include "static/memory.h"

namespace capa::mdmp {

struct Seeds {
    std::vector<std::uint64_t> entries;   // function starts; a subset of `executed`
    std::vector<std::uint64_t> executed;  // instruction starts, non-overlapping

    // diagnostics
    std::size_t code_bytes = 0;      // bytes covered by `executed`
    std::size_t region_bytes = 0;    // bytes in the region
    std::size_t rejected_walks = 0;  // seeds discarded for colliding with real code
    double coverage() const {
        return region_bytes ? static_cast<double>(code_bytes) / region_bytes : 0.0;
    }
};

struct DiscoverOptions {
    bool use_thread_seeds = true;
    bool use_stack_returns = true;
    // Prologue scanning is what finds functions in shellcode and in 32-bit modules,
    // which have no .pdata. It is off for x64 modules whose .pdata already enumerates
    // every function.
    bool use_prologue_scan = true;
    bool linear_sweep = false;  // --linear-sweep; noisiest tier, opt-in
    // Should a swept run that nothing calls start a function of its own?
    //
    // Yes for a region with no function list of its own -- otherwise the sweep finds
    // code that belongs to no function and so yields no features at all. No when the
    // container already enumerates every function (an x64 PE's .pdata): there a swept
    // run is a *fragment* of a known function -- a jump-table block, an exception
    // handler -- and promoting it to an entry splits its parent under Workspace's
    // [entry, next_entry) attribution. That is the same reasoning that keeps
    // pdata_fragments out of `entries`.
    bool sweep_seeds_are_entries = true;
    // Sub-ranges of the region that actually hold code, as [base, end) pairs. When
    // set, the two speculative tiers (prologue scan and linear sweep) are confined
    // to them, so a module's .rdata and .data are not mined for "functions". The
    // seeded tiers are not restricted: a seed is evidence in itself.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> exec_ranges;
    // Backstop so a pathological region cannot hang a run.
    std::size_t max_insns = 4'000'000;
    // Every pointer-sized word found on a thread stack, sorted. Collected once for the
    // whole dump (see collect_stack_words) rather than per region: rescanning tens of
    // megabytes of stack for each of forty regions was the most expensive thing a scan
    // did, and the answer is the same every time. Empty disables the stack tier.
    const std::vector<std::uint64_t>* stack_words = nullptr;
};

// Read every pointer-sized word off every thread's dumped stack, sorted and deduped.
// Callers hand the result to each region's discover() through
// DiscoverOptions::stack_words.
std::vector<std::uint64_t> collect_stack_words(const stat::MemoryImage& mem,
                                               const std::vector<ThreadCtx>& threads,
                                               stat::Arch arch);

// Recover the instruction stream and function entries of the region at
// [region_base, region_base+region_size). `pe` is the module mapped there, if any.
Seeds discover(const stat::MemoryImage& mem, std::uint64_t region_base,
               std::uint64_t region_size, stat::Arch arch, const std::optional<PeImage>& pe,
               const std::vector<ThreadCtx>& threads, const DiscoverOptions& opts);

}  // namespace capa::mdmp
