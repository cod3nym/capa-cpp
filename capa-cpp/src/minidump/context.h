// The per-region ModuleContext for backends that can see process memory.
//
// This is where a dump's extra knowledge is turned into capa features: the PE
// container behind a region becomes `format`/`section`/`export`/`import`, and the
// process-wide export and IAT maps turn a call instruction into `api: CreateFileW`.
//
// It was written for the minidump path and still lives with it, but nothing here is
// minidump-specific: it needs memory, a symbol map, and optionally the PE behind the
// region. The TTD `--scan-code` path supplies the same three from a trace -- the
// region dumps as memory and the module list the recorder wrote into the manifest as
// symbols -- and goes through the backend-neutral constructor below.
//
// The API resolution ladder is the interesting part, and its second rung is what
// distinguishes a memory dump from an on-disk binary: when a call goes through a
// slot, the slot's *stored value* is looked up in the export map. That resolves an
// IAT the loader already filled in, a delay-load slot already bound, and — most
// usefully — a function-pointer table a piece of shellcode built for itself with
// GetProcAddress, which has no import table at all.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "minidump/process.h"
#include "static/module_context.h"

namespace capa::mdmp {

class RegionContext : public stat::ModuleContext {
public:
    // `img` and `region` must outlive this context.
    RegionContext(const ProcessImage& img, const Region& region);

    // Backend-neutral form. `mem` and `syms` must outlive this context, and so must
    // `pe` when it is not null -- a null `pe` means the region is not a container,
    // which is how a shellcode region says `format: sc32`/`sc64` and emits no
    // section/export/import features.
    RegionContext(const stat::MemoryImage& mem, const SymbolMap& syms, stat::Arch arch,
                  std::uint64_t base, const PeImage* pe);

    void resolve_api(const stat::Workspace& ws, const stat::BasicBlock& bb,
                     const stat::DecodedInsn& insn,
                     std::vector<stat::ResolvedApi>& out) const override;
    const std::vector<FeaturePair>& file_features() const override { return file_; }
    const std::vector<FeaturePair>& global_features() const override { return global_; }
    int section_index(std::uint64_t va) const override;

private:
    // from_slot and from_target call each other: a slot's stored pointer may name a
    // thunk, and a thunk may jump through another slot. `hops` is the budget SHARED
    // by the whole chain, and it must be -- a per-call counter is no bound at all
    // when the two functions alternate. A slot whose value points at `jmp [that same
    // slot]` is a two-step cycle, and the resulting infinite recursion overflows the
    // stack, which unlike bad_alloc cannot be caught.
    bool from_slot(const stat::Workspace& ws, std::uint64_t slot, stat::ResolvedApi& out,
                   int hops) const;
    // Resolve a direct branch target, following thunk chains.
    bool from_target(const stat::Workspace& ws, std::uint64_t target, stat::ResolvedApi& out,
                     int hops) const;
    // Recover the constant an indirect call's register was loaded with, by scanning
    // backwards within its basic block.
    bool track_register(const stat::BasicBlock& bb, const stat::DecodedInsn& insn, int reg,
                        std::uint64_t& value, bool& is_slot) const;

    const stat::MemoryImage& mem_;
    const SymbolMap& syms_;
    stat::Arch arch_;
    std::uint64_t base_;
    const PeImage* pe_;  // non-owning; null when the region is not a PE
    std::vector<FeaturePair> file_;
    std::vector<FeaturePair> global_;
    // [start, end) per section, with a usable end even when VirtualSize is 0.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> sections_;
};

}  // namespace capa::mdmp
