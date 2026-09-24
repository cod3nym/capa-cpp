#include "static/workspace.h"

#include <algorithm>
#include <limits>
#include <set>

namespace capa::stat {

Workspace::Workspace(std::uint64_t base, std::vector<std::uint8_t> bytes,
                     std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
                     Arch arch)
    : base_(base),
      region_size_(bytes.size()),
      arch_(arch),
      owned_(MemoryImage::single(base, std::move(bytes))),
      executed_(std::move(executed)) {
    mem_ = &*owned_;
    init(std::move(entries));
}

Workspace::Workspace(const MemoryImage& mem, std::uint64_t region_base,
                     std::uint64_t region_size, std::vector<std::uint64_t> entries,
                     std::vector<std::uint64_t> executed, Arch arch)
    : base_(region_base),
      region_size_(region_size),
      arch_(arch),
      mem_(&mem),
      executed_(std::move(executed)) {
    init(std::move(entries));
}

void Workspace::init(std::vector<std::uint64_t> entries) {
    std::sort(executed_.begin(), executed_.end());
    executed_.erase(std::unique(executed_.begin(), executed_.end()), executed_.end());
    recover(std::move(entries));
}

std::span<const std::uint8_t> Workspace::region_bytes() const {
    std::span<const std::uint8_t> v = mem_->view(base_);
    return v.size() > region_size_ ? v.subspan(0, static_cast<std::size_t>(region_size_)) : v;
}

DecodedInsn Workspace::decode_uncached(std::uint64_t va) const {
    // Code recovery is confined to this region even though reads are not: without
    // this check a widened is_valid_pointer would let recovery walk straight into a
    // neighbouring module.
    if (va < base_ || va - base_ >= region_size_) return DecodedInsn{};
    std::span<const std::uint8_t> v = mem_->view(va);
    if (v.empty()) return DecodedInsn{};
    return decode_one(v.data(), v.size(), va, arch_);
}

const DecodedInsn* Workspace::decode_at(std::uint64_t va) const {
    if (va < base_ || va - base_ >= region_size_) return nullptr;
    if (auto it = cache_.find(va); it != cache_.end()) return it->second.ok ? &it->second : nullptr;
    std::span<const std::uint8_t> v = mem_->view(va);
    if (v.empty()) return nullptr;
    DecodedInsn d = decode_one(v.data(), v.size(), va, arch_);
    auto [it, _] = cache_.emplace(va, std::move(d));
    return it->second.ok ? &it->second : nullptr;
}

void Workspace::recover(std::vector<std::uint64_t> entries) {
    // 1. One uncached pass over every executed address: record code xrefs from
    // concrete branch targets, and collect the call targets that become function
    // entries. Decoding here is deliberately NOT memoized -- this pass touches each
    // address exactly once, so a memo would only buy a second live copy of every
    // instruction in the region, which for a large module is hundreds of MB.
    std::set<std::uint64_t> fn;
    for (std::uint64_t e : entries)
        if (is_executed(e)) fn.insert(e);

    std::vector<std::pair<std::uint64_t, std::uint64_t>> xrefs;  // (target, src)
    // Jump-thunk candidates, confirmed after the xrefs are known (step 2b).
    std::vector<std::uint64_t> thunk_candidates;
    std::set<std::uint64_t> jumped_to;  // targets of a jump (not a call) inside the region
    std::uint64_t prev_end = 0;   // where the previous executed instruction ended
    bool prev_falls = false;      // and whether execution could continue past it
    for (std::uint64_t va : executed_) {
        DecodedInsn insn = decode_uncached(va);
        if (!insn.ok) {
            prev_falls = false;
            continue;
        }
        if ((insn.is_call || insn.is_cond_branch || insn.is_uncond_jmp) && insn.branch_target)
            xrefs.emplace_back(*insn.branch_target, va);
        if ((insn.is_cond_branch || insn.is_uncond_jmp) && insn.branch_target)
            jumped_to.insert(*insn.branch_target);
        if (insn.is_call && insn.branch_target && is_executed(*insn.branch_target))
            fn.insert(*insn.branch_target);
        // A lone unconditional jump that leaves this region's code, and that nothing
        // before it falls into. Either it is reached from outside or by a call, which makes
        // it a thunk, or by a jump inside, which step 2b rules out.
        bool const leaves = insn.is_indirect_branch ||
                            (insn.branch_target && !is_executed(*insn.branch_target));
        bool const fallen_into = prev_falls && prev_end == va;
        if (insn.is_uncond_jmp && leaves && !fallen_into) thunk_candidates.push_back(va);
        prev_end = mask_address(va + insn.length, arch_);
        prev_falls = !(insn.is_ret || insn.is_uncond_jmp);
    }

    // 2. flatten the xrefs into one sorted array plus a target index.
    std::sort(xrefs.begin(), xrefs.end());
    xrefs.erase(std::unique(xrefs.begin(), xrefs.end()), xrefs.end());
    xref_srcs_.reserve(xrefs.size());
    for (std::size_t i = 0; i < xrefs.size();) {
        const std::uint64_t target = xrefs[i].first;
        xref_index_.emplace_back(target, static_cast<std::uint32_t>(xref_srcs_.size()));
        for (; i < xrefs.size() && xrefs[i].first == target; ++i)
            xref_srcs_.push_back(xrefs[i].second);
    }
    xref_index_.shrink_to_fit();
    xref_srcs_.shrink_to_fit();

    // 2b. Jump thunks become functions of their own. Without this a table of stubs --
    // `jmp [rip+2]` then an 8-byte pointer, one per export of a module whose export table
    // was redirected -- is entered from outside at every stub but has no call inside it,
    // so the range rule below made one "function" of everything between two entries and
    // handed it the api: features of every stub it swallowed. One wmplayer trace reported
    // registry and system-information capabilities at LdrGetDllHandle's stub, each time
    // anything called LdrGetDllHandle through it. A jump from inside the region means the
    // jump is part of that code instead, so it stays put. A direct call does not: that makes
    // it a function anyway, and it forwards the same way it does when entered from outside.
    std::set<std::uint64_t> thunks;
    for (std::uint64_t va : thunk_candidates) {
        if (jumped_to.count(va) != 0) continue;
        thunks.insert(va);
        fn.insert(va);
    }

    // 3. recover each function. `executed` is ground-truth code, so a function owns every
    // executed instruction from its entry up to the next function entry (viv attributes
    // all recovered code to some function; a pure flow walk would drop blocks reached only
    // via jump tables / unfollowed edges).
    std::vector<std::uint64_t> fn_sorted(fn.begin(), fn.end());  // sorted (std::set)
    for (std::size_t i = 0; i < fn_sorted.size(); ++i) {
        std::uint64_t boundary =
            (i + 1 < fn_sorted.size()) ? fn_sorted[i + 1] : std::numeric_limits<std::uint64_t>::max();
        functions_.push_back(recover_function(fn_sorted[i], boundary));
        // Only while the jump is all it holds. Executed code after it that no entry claims
        // lands in the same function -- a jump-table case, which records no xref, or what a
        // packer's `jmp rax` reaches -- and excluding the function would drop that code's
        // features with it.
        Function& f = functions_.back();
        f.thunk = thunks.count(fn_sorted[i]) != 0 && f.blocks.size() == 1 &&
                  f.blocks[0].insns.size() == 1;
    }
    cache_.clear();
    cache_.rehash(0);
}

Function Workspace::recover_function(std::uint64_t entry, std::uint64_t boundary) const {
    // the function's instructions: every executed address in [entry, boundary) that decodes.
    std::set<std::uint64_t> visited;
    auto lo = std::lower_bound(executed_.begin(), executed_.end(), entry);
    auto hi = std::lower_bound(executed_.begin(), executed_.end(), boundary);
    for (auto it = lo; it != hi; ++it)
        if (decode_at(*it)) visited.insert(*it);
    if (visited.empty()) {
        cache_.clear();
        return Function{entry, {}};
    }

    std::vector<std::uint64_t> vas(visited.begin(), visited.end());  // sorted (from std::set)

    auto is_terminator = [](const DecodedInsn* i) {
        return i->is_ret || i->is_cond_branch || i->is_uncond_jmp;
    };

    // leaders: entry, plus the fallthrough and concrete target of every terminator.
    std::set<std::uint64_t> leaders{entry};
    for (std::uint64_t va : vas) {
        const DecodedInsn* insn = decode_at(va);
        if (!insn || !is_terminator(insn)) continue;
        std::uint64_t fall = mask_address(va + insn->length, arch_);
        if (visited.count(fall)) leaders.insert(fall);
        if ((insn->is_cond_branch || insn->is_uncond_jmp) && insn->branch_target &&
            visited.count(*insn->branch_target))
            leaders.insert(*insn->branch_target);
    }

    // split into basic blocks along leaders / terminators / address gaps.
    Function f{entry, {}};
    std::size_t i = 0, n = vas.size();
    while (i < n) {
        std::size_t j = i;
        for (;;) {
            const DecodedInsn* cur = decode_at(vas[j]);
            if (is_terminator(cur)) break;
            if (j + 1 >= n) break;
            std::uint64_t nxt = vas[j + 1];
            if (nxt != vas[j] + cur->length) break;  // non-contiguous
            if (leaders.count(nxt)) break;            // next starts a block
            ++j;
        }
        BasicBlock bb;
        bb.va = vas[i];
        for (std::size_t k = i; k <= j; ++k) bb.insns.push_back(*decode_at(vas[k]));
        const DecodedInsn& last = bb.insns.back();
        bb.size = static_cast<std::uint32_t>((last.va + last.length) - bb.va);
        f.blocks.push_back(std::move(bb));
        i = j + 1;
    }

    // ensure the entry block is first (viv f.basic_blocks[0]).
    for (std::size_t b = 1; b < f.blocks.size(); ++b) {
        if (f.blocks[b].va == entry) {
            std::swap(f.blocks[0], f.blocks[b]);
            break;
        }
    }

    // Every instruction this function kept has been copied into a basic block, so the
    // memo's copies are now dead weight. Dropping it here rather than after the whole
    // region bounds the memo at one function instead of one module -- the difference
    // between ~250 bytes per instruction of peak and ~500.
    cache_.clear();
    return f;
}

std::span<const std::uint64_t> Workspace::xrefs_to(std::uint64_t va) const {
    auto it = std::lower_bound(
        xref_index_.begin(), xref_index_.end(), va,
        [](const std::pair<std::uint64_t, std::uint32_t>& e, std::uint64_t v) {
            return e.first < v;
        });
    if (it == xref_index_.end() || it->first != va) return {};
    const std::size_t first = it->second;
    const std::size_t last =
        (it + 1 == xref_index_.end()) ? xref_srcs_.size() : (it + 1)->second;
    return std::span<const std::uint64_t>(xref_srcs_.data() + first, last - first);
}

}  // namespace capa::stat
