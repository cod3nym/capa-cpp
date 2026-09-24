// Seeded code/CFG recovery for capa-cpp's static path.
//
// A Workspace covers ONE region of code: `functions()` are recovered only from
// addresses inside `[base, base + region_size)`. Memory reads, by contrast, see the
// whole `MemoryImage` — resolving an API call means following an IAT slot in one
// module into another module's export table, and a string pointer may well point
// outside the region that referenced it.
//
// Recovery itself is seeded rather than speculative: every address in `executed` is
// taken as an instruction, and every `entry` (plus every concrete call target) begins
// a function. The TTD `--scan-code` path gets those seeds from the trace; the
// minidump path reconstructs them (see minidump/discover.h). Either way the contract
// is the same, and it is strict: `executed` must be a self-consistent instruction
// stream, because a function is defined as owning *every* executed address in
// `[entry, next_entry)`. An address that is not a real instruction start injects
// phantom instructions into a legitimate function.
//
// This models the slice of a vivisect workspace the static viv extractor uses:
// functions -> basic blocks -> instructions, code xrefs, and a permission-free
// memory view for pointer/string/bytes dereferences.
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "static/disasm.h"
#include "static/memory.h"

namespace capa::stat {

struct BasicBlock {
    std::uint64_t va = 0;
    std::uint32_t size = 0;             // bytes spanned (last insn end - va)
    std::vector<DecodedInsn> insns;     // in address order
};

struct Function {
    std::uint64_t va = 0;
    std::vector<BasicBlock> blocks;     // blocks[0] is the entry block
    // A jump thunk: a function that is one unconditional jump, not reached by a jump from
    // inside the region, that only forwards to something else. See Workspace::recover.
    bool thunk = false;
};

class Workspace {
public:
    // Owning: one reconstructed region mapped at `base`, nothing else visible.
    // This is the TTD `--scan-code` path and it behaves exactly as it always has.
    Workspace(std::uint64_t base, std::vector<std::uint8_t> bytes,
              std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
              Arch arch);

    // Borrowing: code recovery is confined to [region_base, region_base+region_size),
    // but reads see all of `mem`, which must outlive this Workspace.
    Workspace(const MemoryImage& mem, std::uint64_t region_base, std::uint64_t region_size,
              std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
              Arch arch);

    // Neither copyable nor movable. The owning constructor points `mem_` at its own
    // `owned_`, and a compiler-generated move would copy that pointer verbatim while
    // move-constructing a new `owned_` in the destination -- leaving `mem_` aimed at
    // the moved-from source. Nothing would crash; every read would just come back
    // empty and the region would silently yield no features. Deleting these turns
    // that into a compile error instead.
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;
    Workspace(Workspace&&) = delete;
    Workspace& operator=(Workspace&&) = delete;

    std::uint64_t base() const { return base_; }
    std::uint64_t region_size() const { return region_size_; }
    Arch arch() const { return arch_; }
    const std::vector<Function>& functions() const { return functions_; }
    const MemoryImage& memory() const { return *mem_; }
    // This region's own bytes, for file-scope carving / string scanning. A view, not
    // a copy: a module image is megabytes.
    std::span<const std::uint8_t> region_bytes() const;

    // code xrefs (call/jmp) TO va; empty if none. Backed by one flat array rather
    // than a vector per target: a large module has hundreds of thousands of branch
    // targets, and a heap vector each is most of a Workspace's memory.
    std::span<const std::uint64_t> xrefs_to(std::uint64_t va) const;

    // ---- permission-free memory view (the whole image, not just this region) ----
    bool is_valid_pointer(std::uint64_t va) const { return mem_->is_mapped(va); }
    // read up to n bytes, clamped to the end of the containing segment; empty if
    // va is not mapped.
    std::vector<std::uint8_t> read(std::uint64_t va, std::size_t n) const {
        return mem_->read(va, n);
    }
    // little-endian pointer of the architecture's width (4 bytes on x86, 8 on x64)
    std::optional<std::uint64_t> read_pointer(std::uint64_t va) const {
        return mem_->read_pointer(va, pointer_size(arch_));
    }

    // vivisect read_string: an ASCII or UTF-16LE string starting at va, else nullopt.
    std::optional<std::string> read_string(std::uint64_t va) const {
        return mem_->read_string(va);
    }
    bool is_probably_string(std::uint64_t va) const { return mem_->is_probably_string(va); }

    // Decode one instruction, memoized. nullptr if `va` is outside this Workspace's
    // region or does not decode. The memo is scoped to one function's recovery (see
    // recover_function), so it never holds a whole region's instructions at once.
    const DecodedInsn* decode_at(std::uint64_t va) const;

    // Decode without touching the memo. Used by the single pass over `executed`
    // that builds xrefs and call-target entries: that pass visits each address once,
    // so caching it would only buy a second copy of every instruction in the region.
    DecodedInsn decode_uncached(std::uint64_t va) const;

private:
    void init(std::vector<std::uint64_t> entries);  // shared ctor tail
    void recover(std::vector<std::uint64_t> entries);
    // recover the function starting at `entry`, owning every executed instruction in
    // [entry, boundary) (boundary == the next function entry, or UINT64_MAX).
    Function recover_function(std::uint64_t entry, std::uint64_t boundary) const;

    std::uint64_t base_ = 0;
    std::uint64_t region_size_ = 0;
    Arch arch_ = Arch::X64;
    // engaged only for the owning constructor; `mem_` points at it or at a caller's.
    std::optional<MemoryImage> owned_;
    const MemoryImage* mem_ = nullptr;

    bool is_executed(std::uint64_t va) const {
        return std::binary_search(executed_.begin(), executed_.end(), va);
    }

    std::vector<std::uint64_t> executed_;  // sorted, deduped, decodable
    // Cleared after every function; see recover_function.
    mutable std::unordered_map<std::uint64_t, DecodedInsn> cache_;

    std::vector<Function> functions_;
    // xrefs, as a sorted (target -> [first, last) into xref_srcs_) index over one
    // flat source array.
    std::vector<std::pair<std::uint64_t, std::uint32_t>> xref_index_;
    std::vector<std::uint64_t> xref_srcs_;
};

}  // namespace capa::stat
