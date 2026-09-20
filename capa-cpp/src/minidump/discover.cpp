#include "minidump/discover.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace capa::mdmp {

namespace {

using stat::Arch;
using stat::DecodedInsn;

// The longest x86 instruction. Bounds the backward search for the call that should
// precede a stack return address, and the overlap check.
constexpr int MAX_INSN_LEN = 15;
// A prologue candidate has to decode into a plausible run before it is believed.
constexpr int PROLOGUE_CONFIRM_INSNS = 4;
// Cap on a single walk, so a self-modifying or garbage region cannot spin.
constexpr std::size_t MAX_WALK_INSNS = 200000;

// Function prologues worth guessing at. These find code in shellcode regions and in
// 32-bit modules, neither of which has a .pdata table to enumerate functions.
struct Sig {
    const std::uint8_t* bytes;
    std::size_t len;
    bool x86;
    bool x64;
};

// 32-bit frame setup. Both encodings of `mov ebp,esp` appear in the wild (MSVC emits
// 8B EC, gcc/clang 89 E5). In 64-bit mode the same instruction carries a REX.W, so
// these two are x86-only -- matching them under x64 decoding finds 32-bit register
// moves, not function starts.
const std::uint8_t SIG_PUSH_EBP_MOV[] = {0x55, 0x8B, 0xEC};        // push ebp; mov ebp,esp
const std::uint8_t SIG_PUSH_EBP_MOV2[] = {0x55, 0x89, 0xE5};       // push ebp; mov ebp,esp
// The same prologue in 64-bit mode: `mov rbp,rsp` needs the REX.W prefix. Hand-written
// x64 shellcode uses this constantly, and without these two the scan only found such a
// function if some *later* instruction happened to match another signature -- which
// records the entry several bytes into the prologue.
const std::uint8_t SIG_PUSH_RBP_MOV[] = {0x55, 0x48, 0x89, 0xE5};   // push rbp; mov rbp,rsp
const std::uint8_t SIG_PUSH_RBP_MOV2[] = {0x55, 0x48, 0x8B, 0xEC};  // push rbp; mov rbp,rsp
const std::uint8_t SIG_MOV_RSP_ARG[] = {0x48, 0x89, 0x5C, 0x24};   // mov [rsp+X],rbx
const std::uint8_t SIG_MOV_RSP_ARG2[] = {0x48, 0x89, 0x4C, 0x24};  // mov [rsp+X],rcx
const std::uint8_t SIG_MOV_RSP_ARG3[] = {0x48, 0x89, 0x54, 0x24};  // mov [rsp+X],rdx
const std::uint8_t SIG_MOV_RSP_ARG4[] = {0x48, 0x89, 0x74, 0x24};  // mov [rsp+X],rsi
const std::uint8_t SIG_SUB_RSP[] = {0x48, 0x83, 0xEC};             // sub rsp,imm8
const std::uint8_t SIG_SUB_RSP32[] = {0x48, 0x81, 0xEC};           // sub rsp,imm32
const std::uint8_t SIG_PUSH_RBX[] = {0x40, 0x53};                  // push rbx
const std::uint8_t SIG_MOV_RAX_RSP[] = {0x48, 0x8B, 0xC4};         // mov rax,rsp
const std::uint8_t SIG_MOV_R11_RSP[] = {0x4C, 0x8B, 0xDC};         // mov r11,rsp
// CET. The two are distinct instructions, not one encoding: endbr64 is F3 0F 1E FA and
// endbr32 is F3 0F 1E FB, so each belongs to exactly one mode.
const std::uint8_t SIG_ENDBR64[] = {0xF3, 0x0F, 0x1E, 0xFA};
const std::uint8_t SIG_ENDBR32[] = {0xF3, 0x0F, 0x1E, 0xFB};
const std::uint8_t SIG_SUB_ESP[] = {0x83, 0xEC};                   // sub esp,imm8
const std::uint8_t SIG_PUSH_EBP_PUSH[] = {0x55, 0x56};             // push ebp; push esi

// Order is not significant: the scan only asks WHETHER some signature matched at an
// offset, never which one, and every entry is a plausible function start on its own.
const Sig kPrologues[] = {
    {SIG_PUSH_RBP_MOV, 4, false, true},  {SIG_PUSH_RBP_MOV2, 4, false, true},
    {SIG_PUSH_EBP_MOV, 3, true, false},  {SIG_PUSH_EBP_MOV2, 3, true, false},
    {SIG_MOV_RSP_ARG, 4, false, true},   {SIG_MOV_RSP_ARG2, 4, false, true},
    {SIG_MOV_RSP_ARG3, 4, false, true},  {SIG_MOV_RSP_ARG4, 4, false, true},
    {SIG_SUB_RSP, 3, false, true},       {SIG_SUB_RSP32, 3, false, true},
    {SIG_PUSH_RBX, 2, false, true},      {SIG_MOV_RAX_RSP, 3, false, true},
    {SIG_MOV_R11_RSP, 3, false, true},   {SIG_ENDBR64, 4, false, true},
    {SIG_ENDBR32, 4, true, false},       {SIG_SUB_ESP, 2, true, false},
    {SIG_PUSH_EBP_PUSH, 2, true, false},
};

// What discovery needs to know about one instruction.
//
// Deliberately NOT a DecodedInsn. Discovery probes far more addresses than it keeps,
// and memoizing a full DecodedInsn -- 136 bytes plus a heap operand vector -- for
// each of them was the single largest allocation in a region scan. Everything the
// walk actually branches on fits in 16 bytes with no heap at all.
struct Step {
    std::uint64_t target = 0;  // concrete branch target; valid only if HAS_TARGET
    std::uint8_t length = 0;
    std::uint8_t flags = 0;

    enum : std::uint8_t {
        OK = 1 << 0,
        CALL = 1 << 1,
        COND = 1 << 2,
        UNCOND = 1 << 3,
        RET = 1 << 4,
        INDIRECT = 1 << 5,
        INT3 = 1 << 6,
        HAS_TARGET = 1 << 7,
    };
    bool has(std::uint8_t f) const { return (flags & f) != 0; }
};

// Accumulates the instruction stream, enforcing self-consistency.
class Stream {
public:
    Stream(const stat::MemoryImage& mem, std::uint64_t base, std::uint64_t size, Arch arch)
        : mem_(mem), base_(base), size_(size), arch_(arch) {}

    bool in_region(std::uint64_t va) const { return va >= base_ && va - base_ < size_; }
    bool known(std::uint64_t va) const { return len_.count(va) != 0; }
    std::size_t insn_count() const { return len_.size(); }
    std::size_t code_bytes() const { return code_bytes_; }
    std::size_t rejected() const { return rejected_; }

    // NOTE: the returned pointer is invalidated by the next call, because decode()
    // may drop the memo to stay under its cap. Copy the Step before decoding again.
    const Step* decode(std::uint64_t va) {
        if (!in_region(va)) return nullptr;
        auto it = cache_.find(va);
        if (it != cache_.end()) return it->second.has(Step::OK) ? &it->second : nullptr;
        // The memo only accelerates re-walks, so dropping it wholesale when it grows
        // past the cap costs a little rework and bounds the memory outright.
        if (cache_.size() >= MAX_MEMO) {
            cache_.clear();
            cache_.rehash(0);
        }
        Step st;
        std::span<const std::uint8_t> v = mem_.view(va);
        if (!v.empty()) {
            DecodedInsn d = stat::decode_one(v.data(), v.size(), va, arch_);
            // an instruction must not run off the end of the region
            if (d.ok && in_region(va + d.length - 1)) {
                st.length = static_cast<std::uint8_t>(d.length);
                st.flags = Step::OK;
                if (d.is_call) st.flags |= Step::CALL;
                if (d.is_cond_branch) st.flags |= Step::COND;
                if (d.is_uncond_jmp) st.flags |= Step::UNCOND;
                if (d.is_ret) st.flags |= Step::RET;
                if (d.is_indirect_branch) st.flags |= Step::INDIRECT;
                if (d.mnem == "int3") st.flags |= Step::INT3;
                if (d.branch_target) {
                    st.flags |= Step::HAS_TARGET;
                    st.target = *d.branch_target;
                }
            }
        }
        auto [ins, unused] = cache_.emplace(va, st);
        return ins->second.has(Step::OK) ? &ins->second : nullptr;
    }

    // Would committing an instruction at [va, va+len) contradict what is already
    // committed? It does if va is already known with a different length, or if it
    // falls strictly inside a committed instruction, or if a committed instruction
    // starts strictly inside it.
    bool conflicts(std::uint64_t va, std::uint32_t len) const {
        return conflicts_with(len_, va, len);
    }

    static bool conflicts_with(const std::unordered_map<std::uint64_t, std::uint8_t>& m,
                               std::uint64_t va, std::uint32_t len) {
        if (auto it = m.find(va); it != m.end()) return it->second != len;
        for (int back = 1; back <= MAX_INSN_LEN; ++back) {
            auto it = m.find(va - static_cast<std::uint64_t>(back));
            if (it != m.end() && back < it->second) return true;
        }
        for (std::uint32_t fwd = 1; fwd < len; ++fwd)
            if (m.count(va + fwd)) return true;
        return false;
    }

    struct Walk {
        bool rejected = false;
        std::vector<std::pair<std::uint64_t, std::uint32_t>> insns;  // only the new ones
    };

    // Walk forward from `seed`, following fall-through and direct branches within
    // the region. A walk that contradicts anything already committed -- or itself --
    // is rejected whole, because committing part of it would splice phantom
    // instructions into a real function.
    Walk walk(std::uint64_t seed, std::vector<std::uint64_t>* calls) {
        Walk out;
        std::vector<std::uint64_t> work{seed};
        std::unordered_set<std::uint64_t> seen;
        // this walk's own boundaries, so a jump into the middle of an instruction
        // it decoded earlier is caught too
        std::unordered_map<std::uint64_t, std::uint8_t> local;

        while (!work.empty()) {
            std::uint64_t va = work.back();
            work.pop_back();
            for (std::size_t steps = 0; steps < MAX_WALK_INSNS; ++steps) {
                if (!in_region(va)) break;
                if (!seen.insert(va).second) break;  // already walked in this pass
                const Step* d = decode(va);
                if (!d) break;  // undecodable: the walk ends here
                const Step ins = *d;  // decode() can invalidate `d`; see its comment

                if (conflicts(va, ins.length) || conflicts_with(local, va, ins.length)) {
                    ++rejected_;
                    out.rejected = true;
                    return out;
                }
                local.emplace(va, ins.length);
                if (!known(va)) out.insns.emplace_back(va, ins.length);

                const bool has_target = ins.has(Step::HAS_TARGET);
                if (ins.has(Step::CALL) && has_target && calls) calls->push_back(ins.target);

                // int3 padding between functions is not part of any of them
                if (ins.has(Step::INT3)) break;
                if (ins.has(Step::RET)) break;

                if (ins.has(Step::COND) && has_target && in_region(ins.target))
                    work.push_back(ins.target);
                if (ins.has(Step::UNCOND)) {
                    if (has_target && in_region(ins.target)) {
                        va = ins.target;
                        continue;
                    }
                    break;  // indirect or out-of-region jmp: nothing more to follow
                }
                if (ins.has(Step::INDIRECT) && !ins.has(Step::CALL)) break;
                va = stat::mask_address(va + ins.length, arch_);
            }
        }
        return out;
    }


    void commit(const std::vector<std::pair<std::uint64_t, std::uint32_t>>& insns) {
        for (const auto& [va, len] : insns) {
            if (len_.emplace(va, static_cast<std::uint8_t>(len)).second) code_bytes_ += len;
        }
    }

    std::vector<std::uint64_t> sorted_addresses() const {
        std::vector<std::uint64_t> v;
        v.reserve(len_.size());
        for (const auto& [va, _] : len_) v.push_back(va);
        std::sort(v.begin(), v.end());
        return v;
    }

private:
    const stat::MemoryImage& mem_;
    std::uint64_t base_, size_;
    Arch arch_;
    // Bounded: see decode(). Locality means the hit rate barely moves once the memo
    // is this large, and the cap is what keeps a 15 MB module out of the gigabytes.
    static constexpr std::size_t MAX_MEMO = 1000000;
    std::unordered_map<std::uint64_t, Step> cache_;
    std::unordered_map<std::uint64_t, std::uint8_t> len_;
    std::size_t code_bytes_ = 0;
    std::size_t rejected_ = 0;
};

}  // namespace

std::vector<std::uint64_t> collect_stack_words(const stat::MemoryImage& mem,
                                               const std::vector<ThreadCtx>& threads,
                                               stat::Arch arch) {
    const int native = stat::pointer_size(arch);
    std::vector<std::uint64_t> out;
    for (const ThreadCtx& t : threads) {
        if (t.stack_size == 0 || t.stack_size > 8ull * 1024 * 1024) continue;
        // Pointer width is the THREAD's, not the dump's. A 64-bit dumper records a
        // WOW64 process as Amd64, so reading its 32-bit threads' stacks in 8-byte
        // words glues pairs of unrelated values together and yields no usable return
        // addresses at all -- silently disabling this tier for exactly the 32-bit
        // modules that need it most, since they have no .pdata to fall back on.
        const int psize = t.wow64_32 ? 4 : native;
        for (std::uint64_t off = 0; off + psize <= t.stack_size; off += psize)
            if (auto v = mem.read_pointer(t.stack_base + off, psize)) out.push_back(*v);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

Seeds discover(const stat::MemoryImage& mem, std::uint64_t region_base,
               std::uint64_t region_size, Arch arch, const std::optional<PeImage>& pe,
               const std::vector<ThreadCtx>& threads, const DiscoverOptions& opts) {
    Stream stream(mem, region_base, region_size, arch);

    std::vector<std::uint64_t> entry_candidates;
    std::vector<std::uint64_t> pending;  // seeds still to walk
    std::vector<std::uint64_t> call_targets;

    auto want = [&](std::uint64_t va) {
        if (stream.in_region(va)) pending.push_back(va);
    };
    auto want_entry = [&](std::uint64_t va) {
        if (stream.in_region(va)) {
            entry_candidates.push_back(va);
            pending.push_back(va);
        }
    };

    // ---- tier 1: what the container already knows ----
    if (pe) {
        want_entry(pe->entry_point);
        for (std::uint64_t cb : pe->tls_callbacks) want_entry(cb);
        for (const PeExport& e : pe->exports)
            if (e.forwarded.empty()) want_entry(e.va);
        for (std::uint64_t f : pe->pdata_starts) want_entry(f);
        // Chained-unwind entries are fragments of a function that begins elsewhere.
        // They are code and worth walking, but making them entries would split the
        // parent function apart under Workspace's [entry, next_entry) attribution.
        for (std::uint64_t f : pe->pdata_fragments) want(f);
    }

    if (opts.use_thread_seeds)
        for (const ThreadCtx& t : threads) want(t.pc);

    // ---- tier 2: recursive descent, with call targets feeding back as entries ----
    auto drain = [&]() {
        std::size_t guard = 0;
        while (!pending.empty() && stream.insn_count() < opts.max_insns) {
            if (++guard > 1'000'000) break;
            std::uint64_t seed = pending.back();
            pending.pop_back();
            if (stream.known(seed)) continue;
            call_targets.clear();
            Stream::Walk w = stream.walk(seed, &call_targets);
            if (w.rejected) continue;  // a bad seed; its call targets are not trustworthy
            stream.commit(w.insns);
            for (std::uint64_t t : call_targets) {
                if (!stream.in_region(t)) continue;  // a call into another module
                entry_candidates.push_back(t);
                if (!stream.known(t)) pending.push_back(t);
            }
        }
    };
    drain();

    // ---- tier 3: stack return addresses ----
    //
    // A value on a thread's stack that points into this region and is immediately
    // preceded by a call instruction is a return address, which means the code
    // before it really executed. The "preceded by a call" test is what keeps the
    // false-positive rate usable; without it every stale stack word is a seed.
    if (opts.use_stack_returns && opts.stack_words && !opts.stack_words->empty()) {
        // The words are sorted, so only the slice that lands inside this region needs
        // looking at -- the rest belong to some other region and were already read
        // once, for the whole dump, before any region was scanned.
        const std::vector<std::uint64_t>& words = *opts.stack_words;
        auto lo = std::lower_bound(words.begin(), words.end(), region_base);
        auto hi = std::lower_bound(words.begin(), words.end(), region_base + region_size);
        for (auto it = lo; it != hi; ++it) {
            const std::uint64_t v = *it;
            if (stream.known(v)) continue;
            // a call whose length lands exactly on the candidate. x86 call encodings
            // run to 7 bytes, and to 8 once a REX prefix is involved.
            bool preceded = false;
            for (int back = 2; back <= 8 && !preceded; ++back) {
                std::uint64_t cva = v - static_cast<std::uint64_t>(back);
                if (!stream.in_region(cva)) continue;
                const Step* d = stream.decode(cva);
                if (d && d->has(Step::CALL) && d->length == static_cast<std::uint8_t>(back))
                    preceded = true;
            }
            if (preceded) pending.push_back(v);
        }
        drain();
    }

    // ---- tier 4: prologue signatures over what is left ----
    //
    // This is the only tier that guesses, and the Stream's conflict rule is what
    // makes it safe: a candidate that disagrees with proven code is discarded whole.
    // Speculative tiers only run where code can actually live.
    auto speculative_here = [&](std::uint64_t va) {
        if (opts.exec_ranges.empty()) return true;
        for (const auto& [lo, hi] : opts.exec_ranges)
            if (va >= lo && va < hi) return true;
        return false;
    };

    if (opts.use_prologue_scan) {
        std::span<const std::uint8_t> view = mem.view(region_base);
        const std::size_t n =
            static_cast<std::size_t>(std::min<std::uint64_t>(region_size, view.size()));
        for (std::size_t off = 0; off + 2 <= n; ++off) {
            std::uint64_t va = region_base + off;
            if (stream.known(va)) continue;
            if (!speculative_here(va)) continue;
            bool hit = false;
            for (const Sig& sig : kPrologues) {
                if (arch == Arch::X86 ? !sig.x86 : !sig.x64) continue;
                if (off + sig.len > n) continue;
                if (std::memcmp(view.data() + off, sig.bytes, sig.len) == 0) {
                    hit = true;
                    break;
                }
            }
            if (!hit) continue;

            // Believe it only if a short run decodes cleanly from here.
            std::uint64_t probe = va;
            int ok = 0;
            for (; ok < PROLOGUE_CONFIRM_INSNS; ++ok) {
                const Step* d = stream.decode(probe);
                if (!d) break;
                const Step step = *d;  // decode() can invalidate `d`
                if (step.has(Step::RET) || step.has(Step::UNCOND)) {
                    ++ok;
                    break;
                }
                probe = stat::mask_address(probe + step.length, arch);
            }
            if (ok < PROLOGUE_CONFIRM_INSNS) continue;

            call_targets.clear();
            Stream::Walk w = stream.walk(va, &call_targets);
            if (w.rejected || w.insns.empty()) continue;
            stream.commit(w.insns);
            entry_candidates.push_back(va);
            for (std::uint64_t t : call_targets)
                if (stream.in_region(t)) {
                    entry_candidates.push_back(t);
                    if (!stream.known(t)) pending.push_back(t);
                }
            drain();
        }
    }

    // ---- tier 5: linear sweep of the gaps (opt-in) ----
    //
    // The sweep collects call targets like every other tier. Without that it produced
    // instructions that belonged to no function at all: Workspace attributes code to
    // the nearest preceding entry, so a sweep that contributed no entries contributed
    // no features either -- it looked like it was working and found nothing.
    if (opts.linear_sweep) {
        std::span<const std::uint8_t> view = mem.view(region_base);
        const std::size_t n =
            static_cast<std::size_t>(std::min<std::uint64_t>(region_size, view.size()));
        for (std::size_t off = 0; off < n; ++off) {
            std::uint64_t va = region_base + off;
            if (stream.known(va)) continue;
            if (!speculative_here(va)) continue;
            call_targets.clear();
            Stream::Walk w = stream.walk(va, &call_targets);
            if (w.rejected || w.insns.empty()) continue;
            stream.commit(w.insns);
            // `va` was unknown before this walk, so it begins a run no earlier tier
            // reached -- the same reasoning that makes a confirmed prologue an entry.
            // Suppressed where the container already knows every function; see
            // DiscoverOptions::sweep_seeds_are_entries.
            if (opts.sweep_seeds_are_entries) entry_candidates.push_back(va);
            // A call target is an unambiguous function start either way.
            for (std::uint64_t t : call_targets)
                if (stream.in_region(t)) entry_candidates.push_back(t);
        }
    }

    Seeds out;
    out.executed = stream.sorted_addresses();
    out.code_bytes = stream.code_bytes();
    out.region_bytes = static_cast<std::size_t>(region_size);
    out.rejected_walks = stream.rejected();

    // An entry is only meaningful if it really is an instruction start we kept.
    std::sort(entry_candidates.begin(), entry_candidates.end());
    entry_candidates.erase(std::unique(entry_candidates.begin(), entry_candidates.end()),
                           entry_candidates.end());
    for (std::uint64_t e : entry_candidates)
        if (stream.known(e)) out.entries.push_back(e);

    return out;
}

}  // namespace capa::mdmp
