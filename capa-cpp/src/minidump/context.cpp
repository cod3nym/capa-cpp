#include "minidump/context.h"

#include <algorithm>

#include "extract_helpers.h"
#include "static/workspace.h"
#include "symbols.h"

namespace capa::mdmp {

namespace {

using stat::DecodedInsn;
using stat::OperKind;
using stat::Operand;
using stat::ResolvedApi;

// How far back within a basic block to look for the load that set up an indirect
// call's target register.
constexpr int MAX_BACK_SCAN = 20;

Address va_addr(std::uint64_t va) { return Address::absolute(va); }

// An endbr64 (CET) prologue sits in front of many indirect-call targets; capa's viv
// extractor steps over it when chasing a thunk chain, and so do we.
bool is_endbr(const std::uint8_t* p, std::size_t n) {
    return n >= 3 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E;
}

}  // namespace

RegionContext::RegionContext(const ProcessImage& img, const Region& region)
    : RegionContext(img.memory, img.symbols, region.arch, region.base,
                    region.pe ? &*region.pe : nullptr) {}

RegionContext::RegionContext(const stat::MemoryImage& mem, const SymbolMap& syms,
                             stat::Arch arch, std::uint64_t base, const PeImage* pe_or_null)
    : mem_(mem), syms_(syms), arch_(arch), base_(base), pe_(pe_or_null) {
    // ---- global: os, arch, format ----
    //
    // `format` is what gates the 29 rules that name one. A mapped module really is a
    // PE; an unbacked region is shellcode, and capa spells that sc32 / sc64.
    const bool x86 = arch_ == stat::Arch::X86;
    global_.emplace_back(Feature::os(OS_WINDOWS), Address::no_address());
    global_.emplace_back(Feature::arch(x86 ? ARCH_I386 : ARCH_AMD64), Address::no_address());
    global_.emplace_back(
        Feature::format(pe_ ? FORMAT_PE : (x86 ? FORMAT_SC32 : FORMAT_SC64)),
        Address::no_address());

    if (!pe_) return;
    const PeImage& pe = *pe_;

    // ---- section extents ----
    //
    // VirtualSize is 0 in plenty of real images -- packers and older linkers leave it
    // unset and rely on SizeOfRawData -- and a section of size zero contains no VA at
    // all. That made section_index() return -1 everywhere and quietly switched off
    // `characteristic: cross section flow` for the whole module, with no diagnostic.
    // Fall back to the distance to the next section, then to the end of the image.
    sections_.reserve(pe.sections.size());
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        std::uint64_t end = pe.sections[i].va + pe.sections[i].vsize;
        if (pe.sections[i].vsize == 0) {
            end = (i + 1 < pe.sections.size()) ? pe.sections[i + 1].va : pe.base + pe.size;
            if (end < pe.sections[i].va) end = pe.sections[i].va;
        }
        sections_.emplace_back(pe.sections[i].va, end);
    }

    // ---- file: sections, exports, imports ----
    // Ports capa/features/extractors/viv/file.py.
    for (const PeSection& s : pe.sections)
        file_.emplace_back(Feature::section(s.name), va_addr(s.va));

    for (const PeExport& e : pe.exports) {
        if (e.forwarded.empty()) {
            file_.emplace_back(Feature::export_(e.name), va_addr(e.va));
        } else {
            // capa reports the forwarder under its *target's* reformatted name, at
            // the forwarding module's export address.
            file_.emplace_back(Feature::export_(reformat_forwarded_export_name(e.forwarded)),
                               va_addr(base_));
            file_.emplace_back(Feature::characteristic("forwarded export"),
                               va_addr(base_));
        }
    }

    for (const PeImport& i : pe.imports) {
        // `import:` features carry the DLL, unlike `api:`. For an API-set import the
        // DLL recorded in the descriptor ("api-ms-win-core-...") matches no rule, so
        // the module that actually hosts the function is emitted as well.
        const Address at = va_addr(i.slot_va);
        for (const std::string& n : generate_symbols(i.dll, i.symbol, /*include_dll=*/true))
            file_.emplace_back(Feature::import_(n), at);
        if (i.dll.rfind("api-ms-", 0) == 0 || i.dll.rfind("ext-ms-", 0) == 0) {
            if (auto p = mem_.read_pointer(i.slot_va, pe.pe32plus ? 8 : 4)) {
                if (const SymRef* s = syms_.export_at(*p)) {
                    for (const std::string& n :
                         generate_symbols(syms_.dll(*s), i.symbol, true))
                        file_.emplace_back(Feature::import_(n), at);
                }
            }
        }
    }
}

int RegionContext::section_index(std::uint64_t va) const {
    for (std::size_t i = 0; i < sections_.size(); ++i)
        if (va >= sections_[i].first && va < sections_[i].second) return static_cast<int>(i);
    return -1;
}

bool RegionContext::from_slot(const stat::Workspace& ws, std::uint64_t slot,
                              ResolvedApi& out, int hops) const {
    if (hops <= 0) return false;
    // 1. The import directory named this slot. Its name is the documented API a rule
    //    is written against -- kernel32.HeapAlloc, not ntdll.RtlAllocateHeap, which
    //    is what the resolved pointer would say.
    if (const SymRef* s = syms_.iat_slot(slot)) {
        out.dll = syms_.dll(*s);
        out.symbol = syms_.symbol(*s);
        return true;
    }
    // 2. Otherwise take the slot's value. This is the case that matters in a dump:
    //    a bound import, a delay-load slot already fixed up, or a table shellcode
    //    built for itself with GetProcAddress.
    if (auto p = ws.read_pointer(slot)) {
        if (const SymRef* s = syms_.export_at(*p)) {
            out.dll = syms_.dll(*s);
            out.symbol = syms_.symbol(*s);
            return true;
        }
        if (from_target(ws, *p, out, hops - 1)) return true;
    }
    return false;
}

bool RegionContext::from_target(const stat::Workspace& ws, std::uint64_t target,
                                ResolvedApi& out, int hops) const {
    for (; hops > 0; --hops) {
        if (const SymRef* s = syms_.export_at(target)) {
            out.dll = syms_.dll(*s);
            out.symbol = syms_.symbol(*s);
            return true;
        }
        // Not an export. If it is a thunk, follow it.
        std::vector<std::uint8_t> buf = mem_.read(target, 16);
        if (buf.empty()) return false;
        std::uint64_t at = target;
        if (is_endbr(buf.data(), buf.size())) {
            at += 4;
            buf = mem_.read(at, 16);
            if (buf.empty()) return false;
        }
        DecodedInsn d = stat::decode_one(buf.data(), buf.size(), at, ws.arch());
        if (!d.ok || !d.is_uncond_jmp || d.opers.empty()) return false;
        const Operand& o = d.opers[0];
        if (o.kind == OperKind::ImmMem || o.kind == OperKind::RipRel)
            return from_slot(ws, o.addr, out, hops - 1);
        if (o.kind == OperKind::PcRel) {
            target = static_cast<std::uint64_t>(o.value);
            continue;
        }
        return false;
    }
    return false;
}

bool RegionContext::track_register(const stat::BasicBlock& bb, const DecodedInsn& insn, int reg,
                                   std::uint64_t& value, bool& is_slot) const {
    const stat::Arch arch = insn.arch;
    const int want = stat::largest_enclosing_reg(reg, arch);
    const bool volatile_reg = stat::reg_is_volatile(reg, arch);

    // find this instruction, then walk backwards
    std::size_t idx = bb.insns.size();
    for (std::size_t i = 0; i < bb.insns.size(); ++i)
        if (bb.insns[i].va == insn.va) {
            idx = i;
            break;
        }
    if (idx == 0 || idx == bb.insns.size()) return false;

    int scanned = 0;
    for (std::size_t i = idx; i-- > 0 && scanned < MAX_BACK_SCAN; ++scanned) {
        const DecodedInsn& p = bb.insns[i];
        // A call in between can have clobbered a caller-saved register, so anything
        // found before it would be stale.
        if (p.is_call && volatile_reg) return false;
        if (p.opers.empty()) continue;
        const Operand& dst = p.opers[0];
        if (dst.kind != OperKind::Reg) continue;
        if (stat::largest_enclosing_reg(dst.reg, arch) != want) continue;
        // A single-operand write to the register we are tracking -- `pop rax`,
        // `inc rax`, `xchg` -- is still a write. Skipping past it and believing an
        // earlier `mov` attributes a value the register no longer holds, which shows
        // up as a confidently wrong api: feature.
        if (p.opers.size() < 2) return false;

        // The most recent write to the register we care about. Either it is a load
        // we understand, or the trail is cold.
        const Operand& src = p.opers[1];
        const bool is_mov = p.mnem.rfind("mov", 0) == 0;
        const bool is_lea = p.mnem == "lea";
        if (is_mov && (src.kind == OperKind::RipRel || src.kind == OperKind::ImmMem)) {
            value = src.addr;  // mov rax, [rip+X] -> rax holds *[X]: a slot
            is_slot = true;
            return true;
        }
        if (is_mov && src.kind == OperKind::Imm) {
            value = static_cast<std::uint64_t>(src.value);  // mov rax, imm: an address
            is_slot = false;
            return true;
        }
        if (is_lea && (src.kind == OperKind::RipRel || src.kind == OperKind::ImmMem)) {
            value = src.addr;  // lea rax, [rip+X] -> rax holds X itself
            is_slot = false;
            return true;
        }
        return false;  // written by something we cannot follow
    }
    return false;
}

void RegionContext::resolve_api(const stat::Workspace& ws, const stat::BasicBlock& bb,
                                const DecodedInsn& insn, std::vector<ResolvedApi>& out) const {
    if (insn.opers.empty()) return;
    if (!insn.is_call && !insn.is_uncond_jmp) return;
    const Operand& o = insn.opers[0];
    ResolvedApi api;
    // The budget for the whole slot/thunk chain that starts here, spent by whichever
    // of from_slot/from_target consumes a hop. capa's viv extractor follows the same
    // number of thunks.
    const int hops = helpers::THUNK_CHAIN_DEPTH_DELTA;

    switch (o.kind) {
        // call [0x40a018] (x86) / call [rip+0x1234] (x64): the operand names a slot.
        case OperKind::ImmMem:
        case OperKind::RipRel:
            if (from_slot(ws, o.addr, api, hops)) out.push_back(std::move(api));
            return;

        // call func: a direct target, possibly through a chain of thunks.
        case OperKind::PcRel:
            if (from_target(ws, static_cast<std::uint64_t>(o.value), api, hops))
                out.push_back(std::move(api));
            return;

        // call rax, after the address was loaded earlier in the block. Extremely
        // common in x64 and near-universal in shellcode.
        case OperKind::Reg: {
            std::uint64_t v = 0;
            bool is_slot = false;
            if (!track_register(bb, insn, o.reg, v, is_slot)) return;
            if (is_slot ? from_slot(ws, v, api, hops) : from_target(ws, v, api, hops))
                out.push_back(std::move(api));
            return;
        }

        // call [rbx+0x28]: a resolved-API struct, the dominant shellcode shape. Only
        // resolvable when the base register's value is itself recoverable.
        case OperKind::RegMem:
        case OperKind::Sib: {
            if (o.base_is_stack) return;  // a local, not an API table
            std::uint64_t base = 0;
            bool is_slot = false;
            if (!track_register(bb, insn, o.reg, base, is_slot)) return;
            if (is_slot) {
                auto p = ws.read_pointer(base);
                if (!p) return;
                base = *p;
            }
            if (from_slot(ws, base + static_cast<std::uint64_t>(o.disp), api, hops))
                out.push_back(std::move(api));
            return;
        }

        default:
            return;
    }
}

}  // namespace capa::mdmp
