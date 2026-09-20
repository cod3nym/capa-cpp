// Zydis-backed x86 / x86-64 disassembly for capa-cpp's static path.
//
// Wraps Zydis and reclassifies each decoded operand into the vivisect operand
// categories that capa's viv extractor branches on (see capa/features/extractors/viv/
// insn.py). Getting this mapping right is what makes the static features line up:
//
//   viv i386ImmOper      -> OperKind::Imm      (immediate, e.g. `push 0x1234`)
//   viv i386ImmMemOper   -> OperKind::ImmMem   (absolute `[disp]`, no regs; incl. fs:[0x30])
//   viv i386PcRelOper    -> OperKind::PcRel    (relative branch target, e.g. `call func`)
//   viv i386RegOper      -> OperKind::Reg      (register, e.g. `call rax`)
//   viv i386RegMemOper   -> OperKind::RegMem   (`[base + disp]`, no index)
//   viv i386SibOper      -> OperKind::Sib      (`[base + index*scale + disp]`)
//   viv Amd64RipRelOper  -> OperKind::RipRel   (`[rip + disp]`)
//
// Both 32-bit (legacy protected mode) and 64-bit decoding are supported; the mode comes
// from the scan-code manifest's `arch` field and has to be threaded all the way down --
// the same bytes decode to different instructions under the two modes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace capa::stat {

// Decode mode for a reconstructed region. X86 is 32-bit protected mode, X64 is long mode.
enum class Arch { X86, X64 };

// Parse a manifest `arch` string. "x86" / "i386" / "32" (any case) mean 32-bit;
// everything else -- including the unset/default "x64" -- means 64-bit. The accepted
// spellings match the dynamic path's, deliberately.
Arch arch_from_string(std::string_view s);

// Pointer width, in bytes.
constexpr int pointer_size(Arch arch) { return arch == Arch::X86 ? 4 : 8; }

// Truncate an absolute address to the architecture's address width. Zydis sign-extends
// 32-bit displacements to 64 bits, so `[0x90000000]` decodes with a disp of
// 0xffffffff90000000; under 32-bit addressing the high half is not part of the address.
constexpr std::uint64_t mask_address(std::uint64_t va, Arch arch) {
    return arch == Arch::X86 ? (va & 0xffffffffull) : va;
}

enum class OperKind { Imm, ImmMem, PcRel, Reg, RegMem, Sib, RipRel, Other };

struct Operand {
    OperKind kind = OperKind::Other;
    int size = 0;  // operand size in bytes (viv `tsize`)

    // Imm / PcRel: `value` is the immediate / absolute branch target. An immediate is
    // stored the way viv stores i386ImmOper.imm: unsigned, narrowed to the width of the
    // operand it pairs with -- so 32-bit `cmp eax, -1` is 0xFFFFFFFF here, not -1, while
    // 64-bit `cmp rax, -1` is 0xFFFFFFFFFFFFFFFF (== -1 in this signed field).
    // ImmMem / RipRel: `addr` is the referenced absolute address (viv getOperAddr).
    // RegMem / Sib: `disp` is the signed displacement (viv `disp`);
    //               `abs` is the absolute constant a string/bytes deref would use (viv `imm`).
    std::int64_t value = 0;
    std::uint64_t addr = 0;
    std::int64_t disp = 0;
    std::int64_t abs = 0;

    int reg = 0;               // Zydis register id (Reg kind, or base reg of a mem operand)
    bool base_is_stack = false;  // base/reg is (r/e)sp or (r/e)bp
    bool reg_is_sp = false;      // base/reg largest-enclosing is (r)sp specifically
    bool is_immediate = false;   // viv isImmed(): true for Imm and PcRel

    // raw encoding, for operand identity comparison (nzxor `opers[0] == opers[1]`)
    int raw_type = 0;   // ZydisOperandType
    int mem_base = 0;
    int mem_index = 0;
};

struct DecodedInsn {
    bool ok = false;
    Arch arch = Arch::X64;  // mode this was decoded in; fixes the address width
    std::uint64_t va = 0;
    std::uint32_t length = 0;
    std::string mnem;  // e.g. "mov", "call", "xor", "xorps", "pxor"
    std::vector<Operand> opers;  // explicit operands, dest-first (viv `opers`)

    std::string seg_prefix;  // "fs" / "gs" / "" (viv getPrefixName, segment part)

    // control-flow classification
    bool is_call = false;
    bool is_cond_branch = false;   // Jcc
    bool is_uncond_jmp = false;    // jmp
    bool is_ret = false;
    bool is_indirect_branch = false;  // jmp/call through reg or memory (target unknown)
    std::optional<std::uint64_t> branch_target;  // concrete target of a direct jmp/jcc/call

    bool is_return() const { return is_ret; }
};

// Branch flags, mirroring the envi.BR_* bits capa's loop / tight-loop code inspects.
enum BranchFlag { BR_FALL = 1, BR_COND = 2, BR_PROC = 4, BR_DEREF = 8, BR_TABLE = 16 };

struct Branch {
    std::optional<std::uint64_t> target;  // nullopt for unresolved indirect branches
    int flags = 0;
};

// getBranches(): reconstruct the (target, flags) list capa iterates. Fallthrough is
// included (BR_FALL) except after an unconditional jmp / ret.
std::vector<Branch> insn_branches(const DecodedInsn& insn);

// Decode one instruction from `buf` (whose byte 0 is at address `va`) in `arch` mode.
// Returns DecodedInsn{ok=false} on failure. Thread-safe (the shared decoders are
// read-only).
DecodedInsn decode_one(const std::uint8_t* buf, std::size_t len, std::uint64_t va, Arch arch);

// True if two operands are structurally identical (viv operand `==`).
bool operand_equal(const Operand& a, const Operand& b);

// Zydis register id of the largest register enclosing `reg` (eax -> rax in long
// mode). Comparing registers by their enclosing form is what lets a `mov eax, ...`
// be recognised as the write that a later `call rax` consumes.
int largest_enclosing_reg(int reg, Arch arch);

// Is `reg` caller-saved, i.e. can a call in between have clobbered it? Used to
// abandon the backward search for what loaded an indirect call's target.
bool reg_is_volatile(int reg, Arch arch);

}  // namespace capa::stat
