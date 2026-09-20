#include "static/disasm.h"

#include <Zydis/Zydis.h>

#include <cctype>
#include <string>

namespace capa::stat {

namespace {

ZydisMachineMode machine_mode(Arch arch) {
    return arch == Arch::X86 ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;
}

// One shared, read-only decoder per mode. ZydisDecoderDecodeFull does not mutate them,
// so concurrent decodes are safe.
const ZydisDecoder& decoder(Arch arch) {
    static const ZydisDecoder d64 = [] {
        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        return dec;
    }();
    static const ZydisDecoder d32 = [] {
        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        return dec;
    }();
    return arch == Arch::X86 ? d32 : d64;
}

ZydisRegister enclosing(ZydisRegister reg, Arch arch) {
    if (reg == ZYDIS_REGISTER_NONE) return ZYDIS_REGISTER_NONE;
    return ZydisRegisterGetLargestEnclosing(machine_mode(arch), reg);
}
// The largest enclosing register is (r)sp/(r)bp in long mode but (e)sp/(e)bp in 32-bit
// mode, so both spellings have to be accepted.
bool is_stack_reg(ZydisRegister reg, Arch arch) {
    ZydisRegister big = enclosing(reg, arch);
    return big == ZYDIS_REGISTER_RSP || big == ZYDIS_REGISTER_RBP ||
           big == ZYDIS_REGISTER_ESP || big == ZYDIS_REGISTER_EBP;
}
bool is_sp_reg(ZydisRegister reg, Arch arch) {
    ZydisRegister big = enclosing(reg, arch);
    return big == ZYDIS_REGISTER_RSP || big == ZYDIS_REGISTER_ESP;
}

// Truncate `v` to `bits`; a width of 0 or >= 64 leaves it alone.
std::uint64_t mask_to_bits(std::uint64_t v, unsigned bits) {
    if (bits == 0 || bits >= 64) return v;
    return v & ((1ull << bits) - 1);
}

// The width viv would store an immediate at.
//
// vivisect keeps i386ImmOper.imm *unsigned*, parsed at the immediate's own encoded size,
// and then (envi/archs/i386/disasm.py, the OP_SIGNED branch) sign-extends it to the width
// of the operand appended before it when the two differ:
//
//     if operflags & opcode86.OP_SIGNED:
//         if len(operands) and tsize != operands[-1].tsize:
//             oper.imm = e_bits.sign_extend(oper.imm, oper.tsize, operands[-1].tsize)
//
// e_bits.sign_extend returns an unsigned value, so `cmp eax, -1` (83 F8 FF) ends up as
// 0xFFFFFFFF, not -1. Zydis instead hands us the value sign-extended to a full 64 bits
// and reports only the *encoded* width in `operand.size` (8 bits for the `83 /x ib`
// forms), so neither of its numbers is viv's -- we have to rebuild the width. Falling
// back to the immediate's own width when there is no preceding operand reproduces viv's
// unextended `push -1` (6A FF) == 0xFF.
unsigned viv_imm_bits(unsigned prev_operand_bits, unsigned imm_bits) {
    return prev_operand_bits ? prev_operand_bits : imm_bits;
}

}  // namespace

// The accepted 32-bit spellings must stay identical to the dynamic path's
// (capa::ttd::compute_global_features in ttd/extractor.cpp): the two backends read the
// same trace, so a spelling one accepts and the other does not yields contradictory
// `arch:` features for it. Note "x32" is deliberately NOT here -- that names the x86-64
// ILP32 ABI, whose bytes are 64-bit encodings.
Arch arch_from_string(std::string_view s) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) t.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (t == "x86" || t == "i386" || t == "32") return Arch::X86;
    return Arch::X64;
}

DecodedInsn decode_one(const std::uint8_t* buf, std::size_t len, std::uint64_t va, Arch arch) {
    DecodedInsn out;
    out.arch = arch;
    out.va = va;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder(arch), buf, len, &insn, operands)))
        return out;

    out.ok = true;
    out.length = insn.length;
    out.mnem = ZydisMnemonicGetString(insn.mnemonic);

    if (insn.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS)
        out.seg_prefix = "fs";
    else if (insn.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS)
        out.seg_prefix = "gs";

    // control-flow classification
    switch (insn.meta.category) {
        case ZYDIS_CATEGORY_CALL: out.is_call = true; break;
        case ZYDIS_CATEGORY_RET: out.is_ret = true; break;
        case ZYDIS_CATEGORY_COND_BR: out.is_cond_branch = true; break;
        case ZYDIS_CATEGORY_UNCOND_BR: out.is_uncond_jmp = true; break;
        default: break;
    }

    // width of the last explicit operand seen, for viv_imm_bits() below (viv's
    // `operands[-1].tsize`).
    unsigned prev_operand_bits = 0;

    for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
        const ZydisDecodedOperand& op = operands[i];
        if (op.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT) continue;

        Operand o;
        o.raw_type = static_cast<int>(op.type);
        o.size = op.size / 8;

        switch (op.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                o.kind = OperKind::Reg;
                o.reg = static_cast<int>(op.reg.value);
                o.base_is_stack = is_stack_reg(op.reg.value, arch);
                o.reg_is_sp = is_sp_reg(op.reg.value, arch);
                break;

            case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
                o.is_immediate = true;
                if (op.imm.is_relative) {
                    o.kind = OperKind::PcRel;
                    ZyanU64 abs = 0;
                    ZydisCalcAbsoluteAddress(&insn, &op, va, &abs);
                    // Zydis only truncates a 32-bit relative target when the operand
                    // width is 16, so a branch that wraps around 4 GiB needs masking.
                    abs = mask_address(abs, arch);
                    o.value = static_cast<std::int64_t>(abs);
                    o.addr = abs;
                } else {
                    o.kind = OperKind::Imm;
                    o.value = static_cast<std::int64_t>(mask_to_bits(
                        op.imm.value.u, viv_imm_bits(prev_operand_bits, op.size)));
                }
                break;
            }

            case ZYDIS_OPERAND_TYPE_MEMORY: {
                o.mem_base = static_cast<int>(op.mem.base);
                o.mem_index = static_cast<int>(op.mem.index);
                o.disp = op.mem.disp.value;  // signed: this is viv's struct `offset`
                // `abs` is used as an address (string/bytes deref), so it takes the
                // architecture's address width, like viv's unsigned i386 `imm`.
                o.abs = static_cast<std::int64_t>(
                    mask_address(static_cast<std::uint64_t>(op.mem.disp.value), arch));
                if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP) {
                    o.kind = OperKind::RipRel;
                    ZyanU64 abs = 0;
                    ZydisCalcAbsoluteAddress(&insn, &op, va, &abs);
                    o.addr = mask_address(abs, arch);
                } else if (op.mem.index != ZYDIS_REGISTER_NONE || is_sp_reg(op.mem.base, arch)) {
                    // has an index, or a base of (r/e)sp -- the latter forces a SIB byte, so
                    // vivisect models `[rsp+disp]` as i386SibOper (whose offset handler does
                    // NOT skip the stack pointer, unlike the RegMemOper handler).
                    o.kind = OperKind::Sib;
                    o.reg = static_cast<int>(op.mem.base);
                    o.base_is_stack = is_stack_reg(op.mem.base, arch);
                    o.reg_is_sp = is_sp_reg(op.mem.base, arch);
                } else if (op.mem.base != ZYDIS_REGISTER_NONE) {
                    o.kind = OperKind::RegMem;
                    o.reg = static_cast<int>(op.mem.base);
                    o.base_is_stack = is_stack_reg(op.mem.base, arch);
                    o.reg_is_sp = is_sp_reg(op.mem.base, arch);
                    o.addr = mask_address(static_cast<std::uint64_t>(op.mem.disp.value), arch);
                } else {
                    // no base, no index: absolute direct `[disp]` (incl. fs:[0x30])
                    o.kind = OperKind::ImmMem;
                    o.addr = mask_address(static_cast<std::uint64_t>(op.mem.disp.value), arch);
                }
                break;
            }

            default:
                o.kind = OperKind::Other;
                break;
        }
        out.opers.push_back(o);
        prev_operand_bits = op.size;
    }

    // resolve a concrete direct-branch target from the first explicit operand
    if (out.is_call || out.is_cond_branch || out.is_uncond_jmp) {
        if (!out.opers.empty()) {
            const Operand& t = out.opers[0];
            if (t.kind == OperKind::PcRel) {
                out.branch_target = t.addr;
            } else if (t.kind == OperKind::Imm) {
                out.branch_target = mask_address(static_cast<std::uint64_t>(t.value), arch);
            } else {
                out.is_indirect_branch = true;  // reg / memory target
            }
        } else {
            out.is_indirect_branch = true;
        }
    }

    return out;
}

std::vector<Branch> insn_branches(const DecodedInsn& insn) {
    std::vector<Branch> out;
    std::uint64_t fall = mask_address(insn.va + insn.length, insn.arch);

    if (insn.is_cond_branch) {
        out.push_back({insn.branch_target, BR_COND});
        out.push_back({fall, BR_FALL});
    } else if (insn.is_uncond_jmp) {
        if (insn.branch_target)
            out.push_back({insn.branch_target, 0});  // mnem=="jmp" makes this a loop edge
        else
            out.push_back({std::nullopt, BR_DEREF});
    } else if (insn.is_call) {
        if (insn.branch_target)
            out.push_back({insn.branch_target, BR_PROC});
        else
            out.push_back({std::nullopt, BR_PROC | BR_DEREF});
        out.push_back({fall, BR_FALL});
    } else if (insn.is_ret) {
        // no successors
    } else {
        out.push_back({fall, BR_FALL});
    }
    return out;
}

int largest_enclosing_reg(int reg, Arch arch) {
    return static_cast<int>(enclosing(static_cast<ZydisRegister>(reg), arch));
}

bool reg_is_volatile(int reg, Arch arch) {
    const ZydisRegister big = enclosing(static_cast<ZydisRegister>(reg), arch);
    if (arch == Arch::X86) {
        // cdecl/stdcall: eax, ecx, edx are caller-saved.
        return big == ZYDIS_REGISTER_EAX || big == ZYDIS_REGISTER_ECX ||
               big == ZYDIS_REGISTER_EDX;
    }
    // Win64: rax, rcx, rdx, r8-r11 are caller-saved.
    switch (big) {
        case ZYDIS_REGISTER_RAX:
        case ZYDIS_REGISTER_RCX:
        case ZYDIS_REGISTER_RDX:
        case ZYDIS_REGISTER_R8:
        case ZYDIS_REGISTER_R9:
        case ZYDIS_REGISTER_R10:
        case ZYDIS_REGISTER_R11:
            return true;
        default:
            return false;
    }
}

bool operand_equal(const Operand& a, const Operand& b) {
    if (a.kind != b.kind) return false;
    switch (a.kind) {
        case OperKind::Reg:
            return a.reg == b.reg;
        case OperKind::Imm:
        case OperKind::PcRel:
            return a.value == b.value;
        case OperKind::ImmMem:
        case OperKind::RipRel:
            return a.addr == b.addr;
        case OperKind::RegMem:
        case OperKind::Sib:
            return a.mem_base == b.mem_base && a.mem_index == b.mem_index && a.disp == b.disp;
        default:
            return false;
    }
}

}  // namespace capa::stat
