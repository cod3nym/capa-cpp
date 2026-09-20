// Ports capa/features/extractors/ida/basicblock.py: tight loop, stack string, and the
// structural `basic block` feature.
#include "ida/extractor.h"

#include "extract_helpers.h"

namespace capa::ida {

namespace {

void add(std::vector<FeaturePair>& out, Feature f, const Address& a) {
    out.emplace_back(std::move(f), a);
}
Address va(ea_t ea) { return Address::absolute(static_cast<std::uint64_t>(ea)); }

// capa's get_printable_len(): how many printable characters an immediate contributes.
// Python raises on a data type it does not pack (float, byte arrays, ...); returning 0
// is the same answer for stack-string purposes without taking the plugin down.
int get_printable_len(const op_t& op) {
    switch (op.dtype) {
        case dt_byte:
        case dt_word:
        case dt_dword:
        case dt_qword: break;
        default: return 0;
    }
    return helpers::printable_len(mask_op_val(op),
                                  static_cast<int>(get_dtype_size(op.dtype)));
}

bool is_mov_imm_to_stack(const insn_t& insn) {
    if (insn.ops[1].type != o_imm) return false;
    if (!is_op_stack_var(insn.ea, 0)) return false;
    const char* mnem = insn.get_canon_mnem(PH);
    if (mnem == nullptr) return false;
    return std::string(mnem).rfind("mov", 0) == 0;
}

bool bb_contains_stackstring(const IdaBB& bb) {
    int count = 0;
    for (const insn_t& insn : bb.insns) {
        if (is_mov_imm_to_stack(insn)) count += get_printable_len(insn.ops[1]);
        if (count > helpers::MIN_STACKSTRING_LEN) return true;
    }
    return false;
}

}  // namespace

void extract_basic_block_features(const IdaFunc&, const IdaBB& bb,
                                  std::vector<FeaturePair>& out) {
    if (is_basic_block_tight_loop(bb))
        add(out, Feature::characteristic("tight loop"), va(bb.start_ea));
    if (bb_contains_stackstring(bb))
        add(out, Feature::characteristic("stack string"), va(bb.start_ea));
    add(out, Feature::basic_block(), va(bb.start_ea));
}

}  // namespace capa::ida
