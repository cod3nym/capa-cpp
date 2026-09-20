// Static feature extractor for capa-cpp.
//
// Ports capa/features/extractors/viv/{insn,function,basicblock,file,global_}.py over
// the seeded Workspace + Zydis. Only the features that can fire on a reconstructed,
// import-less shellcode image are emitted:
//   - insn:  mnemonic, number/offset/operand, bytes, string, nzxor, peb access,
//            fs/gs access, call $+5, calls from, recursive/indirect call
//   - bb:    basic block, tight loop, stack string
//   - func:  calls to, loop
//   - file:  embedded pe, strings
//   - global: os(windows), arch(i386|amd64)
//
// API/import/export/section/format/FLIRT-name and cross-section-flow features need
// a PE container and an import table, which a reconstructed blob does not have -- so
// on that path their viv handlers would yield nothing anyway and are omitted. A
// backend that DOES have a container (the minidump path) supplies a ModuleContext,
// and then those features are emitted through the very same handlers.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"
#include "feature_filter.h"
#include "feature_extractor.h"
#include "static/module_context.h"
#include "static/workspace.h"

namespace capa::stat {

using capa::FeaturePair;

class StaticExtractor : public StaticFeatureExtractor {
public:
    // `bytes` is the flat .bin image mapped at `base`; `entries`/`executed` are the
    // manifest seeds for this region; `arch` is the manifest's decode mode.
    // `filter`, when given, drops file-scope features no rule can read as they are
    // carved rather than after. A region can be a whole module image and every printable
    // run in it is a `string:` feature; see feature_filter.h. Must outlive this.
    StaticExtractor(std::uint64_t base, std::vector<std::uint8_t> bytes,
                    std::vector<std::uint64_t> entries, std::vector<std::uint64_t> executed,
                    Arch arch, const FeatureFilter* filter = nullptr);

    // Over shared process memory, with an optional container context. `mem` and
    // `ctx` must outlive this extractor; a null `ctx` behaves exactly as above.
    StaticExtractor(const MemoryImage& mem, std::uint64_t region_base,
                    std::uint64_t region_size, std::vector<std::uint64_t> entries,
                    std::vector<std::uint64_t> executed, Arch arch,
                    const ModuleContext* ctx, const FeatureFilter* filter = nullptr);

    std::uint64_t base() const { return ws_.base(); }
    Arch arch() const { return ws_.arch(); }
    const std::vector<Function>& functions() const { return ws_.functions(); }

    // ---- typed interface (used directly by --scan-dump-features) ----
    //
    // Precomputed: globals are yielded at *every* scope, including once per instruction,
    // so they are built once in the ctor and handed out by reference (same as
    // TtdExtractor::extract_global_features on the dynamic side).
    const std::vector<FeaturePair>& extract_global_features() const override {
        return global_features_;
    }
    std::vector<FeaturePair> extract_file_features() const override;
    std::vector<FeaturePair> extract_function_features(const Function& f) const;
    std::vector<FeaturePair> extract_basic_block_features(const Function& f,
                                                          const BasicBlock& bb) const;
    std::vector<FeaturePair> extract_insn_features(const Function& f, const BasicBlock& bb,
                                                   const DecodedInsn& insn) const;

    // ---- StaticFeatureExtractor ----
    //
    // Handles carry pointers straight into the Workspace's Function/BasicBlock/
    // DecodedInsn storage, which lives as long as this extractor does.
    Address get_base_address() const override { return Address::absolute(ws_.base()); }
    const SampleHashes& get_sample_hashes() const override { return hashes_; }
    bool is_library_function(const Address& a) const override {
        return ctx_ && ctx_->is_library_function(a.value);
    }
    std::string get_function_name(const Address& a) const override {
        return ctx_ ? ctx_->function_name(a.value) : std::string();
    }

    std::vector<FunctionHandle> get_functions() const override;
    std::vector<FeaturePair> extract_function_features(const FunctionHandle& fh) const override;
    std::vector<BBHandle> get_basic_blocks(const FunctionHandle& fh) const override;
    std::vector<FeaturePair> extract_basic_block_features(const FunctionHandle& fh,
                                                          const BBHandle& bbh) const override;
    std::vector<InsnHandle> get_instructions(const FunctionHandle& fh,
                                             const BBHandle& bbh) const override;
    std::vector<FeaturePair> extract_insn_features(const FunctionHandle& fh, const BBHandle& bbh,
                                                   const InsnHandle& ih) const override;

private:
    void init_globals(Arch arch);

    Workspace ws_;  // see ws_.region_bytes() for file-scope scanning
    const ModuleContext* ctx_ = nullptr;  // non-owning; null on the TTD path
    const FeatureFilter* filter_ = nullptr;  // non-owning; null means keep everything
    std::vector<FeaturePair> global_features_;
    // a reconstructed region is not a file, so it has no sample hashes.
    SampleHashes hashes_;
};

}  // namespace capa::stat
