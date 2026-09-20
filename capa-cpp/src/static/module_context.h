// What a container-aware backend can tell StaticExtractor about the region it is
// scanning.
//
// The TTD `--scan-code` path analyses a reconstructed blob: no PE container, no
// import table, no symbols, so capa's api/import/export/section/format handlers have
// nothing to work with and StaticExtractor omits them. A minidump region does have
// all of that, and 500 of capa's 1055 rules use `api:` features — so rather than
// fork the 365 lines of insn/bb/function handlers, StaticExtractor takes an optional
// context that supplies exactly the pieces a real image knows.
//
// This is an interface rather than a struct of data on purpose: one vtable, no
// per-call allocation, and `src/static/` needs only this declaration, so no minidump
// or PE types leak into the shared core. A null context is bit-for-bit today's
// behavior, which is what keeps the TTD and IDA paths provably unchanged.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "feature_extractor.h"

namespace capa::stat {

class Workspace;
struct BasicBlock;
struct DecodedInsn;

// A call target that resolved to a named API.
struct ResolvedApi {
    std::string dll;
    std::string symbol;
};

class ModuleContext {
public:
    virtual ~ModuleContext() = default;

    // Instruction scope: resolve a call/jmp to the API it reaches. `out` is a
    // caller-owned buffer, reused across instructions; append to it. Called only for
    // `call` and `jmp`.
    virtual void resolve_api(const Workspace& /*ws*/, const BasicBlock& /*bb*/,
                             const DecodedInsn& /*insn*/, std::vector<ResolvedApi>& /*out*/) const {}

    // File scope: section / export / import / function-name features, precomputed
    // because they do not vary per call. Emitted verbatim after the built-in
    // embedded-PE carve and string scan.
    virtual const std::vector<FeaturePair>& file_features() const {
        static const std::vector<FeaturePair> none;
        return none;
    }

    // Global scope: if non-empty this REPLACES the built-in os+arch pair, which is
    // how a module region adds `format: pe` (and how a shellcode region says sc32 /
    // sc64 instead).
    virtual const std::vector<FeaturePair>& global_features() const {
        static const std::vector<FeaturePair> none;
        return none;
    }

    // Index of the section containing `va`, or -1. Only used to decide
    // characteristic("cross section flow"); the values themselves are opaque.
    virtual int section_index(std::uint64_t /*va*/) const { return -1; }

    // capa's StaticFeatureExtractor hooks for recognised library code.
    virtual bool is_library_function(std::uint64_t /*va*/) const { return false; }
    virtual std::string function_name(std::uint64_t /*va*/) const { return {}; }
};

}  // namespace capa::stat
