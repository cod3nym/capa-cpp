// Backend-neutral feature-extractor interface for capa-cpp.
//
// Ports capa/features/extractors/base_extractor.py: the handle types and the
// StaticFeatureExtractor abstract base that every static backend implements.
//
// A handle is an address plus an opaque `inner` pointer the backend owns; it stands
// in for Python's `dataclass(address, inner: Any)`. The pointee must outlive every
// handle the backend hands out — in practice each backend keeps its own stable
// storage (a Workspace, a deque of per-function records) and points into it.
//
// The dynamic/TTD path deliberately does NOT go through this interface: it has a
// single backend and binds to it concretely to keep the per-call hot path
// allocation-light (see ttd/extractor.h).
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"

namespace capa {

// One extracted feature and where it was found.
using FeaturePair = std::pair<Feature, Address>;

struct SampleHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

struct FunctionHandle {
    Address address;
    const void* inner = nullptr;
};

struct BBHandle {
    Address address;
    const void* inner = nullptr;
};

struct InsnHandle {
    Address address;
    const void* inner = nullptr;
};

class StaticFeatureExtractor {
public:
    virtual ~StaticFeatureExtractor() = default;

    virtual Address get_base_address() const = 0;
    virtual const SampleHashes& get_sample_hashes() const = 0;

    // Global features are yielded at every scope, including once per instruction, so
    // they are precomputed and handed out by reference rather than rebuilt each time.
    virtual const std::vector<FeaturePair>& extract_global_features() const = 0;
    virtual std::vector<FeaturePair> extract_file_features() const = 0;

    virtual std::vector<FunctionHandle> get_functions() const = 0;
    virtual std::vector<FeaturePair> extract_function_features(const FunctionHandle& fh) const = 0;

    virtual std::vector<BBHandle> get_basic_blocks(const FunctionHandle& fh) const = 0;
    virtual std::vector<FeaturePair> extract_basic_block_features(const FunctionHandle& fh,
                                                                  const BBHandle& bbh) const = 0;

    virtual std::vector<InsnHandle> get_instructions(const FunctionHandle& fh,
                                                     const BBHandle& bbh) const = 0;
    virtual std::vector<FeaturePair> extract_insn_features(const FunctionHandle& fh,
                                                           const BBHandle& bbh,
                                                           const InsnHandle& ih) const = 0;

    // Optional: backends that can recognize library code report it here so the driver
    // can skip those functions (capa StaticFeatureExtractor.is_library_function).
    virtual bool is_library_function(const Address&) const { return false; }
    virtual std::string get_function_name(const Address&) const { return {}; }
};

}  // namespace capa
