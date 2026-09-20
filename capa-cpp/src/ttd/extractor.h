// TTD dynamic feature extractor for capa-cpp.
//
// Ports capa/features/extractors/ttd/{extractor,file,process,thread,call,global_,
// helpers}.py. Consumes a parsed ttd::Report and yields capa Features per scope.
//
// This is the only dynamic backend, so the dynamic capabilities driver uses it
// concretely (no abstract base) to keep the per-call hot path allocation-light.
// The StaticFeatureExtractor interface in feature_extractor.h covers static backends.
#pragma once

#include <string>
#include <utility>
#include <vector>

#include "address.h"
#include "feature.h"
#include "feature_extractor.h"
#include "ttd/models.h"

namespace capa::ttd {

using capa::FeaturePair;

struct ProcessHandle {
    Address address;
    const Process* inner = nullptr;
};

struct ThreadHandle {
    Address address;
};

struct CallHandle {
    Address address;
    const Call* inner = nullptr;
};

class TtdExtractor {
public:
    static constexpr int CURRENT_VERSION = 1;

    explicit TtdExtractor(Report report);

    // sample hashes
    const std::string& md5() const { return report_.sample.md5; }
    const std::string& sha1() const { return report_.sample.sha1; }
    const std::string& sha256() const { return report_.sample.sha256; }
    const Report& report() const { return report_; }

    const std::vector<FeaturePair>& extract_global_features() const { return global_features_; }
    std::vector<FeaturePair> extract_file_features() const;

    std::vector<ProcessHandle> get_processes() const;
    std::vector<FeaturePair> extract_process_features(const ProcessHandle& ph) const;
    std::string get_process_name(const ProcessHandle& ph) const;

    std::vector<ThreadHandle> get_threads(const ProcessHandle& ph) const;
    std::vector<FeaturePair> extract_thread_features(const ProcessHandle& ph,
                                                     const ThreadHandle& th) const;

    std::vector<CallHandle> get_calls(const ProcessHandle& ph, const ThreadHandle& th) const;

    // The same calls, one at a time. get_calls materializes a handle per call in the
    // thread -- forty bytes each, and the whole vector is live before the first call is
    // looked at -- which on a trace with millions of calls in one thread is hundreds of
    // megabytes held to iterate a list the caller only ever walks forwards.
    std::size_t call_count(const ProcessHandle& ph, const ThreadHandle& th) const;
    // `idx` must be below call_count for the same handles; out of range yields an empty
    // handle, which extract_call_features reads as a call with no features.
    CallHandle call_at(const ProcessHandle& ph, const ThreadHandle& th, std::size_t idx) const;
    std::vector<FeaturePair> extract_call_features(const ProcessHandle& ph,
                                                   const ThreadHandle& th,
                                                   const CallHandle& ch) const;
    std::string get_call_name(const ProcessHandle& ph, const ThreadHandle& th,
                              const CallHandle& ch) const;

private:
    struct ThreadEntry {
        Address address;
        std::vector<const Call*> calls;  // sorted by seq
    };
    struct ProcEntry {
        Address address;
        const Process* proc = nullptr;
        std::vector<ThreadEntry> threads;  // insertion order (declared then discovered)
    };

    const ProcEntry* find_proc(const Address& addr) const;
    const ThreadEntry* find_thread(const ProcEntry& pe, const Address& addr) const;

    Report report_;
    std::vector<FeaturePair> global_features_;
    std::vector<ProcEntry> procs_;
};

}  // namespace capa::ttd
