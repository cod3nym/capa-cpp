// Ports capa/features/extractors/ida/function.py: calls-to, loop, recursive call,
// function name, and the fork's alternative names.
#include "ida/extractor.h"

#include "extract_helpers.h"

namespace capa::ida {

namespace {

void add(std::vector<FeaturePair>& out, Feature f, const Address& a) {
    out.emplace_back(std::move(f), a);
}
Address va(ea_t ea) { return Address::absolute(static_cast<std::uint64_t>(ea)); }

void extract_function_calls_to(const IdaFunc& f, std::vector<FeaturePair>& out) {
    for (ea_t ea : code_refs_to(f.start_ea, /*flow=*/true))
        add(out, Feature::characteristic("calls to"), va(ea));
}

void extract_function_loop(IdaFunc& f, std::vector<FeaturePair>& out) {
    build_function_loop_edges(f);
    if (!f.loop_edges.empty() && helpers::has_loop(f.loop_edges))
        add(out, Feature::characteristic("loop"), va(f.start_ea));
}

void extract_recursive_call(const IdaFunc& f, std::vector<FeaturePair>& out) {
    if (is_function_recursive(f))
        add(out, Feature::characteristic("recursive call"), va(f.start_ea));
}

void extract_function_name(const IdaFunc& f, std::vector<FeaturePair>& out) {
    std::string name = get_ea_name(f.start_ea);
    if (name.rfind("sub_", 0) == 0) return;  // IDA's default name carries no information
    if (name.empty()) return;

    add(out, Feature::function_name(name), va(f.start_ea));
    if (name.front() == '_') add(out, Feature::function_name(name.substr(1)), va(f.start_ea));
}

void extract_function_alternative_names(const IdaFunc& f, std::vector<FeaturePair>& out) {
    for (const std::string& aname : get_function_alternative_names(f.start_ea))
        add(out, Feature::function_name(aname), va(f.start_ea));
}

}  // namespace

void extract_function_features(IdaFunc& f, std::vector<FeaturePair>& out) {
    extract_function_calls_to(f, out);
    extract_function_loop(f, out);
    extract_recursive_call(f, out);
    extract_function_name(f, out);
    extract_function_alternative_names(f, out);
}

}  // namespace capa::ida
