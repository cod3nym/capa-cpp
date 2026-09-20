#include "static/manifest.h"

namespace capa::stat {

namespace {
std::uint64_t as_u64(const nlohmann::json& j, std::uint64_t dflt = 0) {
    if (j.is_number_unsigned()) return j.get<std::uint64_t>();
    if (j.is_number_integer()) return static_cast<std::uint64_t>(j.get<std::int64_t>());
    if (j.is_number_float()) return static_cast<std::uint64_t>(j.get<double>());
    return dflt;
}
}  // namespace

Manifest Manifest::from_json(const nlohmann::json& j) {
    Manifest m;
    m.version = j.value("version", 0);
    m.trace = j.value("trace", std::string{});
    m.arch = j.value("arch", std::string{"x64"});

    if (auto it = j.find("modules"); it != j.end() && it->is_array()) {
        for (const auto& mj : *it) {
            ModuleInfo mod;
            mod.name = mj.value("name", std::string{});
            mod.path = mj.value("path", std::string{});
            mod.base = as_u64(mj.value("base", nlohmann::json(0)));
            mod.size = as_u64(mj.value("size", nlohmann::json(0)));
            mod.arch = mj.value("arch", std::string{});
            if (auto e = mj.find("exports"); e != mj.end() && e->is_array()) {
                mod.exports.reserve(e->size());
                for (const auto& ej : *e) {
                    // [rva, "name"]. Anything else is a schema we do not know; skip
                    // the entry rather than the module, so one bad pair does not cost
                    // the other 2,400 exports.
                    if (!ej.is_array() || ej.size() != 2 || !ej[1].is_string()) continue;
                    std::uint64_t rva = as_u64(ej[0]);
                    if (rva > 0xFFFFFFFFull) continue;
                    mod.exports.emplace_back(static_cast<std::uint32_t>(rva),
                                             ej[1].get<std::string>());
                }
            }
            m.modules.push_back(std::move(mod));
        }
    }

    if (auto it = j.find("regions"); it != j.end() && it->is_array()) {
        for (const auto& rj : *it) {
            Region r;
            r.base = as_u64(rj.value("base", nlohmann::json(0)));
            r.size = as_u64(rj.value("size", nlohmann::json(0)));
            r.classification = rj.value("classification", std::string{"exec"});
            if (auto e = rj.find("entries"); e != rj.end() && e->is_array())
                for (const auto& v : *e) r.entries.push_back(as_u64(v));
            if (auto e = rj.find("executed"); e != rj.end() && e->is_array())
                for (const auto& v : *e) r.executed.push_back(as_u64(v));
            if (auto d = rj.find("dumps"); d != rj.end() && d->is_array()) {
                for (const auto& dj : *d) {
                    Dump dump;
                    dump.file = dj.value("file", std::string{});
                    dump.position = dj.value("position", std::string{});
                    dump.entry = as_u64(dj.value("entry", nlohmann::json(0)));
                    r.dumps.push_back(std::move(dump));
                }
            }
            m.regions.push_back(std::move(r));
        }
    }
    return m;
}

nlohmann::json CapabilityRecord::to_json() const {
    nlohmann::json j;
    j["rule"] = rule;
    j["namespace"] = namespace_;
    j["position"] = position;
    j["base"] = base;
    j["classification"] = classification;
    if (has_offset)
        j["offset"] = offset;
    else
        j["offset"] = nullptr;
    j["scans_matched"] = scans_matched;
    j["vas"] = vas;
    j["scope"] = scope;
    // An array of {va, features} rather than an object keyed by VA: JSON object keys
    // are strings, and a 64-bit address round-trips through one only by convention.
    // Always emitted, empty included, so a reader can tell "this capa-cpp does not
    // compute feature addresses" from "it did and found none here".
    nlohmann::json fv = nlohmann::json::array();
    for (const auto& [va, features] : feature_vas) {
        if (features.empty()) continue;
        fv.push_back({{"va", va}, {"features", features}});
    }
    j["featureVas"] = std::move(fv);
    j["kind"] = kind;
    return j;
}

std::pair<std::uint64_t, std::uint64_t> position_key(const std::string& position) {
    constexpr std::uint64_t BIG = 1ull << 63;  // sentinel for unparseable (Python uses 1<<64)
    auto colon = position.find(':');
    if (colon == std::string::npos) return {BIG, BIG};
    try {
        std::uint64_t seq = std::stoull(position.substr(0, colon), nullptr, 16);
        std::uint64_t steps = std::stoull(position.substr(colon + 1), nullptr, 16);
        return {seq, steps};
    } catch (...) {
        return {BIG, BIG};
    }
}

}  // namespace capa::stat
