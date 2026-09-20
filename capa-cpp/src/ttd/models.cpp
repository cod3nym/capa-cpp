#include "ttd/models.h"

#include <bit>

namespace capa::ttd {

using nlohmann::json;

namespace {

std::string get_str(const json& j, const char* key, const std::string& dflt = "") {
    auto it = j.find(key);
    if (it != j.end() && it->is_string()) return it->get<std::string>();
    return dflt;
}

std::int64_t get_int(const json& j, const char* key, std::int64_t dflt = 0) {
    auto it = j.find(key);
    if (it == j.end()) return dflt;
    if (it->is_number_unsigned()) {
        std::uint64_t u = it->get<std::uint64_t>();
        // capa uses arbitrary-precision ints; we canonicalize to int64 via bit-cast so
        // e.g. 0xFFFFFFFFFFFFFFFE and -2 map to the same key (a minor, deliberate merge).
        return static_cast<std::int64_t>(u);
    }
    if (it->is_number_integer()) return it->get<std::int64_t>();
    if (it->is_number_float()) return static_cast<std::int64_t>(it->get<double>());
    return dflt;
}

std::uint64_t get_u64(const json& j, const char* key, std::uint64_t dflt = 0) {
    auto it = j.find(key);
    if (it == j.end() || !it->is_number()) return dflt;
    if (it->is_number_unsigned()) return it->get<std::uint64_t>();
    if (it->is_number_integer()) return static_cast<std::uint64_t>(it->get<std::int64_t>());
    return static_cast<std::uint64_t>(it->get<double>());
}

Arg parse_arg(const json& e, StringPool& pool) {
    Arg a;
    if (e.is_boolean()) {
        a.kind = Arg::Kind::Bool;
        a.i = e.get<bool>() ? 1 : 0;
    } else if (e.is_string()) {
        a.kind = Arg::Kind::Str;
        a.i = pool.intern(e.get<std::string>());
    } else if (e.is_number_unsigned()) {
        a.kind = Arg::Kind::Int;
        a.i = static_cast<std::int64_t>(e.get<std::uint64_t>());
    } else if (e.is_number_integer()) {
        a.kind = Arg::Kind::Int;
        a.i = e.get<std::int64_t>();
    } else if (e.is_number_float()) {
        a.kind = Arg::Kind::Int;
        a.i = static_cast<std::int64_t>(e.get<double>());
    } else {
        // null/object/array: skip-worthy; represent as Int 0 (won't be emitted usefully)
        a.kind = Arg::Kind::Int;
        a.i = 0;
    }
    return a;
}

Call parse_call(const json& j, Report& r) {
    StringPool& pool = r.strings;
    Call c;
    c.tid = get_int(j, "tid");
    c.seq = get_int(j, "seq");
    c.position = get_str(j, "position");
    c.module = pool.intern(get_str(j, "module"));
    c.api = pool.intern(get_str(j, "api"));
    c.arg_offset = static_cast<std::uint32_t>(r.args.size());
    if (auto it = j.find("args"); it != j.end() && it->is_array()) {
        for (const auto& e : *it) r.args.push_back(parse_arg(e, pool));
    }
    c.arg_count = static_cast<std::uint32_t>(r.args.size() - c.arg_offset);
    if (auto it = j.find("ret"); it != j.end() && it->is_number()) {
        c.ret = get_int(j, "ret");
    }
    return c;
}

Process parse_process(const json& j, Report& r) {
    Process p;
    p.pid = get_int(j, "pid");
    p.ppid = get_int(j, "ppid");
    p.name = get_str(j, "name");
    if (auto it = j.find("environ"); it != j.end() && it->is_array()) {
        for (const auto& e : *it)
            if (e.is_string()) p.environ_strings.push_back(e.get<std::string>());
    }
    if (auto it = j.find("threads"); it != j.end() && it->is_array()) {
        for (const auto& e : *it)
            if (e.is_number()) p.threads.push_back(e.get<std::int64_t>());
    }
    if (auto it = j.find("calls"); it != j.end() && it->is_array()) {
        for (const auto& e : *it)
            if (e.is_object()) p.calls.push_back(parse_call(e, r));
    }
    return p;
}

}  // namespace

Report Report::from_json(const json& j) {
    Report r;
    r.version = static_cast<int>(get_int(j, "version"));

    if (auto it = j.find("trace"); it != j.end() && it->is_object()) {
        r.trace.path = get_str(*it, "path");
        r.trace.arch = get_str(*it, "arch", "x64");
        r.trace.os = get_str(*it, "os", "windows");
    }
    if (auto it = j.find("sample"); it != j.end() && it->is_object()) {
        r.sample.md5 = get_str(*it, "md5");
        r.sample.sha1 = get_str(*it, "sha1");
        r.sample.sha256 = get_str(*it, "sha256");
        r.sample.name = get_str(*it, "name");
    }
    if (auto it = j.find("file"); it != j.end() && it->is_object()) {
        const json& f = *it;
        if (auto a = f.find("imports"); a != f.end() && a->is_array()) {
            for (const auto& e : *a) {
                Import imp;
                imp.dll = get_str(e, "dll");
                imp.name = get_str(e, "name");
                imp.va = get_u64(e, "va");
                r.file.imports.push_back(std::move(imp));
            }
        }
        if (auto a = f.find("exports"); a != f.end() && a->is_array()) {
            for (const auto& e : *a) {
                Export ex;
                ex.name = get_str(e, "name");
                ex.va = get_u64(e, "va");
                r.file.exports.push_back(std::move(ex));
            }
        }
        if (auto a = f.find("sections"); a != f.end() && a->is_array()) {
            for (const auto& e : *a) {
                Section sec;
                sec.name = get_str(e, "name");
                sec.va = get_u64(e, "va");
                r.file.sections.push_back(std::move(sec));
            }
        }
        if (auto a = f.find("strings"); a != f.end() && a->is_array()) {
            for (const auto& e : *a)
                if (e.is_string()) r.file.strings.push_back(e.get<std::string>());
        }
    }
    if (auto it = j.find("processes"); it != j.end() && it->is_array()) {
        for (const auto& e : *it)
            if (e.is_object()) r.processes.push_back(parse_process(e, r));
    }
    r.strings.seal();  // nothing interns after parsing; the lookup table is dead weight
    return r;
}

}  // namespace capa::ttd
