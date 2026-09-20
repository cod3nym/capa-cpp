#include "symbols.h"

#include <algorithm>
#include <cctype>

namespace capa {

bool is_aw_function(const std::string& symbol) {
    if (symbol.size() < 2) return false;
    char last = symbol.back();
    return last == 'A' || last == 'W';
}

bool is_ordinal(const std::string& symbol) {
    return !symbol.empty() && symbol.front() == '#';
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool ends_with(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

std::vector<std::string> generate_symbols(const std::string& dll_in, const std::string& symbol,
                                          bool include_dll) {
    std::vector<std::string> out;

    std::string dll = to_lower(dll_in);
    // trim extensions observed in dynamic traces
    if (ends_with(dll, ".dll")) dll = dll.substr(0, dll.size() - 4);
    else if (ends_with(dll, ".drv")) dll = dll.substr(0, dll.size() - 4);
    else if (ends_with(dll, ".so")) dll = dll.substr(0, dll.size() - 3);

    if (include_dll || is_ordinal(symbol)) {
        out.push_back(dll + "." + symbol);
    }

    if (!is_ordinal(symbol)) {
        out.push_back(symbol);

        if (is_aw_function(symbol)) {
            if (include_dll) {
                out.push_back(dll + "." + symbol.substr(0, symbol.size() - 1));
            }
            out.push_back(symbol.substr(0, symbol.size() - 1));
        }
    }

    return out;
}

std::string reformat_forwarded_export_name(const std::string& forwarded_name) {
    // rpartition('.'): the DLL part may itself be a path containing periods, so split
    // on the last one.
    std::size_t dot = forwarded_name.rfind('.');
    if (dot == std::string::npos) return "." + forwarded_name;  // Python: ("", "", name)
    return to_lower(forwarded_name.substr(0, dot)) + "." + forwarded_name.substr(dot + 1);
}

std::int64_t twos_complement(std::uint64_t val, int bits) {
    if (bits <= 0 || bits > 64) return static_cast<std::int64_t>(val);
    const std::uint64_t sign_bit = 1ull << (bits - 1);
    if (val & sign_bit) {
        // bits == 64 would overflow `1 << bits`; the cast already yields the value.
        if (bits == 64) return static_cast<std::int64_t>(val);
        return static_cast<std::int64_t>(val) - static_cast<std::int64_t>(1ull << bits);
    }
    return static_cast<std::int64_t>(val);
}

}  // namespace capa
