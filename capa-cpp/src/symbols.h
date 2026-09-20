// Ports capa/features/extractors/helpers.py::generate_symbols (+ is_aw_function /
// is_ordinal). Over-generates API/import name variants so rules match whether they
// reference the DLL, the bare name, or the A/W-trimmed form.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace capa {

bool is_aw_function(const std::string& symbol);
bool is_ordinal(const std::string& symbol);

std::vector<std::string> generate_symbols(const std::string& dll, const std::string& symbol,
                                          bool include_dll = false);

// A forwarded export names a DLL (possibly a path, so split on the LAST period) and a
// symbol. Lowercase the DLL, keep the symbol verbatim.
std::string reformat_forwarded_export_name(const std::string& forwarded_name);

// Interpret the low `bits` of `val` as a two's-complement signed integer.
std::int64_t twos_complement(std::uint64_t val, int bits);

}  // namespace capa
