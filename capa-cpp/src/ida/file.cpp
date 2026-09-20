// Ports capa/features/extractors/ida/file.py: exports, imports, strings, section
// names, embedded PEs and statically-linked function names.
#include "ida/extractor.h"

#include "extract_helpers.h"
#include "symbols.h"

namespace capa::ida {

namespace {

constexpr std::uint32_t MAX_OFFSET_PE_AFTER_MZ = 0x200;

void add(std::vector<FeaturePair>& out, Feature f, const Address& a) {
    out.emplace_back(std::move(f), a);
}
Address va(ea_t ea) { return Address::absolute(static_cast<std::uint64_t>(ea)); }

std::vector<std::uint8_t> xor_static(const std::vector<std::uint8_t>& data, std::uint8_t key) {
    std::vector<std::uint8_t> out(data.size());
    for (std::size_t i = 0; i < data.size(); ++i) out[i] = data[i] ^ key;
    return out;
}

// capa/features/extractors/ida/file.py::check_segment_for_pe — an XOR-aware carve
// over IDA's own byte search, so it finds PEs encoded with a single-byte key.
std::vector<ea_t> check_segment_for_pe(const SegInfo& seg) {
    std::vector<ea_t> found;
    const std::vector<std::uint8_t> mz{'M', 'Z'};
    const std::vector<std::uint8_t> pe{'P', 'E'};

    for (int k = 0; k < 256; ++k) {
        std::uint8_t key = static_cast<std::uint8_t>(k);
        std::vector<std::uint8_t> mzx = xor_static(mz, key);
        std::vector<std::uint8_t> pex = xor_static(pe, key);

        for (ea_t off : find_byte_sequence(seg.start_ea, seg.end_ea, mzx)) {
            // the MZ header's e_lfanew field sits at +0x3c
            ea_t e_lfanew = off + 0x3C;
            if (seg.end_ea < e_lfanew + 4) continue;

            std::vector<std::uint8_t> raw = read_bytes_at(e_lfanew, 4);
            if (raw.size() != 4) continue;
            std::vector<std::uint8_t> dec = xor_static(raw, key);
            std::uint32_t newoff = static_cast<std::uint32_t>(dec[0]) |
                                   (static_cast<std::uint32_t>(dec[1]) << 8) |
                                   (static_cast<std::uint32_t>(dec[2]) << 16) |
                                   (static_cast<std::uint32_t>(dec[3]) << 24);
            if (newoff > MAX_OFFSET_PE_AFTER_MZ) continue;

            ea_t peoff = off + newoff;
            if (seg.end_ea < peoff + 2) continue;

            std::vector<std::uint8_t> at_pe = read_bytes_at(peoff, 2);
            if (at_pe.size() == 2 && at_pe[0] == pex[0] && at_pe[1] == pex[1]) found.push_back(off);
        }
    }
    return found;
}

void extract_file_embedded_pe(std::vector<FeaturePair>& out) {
    for (const SegInfo& seg : get_segments(/*skip_header_segments=*/true)) {
        for (ea_t ea : check_segment_for_pe(seg)) {
            qoff64_t file_offset = get_fileregion_offset(ea);
            if (file_offset != -1)
                add(out, Feature::characteristic("embedded pe"),
                    Address::file_offset(static_cast<std::uint64_t>(file_offset)));
        }
    }
}

void extract_file_export_names(std::vector<FeaturePair>& out) {
    std::size_t n = get_entry_qty();
    for (std::size_t i = 0; i < n; ++i) {
        uval_t ord = get_entry_ordinal(i);
        ea_t ea = get_entry(ord);
        if (ea == BADADDR) continue;

        qstring fwd;
        if (get_entry_forwarder(&fwd, ord) > 0) {
            std::string name = reformat_forwarded_export_name(fwd.c_str());
            add(out, Feature::export_(name), va(ea));
            add(out, Feature::characteristic("forwarded export"), va(ea));
        } else {
            qstring name;
            if (get_entry_name(&name, ord) <= 0) continue;
            add(out, Feature::export_(name.c_str()), va(ea));
        }
    }
}

void extract_file_import_names(std::vector<FeaturePair>& out) {
    for (const auto& [ea, info] : get_file_imports()) {
        Address addr = va(ea);
        std::string dll, symbol;

        if (!info.function.empty() && info.ordinal != 0) {
            // named *and* ordinal: emit by name here, then fall through to by-ordinal
            for (const std::string& name :
                 generate_symbols(info.library, info.function, /*include_dll=*/true))
                add(out, Feature::import_(name), addr);
            dll = info.library;
            symbol = "#" + std::to_string(info.ordinal);
        } else if (!info.function.empty()) {
            dll = info.library;
            symbol = info.function;
        } else if (info.ordinal != 0) {
            dll = info.library;
            symbol = "#" + std::to_string(info.ordinal);
        } else {
            continue;
        }

        for (const std::string& name : generate_symbols(dll, symbol, /*include_dll=*/true))
            add(out, Feature::import_(name), addr);
    }

    for (const auto& [ea, info] : get_file_externs())
        add(out, Feature::import_(info.function), va(ea));
}

void extract_file_section_names(std::vector<FeaturePair>& out) {
    for (const SegInfo& seg : get_segments(/*skip_header_segments=*/true))
        add(out, Feature::section(seg.name), va(seg.start_ea));
}

void extract_file_strings(std::vector<FeaturePair>& out) {
    for (const SegInfo& seg : get_segments()) {
        std::vector<std::uint8_t> buf = get_segment_buffer(seg);
        if (buf.empty()) continue;

        auto emit = [&](const std::vector<helpers::FoundString>& found) {
            for (const auto& s : found) {
                ea_t ea = seg.start_ea + static_cast<ea_t>(s.offset);
                qoff64_t file_offset = get_fileregion_offset(ea);
                if (file_offset == -1) continue;
                add(out, Feature::string(s.s),
                    Address::file_offset(static_cast<std::uint64_t>(file_offset)));
            }
        };
        emit(helpers::scan_ascii_strings(buf));
        emit(helpers::scan_unicode_strings(buf));
    }
}

void extract_file_function_names(std::vector<FeaturePair>& out) {
    // the names of statically-linked library functions
    for (ea_t ea : all_function_eas()) {
        if (!(get_func_flags_at(ea) & FUNC_LIB)) continue;
        std::string name = get_ea_name(ea);
        if (name.empty()) continue;
        add(out, Feature::function_name(name), va(ea));
        if (name.front() == '_') {
            // some linkers prefix linked routines with `_` to avoid collisions; match
            // both spellings, e.g. `_fwrite` and `fwrite`.
            add(out, Feature::function_name(name.substr(1)), va(ea));
        }
    }
}

}  // namespace

void extract_file_features(std::vector<FeaturePair>& out) {
    extract_file_export_names(out);
    extract_file_import_names(out);
    extract_file_strings(out);
    extract_file_section_names(out);
    extract_file_embedded_pe(out);
    extract_file_function_names(out);
}

}  // namespace capa::ida
