#include "pseudocode.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include <hexrays.hpp>

namespace idacapa {

namespace {

// Findings for one decompiled function: the rules that matched anywhere inside it, and
// the per-address markers to hang off individual pseudocode lines.
struct FuncFindings {
    std::set<std::string> rules;                        // header lines, deduplicated
    std::map<ea_t, std::vector<std::string>> by_address;  // marker text per address
};

std::map<ea_t, FuncFindings> g_by_function;  // keyed by function entry ea
bool g_callback_installed = false;
int g_available = -1;  // -1 unknown, 0 no decompiler, 1 present

// "capa: rule - feature" -> "rule", which is what belongs in the header.
std::string rule_part(const std::string& line) {
    std::string s = line;
    const std::string prefix = ANNOTATION_PREFIX;
    if (s.rfind(prefix, 0) == 0) s = s.substr(prefix.size());
    std::size_t dash = s.find(" - ");
    if (dash != std::string::npos) s = s.substr(0, dash);
    return s;
}

// Escape the characters IDA's line formatter would otherwise eat.
qstring as_comment(const std::string& text) {
    qstring escaped;
    for (char c : text) {
        if (c == COLOR_ON || c == COLOR_OFF || c == COLOR_ESC || c == COLOR_INV)
            escaped.append(COLOR_ESC);
        escaped.append(c);
    }
    qstring out;
    out.append(SCOLOR_ON);
    out.append(SCOLOR_AUTOCMT);
    out.append(escaped);
    out.append(SCOLOR_OFF);
    out.append(SCOLOR_AUTOCMT);
    return out;
}

// The pseudocode line an address decompiled into, or -1.
int line_of_address(cfunc_t* cfunc, ea_t ea) {
    eamap_t& eamap = cfunc->get_eamap();
    eamap_iterator_t it = eamap_find(&eamap, ea);
    if (it == eamap_end(&eamap)) return -1;

    const cinsnptrvec_t& insns = eamap_second(it);
    for (const cinsn_t* insn : insns) {
        int x = 0, y = 0;
        if (cfunc->find_item_coords(insn, &x, &y)) return y;
    }
    return -1;
}

ssize_t idaapi hexrays_callback(void*, hexrays_event_t event, va_list va) {
    if (event != hxe_func_printed) return 0;

    cfunc_t* cfunc = va_arg(va, cfunc_t*);
    if (cfunc == nullptr) return 0;

    auto it = g_by_function.find(cfunc->entry_ea);
    if (it == g_by_function.end()) return 0;
    const FuncFindings& findings = it->second;

    // Per-address markers first: inserting the header would shift every line number.
    for (const auto& [ea, marks] : findings.by_address) {
        int line = line_of_address(cfunc, ea);
        if (line < 0 || line >= static_cast<int>(cfunc->sv.size())) continue;
        for (const std::string& mark : marks) {
            cfunc->sv[line].line.append("  ");
            cfunc->sv[line].line.append(as_comment("// " + mark));
        }
    }

    // Then the header, at the very top.
    strvec_t header;
    for (const std::string& rule : findings.rules)
        header.push_back().line = as_comment("// capa: " + rule);
    if (!header.empty()) {
        header.push_back().line = qstring();
        cfunc->sv.insert(cfunc->sv.begin(), header.begin(), header.end());
    }
    return 0;
}

// Throw away cached decompilations and repaint whatever is on screen, so a change
// takes effect without the user having to close and reopen the pseudocode.
void refresh_open_pseudocode() {
    clear_cached_cfuncs();
    // IDA names pseudocode windows "Pseudocode-A", "-B", ... There is no API to
    // enumerate them, so walk the letters; a gap is possible if a middle one was
    // closed, hence checking all 26 rather than stopping at the first miss.
    for (int i = 0; i < 26; ++i) {
        char title[32];
        qsnprintf(title, sizeof(title), "Pseudocode-%c", 'A' + i);
        TWidget* w = find_widget(title);
        if (w != nullptr) refresh_custom_viewer(w);
    }
}

}  // namespace

bool pseudocode_available() {
    if (g_available < 0) {
        g_available = init_hexrays_plugin() ? 1 : 0;
        if (g_available == 0)
            msg("capa: no Hex-Rays decompiler found; results will be shown in the "
                "disassembly only.\n");
    }
    return g_available == 1;
}

void set_pseudocode_annotations(const AnnotationMap& annotations) {
    if (!pseudocode_available()) return;

    g_by_function.clear();
    for (const auto& [ea, lines] : annotations) {
        ea_t fea = get_func_start(ea);
        if (fea == BADADDR) continue;  // not in a function: nothing to decompile
        FuncFindings& f = g_by_function[fea];
        for (const std::string& line : lines) {
            f.rules.insert(rule_part(line));
            // The function's own match already reads as the header; only the more
            // specific feature lines are worth repeating beside a statement.
            if (line.find(" - ") != std::string::npos)
                f.by_address[ea].push_back(rule_part(line) + line.substr(line.find(" - ")));
        }
    }

    const bool want = !g_by_function.empty();
    if (want && !g_callback_installed)
        g_callback_installed = install_hexrays_callback(hexrays_callback, nullptr);
    else if (!want && g_callback_installed) {
        remove_hexrays_callback(hexrays_callback, nullptr);
        g_callback_installed = false;
    }

    refresh_open_pseudocode();
}

void shutdown_pseudocode() {
    if (g_callback_installed) {
        remove_hexrays_callback(hexrays_callback, nullptr);
        g_callback_installed = false;
    }
    g_by_function.clear();
    if (g_available == 1) term_hexrays_plugin();
}

}  // namespace idacapa
