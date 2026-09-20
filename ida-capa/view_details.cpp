#include "view_details.h"

#include <cstring>
#include <string>

namespace idacapa {

const char* const DETAILS_TITLE = "capa details";

namespace {

// The first "0x...." on a line, or BADADDR, so double-clicking a feature jumps to
// where it was found.
//
// Parsed by hand rather than with strtoull: pro.h defines `strtoull` to the
// Microsoft-only `_strtoui64`, which does not exist in namespace std.
ea_t address_on_line(const char* tagged) {
    if (tagged == nullptr) return BADADDR;
    qstring plain;
    tag_remove(&plain, tagged);

    const char* at = std::strstr(plain.c_str(), "0x");
    if (at == nullptr) return BADADDR;

    std::uint64_t v = 0;
    int digits = 0;
    for (const char* p = at + 2; *p != '\0'; ++p, ++digits) {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else break;
        if (digits >= 16) return BADADDR;  // longer than an address can be
        v = (v << 4) | static_cast<std::uint64_t>(d);
    }
    if (digits == 0) return BADADDR;
    return static_cast<ea_t>(v);
}

bool idaapi on_dblclick(TWidget* v, int /*shift*/, void* /*ud*/) {
    ea_t ea = address_on_line(get_custom_viewer_curline(v, /*mouse=*/true));
    if (ea == BADADDR || !is_mapped(ea)) return false;
    jumpto(ea);
    return true;
}

const custom_viewer_handlers_t VIEW_HANDLERS(
    nullptr,   // keyboard
    nullptr,   // popup
    nullptr,   // mouse_moved
    nullptr,   // click
    on_dblclick,
    nullptr,   // curpos
    nullptr,   // close
    nullptr,   // help
    nullptr);  // adjust_place

qstring comment_line(const std::string& text) {
    qstring out;
    out.append(SCOLOR_ON);
    out.append(SCOLOR_AUTOCMT);
    out.append(text.c_str());
    out.append(SCOLOR_OFF);
    out.append(SCOLOR_AUTOCMT);
    return out;
}

std::string ea_to_hex(ea_t ea) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(ea));
    return buf;
}

// Render a match subtree as indented text: the same shape the explorer would show if
// IDA folders could carry data.
void render_node(const ResultNode& node, int depth, qstrvec_t& out) {
    std::string line(static_cast<std::size_t>(depth) * 2, ' ');
    line += node.info;
    if (node.address != BADADDR) line += "  @ " + ea_to_hex(node.address);
    if (!node.details.empty()) line += "   " + node.details;
    out.push_back(qstring(line.c_str()));

    for (const ResultNode& child : node.children) render_node(child, depth + 1, out);
}

}  // namespace

DetailsView::~DetailsView() { close(); }

void DetailsView::render(const qstrvec_t& lines, bool activate) {
    m_lines.clear();
    for (const qstring& l : lines) m_lines.push_back().line = l;
    if (m_lines.empty()) m_lines.push_back().line = " ";

    simpleline_place_t first;
    simpleline_place_t last(static_cast<int>(m_lines.size() - 1));

    if (m_widget == nullptr) {
        m_widget = create_custom_viewer(DETAILS_TITLE, &first, &last, &first, nullptr, &m_lines,
                                        &VIEW_HANDLERS, this);
        display_widget(m_widget, WOPN_DP_TAB | WOPN_RESTORE);
    } else {
        set_custom_viewer_range(m_widget, &first, &last);
        refresh_custom_viewer(m_widget);
    }

    if (activate && m_widget != nullptr) activate_widget(m_widget, true);
}

void DetailsView::show(const std::string& rule_name, const std::string& ns,
                       const ResultNode& match, bool activate) {
    qstrvec_t lines;

    std::string header = rule_name;
    if (!ns.empty()) header += "   [" + ns + "]";
    lines.push_back(comment_line(header));

    std::string sub = match.info;
    if (match.address != BADADDR) sub += "  @ " + ea_to_hex(match.address);
    lines.push_back(comment_line(sub));
    lines.push_back(qstring());

    // The match node itself is the scope line already printed above, so start at its
    // children — otherwise every tree would be indented under a repeat of that line.
    for (const ResultNode& child : match.children) render_node(child, 0, lines);

    render(lines, activate);
}

void DetailsView::show_message(const std::string& text, bool activate) {
    qstrvec_t lines;
    lines.push_back(comment_line(text));
    render(lines, activate);
}

void DetailsView::close() {
    if (m_widget == nullptr) return;
    TWidget* w = m_widget;
    m_widget = nullptr;  // before close_widget: the close notification comes back to us
    close_widget(w, 0);
}

}  // namespace idacapa
