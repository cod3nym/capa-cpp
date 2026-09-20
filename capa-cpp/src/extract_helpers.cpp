#include "extract_helpers.h"

#include <algorithm>
#include <array>
#include <unordered_map>

namespace capa::helpers {

bool is_printable_char(std::uint8_t c) {
    return (c >= 0x20 && c <= 0x7e) || c == 0x09 || c == 0x0a || c == 0x0b || c == 0x0c ||
           c == 0x0d;
}

bool is_printable_ascii_bytes(const std::uint8_t* b, int len) {
    for (int k = 0; k < len; ++k)
        if (!is_printable_char(b[k])) return false;
    return true;
}

bool is_printable_utf16le_bytes(const std::uint8_t* b, int len) {
    for (int k = 1; k < len; k += 2)
        if (b[k] != 0x00) return false;
    for (int k = 0; k < len; k += 2)
        if (!is_printable_char(b[k])) return false;
    return true;
}

bool all_zeros(const std::vector<std::uint8_t>& b) {
    for (std::uint8_t c : b)
        if (c != 0) return false;
    return !b.empty();
}

int printable_len(std::uint64_t value, int size) {
    if (size != 1 && size != 2 && size != 4 && size != 8) return 0;
    std::array<std::uint8_t, 8> chars{};
    for (int k = 0; k < size; ++k) chars[k] = static_cast<std::uint8_t>((value >> (8 * k)) & 0xff);
    if (is_printable_ascii_bytes(chars.data(), size)) return size;
    if (is_printable_utf16le_bytes(chars.data(), size)) return size / 2;
    return 0;
}

void scan_ascii_strings(std::span<const std::uint8_t> buf,
                        const std::function<void(std::string&&, std::size_t)>& on_string) {
    std::size_t i = 0, n = buf.size();
    while (i < n) {
        if (is_printable_char(buf[i]) && buf[i] != 0x00) {
            std::size_t start = i;
            while (i < n && is_printable_char(buf[i])) ++i;
            if (i - start >= MIN_STRING_LEN)
                on_string(std::string(buf.begin() + start, buf.begin() + i), start);
        } else {
            ++i;
        }
    }
}

std::vector<FoundString> scan_ascii_strings(std::span<const std::uint8_t> buf) {
    std::vector<FoundString> out;
    scan_ascii_strings(buf, [&out](std::string&& s, std::size_t offset) {
        out.push_back({std::move(s), offset});
    });
    return out;
}

void scan_unicode_strings(std::span<const std::uint8_t> buf,
                          const std::function<void(std::string&&, std::size_t)>& on_string) {
    std::size_t i = 0, n = buf.size();
    while (i + 1 < n) {
        if (is_printable_char(buf[i]) && buf[i + 1] == 0x00) {
            std::size_t start = i;
            std::string s;
            while (i + 1 < n && is_printable_char(buf[i]) && buf[i + 1] == 0x00) {
                s.push_back(static_cast<char>(buf[i]));
                i += 2;
            }
            if (s.size() >= MIN_STRING_LEN) on_string(std::move(s), start);
        } else {
            ++i;
        }
    }
}

std::vector<FoundString> scan_unicode_strings(std::span<const std::uint8_t> buf) {
    std::vector<FoundString> out;
    scan_unicode_strings(buf, [&out](std::string&& s, std::size_t offset) {
        out.push_back({std::move(s), offset});
    });
    return out;
}

std::vector<std::size_t> carve_embedded_pe(std::span<const std::uint8_t> buf) {
    std::vector<std::size_t> out;
    std::size_t n = buf.size();
    for (std::size_t o = 1; o + 0x40 < n; ++o) {
        if (buf[o] != 'M' || buf[o + 1] != 'Z') continue;
        std::uint32_t e_lfanew = buf[o + 0x3c] | (buf[o + 0x3d] << 8) | (buf[o + 0x3e] << 16) |
                                 (static_cast<std::uint32_t>(buf[o + 0x3f]) << 24);
        std::size_t p = o + e_lfanew;
        if (p + 4 > n) continue;
        if (buf[p] == 'P' && buf[p + 1] == 'E' && buf[p + 2] == 0x00 && buf[p + 3] == 0x00)
            out.push_back(o);
    }
    return out;
}

bool has_loop(const std::vector<std::pair<std::uint64_t, std::uint64_t>>& edges) {
    std::unordered_map<std::uint64_t, int> id;
    std::vector<std::uint64_t> nodes;
    auto node_id = [&](std::uint64_t v) {
        auto it = id.find(v);
        if (it != id.end()) return it->second;
        int k = static_cast<int>(nodes.size());
        id[v] = k;
        nodes.push_back(v);
        return k;
    };
    std::vector<std::vector<int>> adj;
    auto ensure = [&](int k) {
        if (static_cast<int>(adj.size()) <= k) adj.resize(k + 1);
    };
    for (auto& [a, b] : edges) {
        int ia = node_id(a), ib = node_id(b);
        ensure(ia);
        ensure(ib);
        adj[ia].push_back(ib);
    }
    int N = static_cast<int>(nodes.size());
    adj.resize(N);

    std::vector<int> idx(N, -1), low(N, 0), onstk(N, 0);
    std::vector<int> stk;
    int counter = 0;
    bool found = false;

    // iterative Tarjan
    for (int s = 0; s < N && !found; ++s) {
        if (idx[s] != -1) continue;
        std::vector<std::pair<int, std::size_t>> call{{s, 0}};
        while (!call.empty()) {
            auto& [v, ci] = call.back();
            if (ci == 0) {
                idx[v] = low[v] = counter++;
                stk.push_back(v);
                onstk[v] = 1;
            }
            if (ci < adj[v].size()) {
                int w = adj[v][ci++];
                if (idx[w] == -1) {
                    call.push_back({w, 0});
                } else if (onstk[w]) {
                    low[v] = std::min(low[v], idx[w]);
                }
            } else {
                if (low[v] == idx[v]) {
                    int comp = 0, w;
                    do {
                        w = stk.back();
                        stk.pop_back();
                        onstk[w] = 0;
                        ++comp;
                    } while (w != v);
                    if (comp >= 2) found = true;
                }
                call.pop_back();
                if (!call.empty())
                    low[call.back().first] = std::min(low[call.back().first], low[v]);
            }
        }
    }
    // also catch a self-loop edge (a->a), which is a strongly connected component of size 1
    if (!found)
        for (auto& [a, b] : edges)
            if (a == b) return true;
    return found;
}

}  // namespace capa::helpers
