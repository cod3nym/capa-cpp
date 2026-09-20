#include "module_filter.h"

#include <algorithm>
#include <cctype>

namespace capa {

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ends_with(const std::string& s, const char* suffix) {
    const std::string suf = suffix;
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

}  // namespace

const char* module_class_name(ModuleClass c) {
    switch (c) {
        case ModuleClass::MainModule: return "exe";
        case ModuleClass::Module: return "module";
        case ModuleClass::SystemModule: return "system";
        case ModuleClass::Dynamic: return "dynamic";
    }
    return "?";
}

bool is_system_module_path(const std::string& path) {
    const std::string p = lower(path);
    static const char* kDirs[] = {
        "\\windows\\system32\\",     "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",       "\\windows\\systemapps\\",
        "\\systemroot\\system32\\",  "\\systemroot\\syswow64\\",
    };
    for (const char* d : kDirs)
        if (p.find(d) != std::string::npos) return true;
    return false;
}

std::string windowsapps_package(const std::string& path) {
    static const std::string kMarker = "\\windowsapps\\";
    const std::string p = lower(path);
    std::size_t at = p.find(kMarker);
    if (at == std::string::npos) return {};
    std::size_t start = at + kMarker.size();
    std::size_t end = p.find('\\', start);
    if (end == std::string::npos) return {};
    // Just the package component, NOT the path prefix leading to it. The two call
    // sites compare one module's answer against another's, and the same package can
    // reach them spelled differently -- "C:\Program Files\WindowsApps\Pkg\..." from
    // one source, "\??\C:\Program Files\WindowsApps\Pkg\..." from another. Comparing
    // prefixes would call those different packages and drop the sample's own DLLs.
    return p.substr(start, end - start);
}

void classify_modules(std::vector<ModuleEntry>& mods, std::uint64_t image_base) {
    for (ModuleEntry& m : mods) {
        if (m.name.empty()) {
            std::size_t at = m.path.find_last_of("\\/");
            m.name = lower(at == std::string::npos ? m.path : m.path.substr(at + 1));
        }
        m.cls = is_system_module_path(m.path) ? ModuleClass::SystemModule : ModuleClass::Module;
    }
    std::sort(mods.begin(), mods.end(),
              [](const ModuleEntry& a, const ModuleEntry& b) { return a.base < b.base; });

    ModuleEntry* main = nullptr;
    if (image_base != 0) {
        for (ModuleEntry& m : mods)
            if (image_base >= m.base && image_base - m.base < m.size) {
                main = &m;
                break;
            }
    }
    if (main == nullptr) {
        for (ModuleEntry& m : mods)
            if (ends_with(m.name, ".exe")) {
                main = &m;
                break;
            }
    }
    if (main == nullptr) return;

    main->cls = ModuleClass::MainModule;
    // Packaged apps: a WindowsApps module from a package OTHER than the main
    // executable's is framework code the app merely binds.
    const std::string own = windowsapps_package(main->path);
    for (ModuleEntry& m : mods) {
        if (&m == main || m.cls != ModuleClass::Module) continue;
        const std::string pkg = windowsapps_package(m.path);
        if (!pkg.empty() && pkg != own) m.cls = ModuleClass::SystemModule;
    }
}

ModuleClass classify_address(const std::vector<ModuleEntry>& mods, std::uint64_t va) {
    auto it = std::upper_bound(mods.begin(), mods.end(), va,
                               [](std::uint64_t v, const ModuleEntry& m) { return v < m.base; });
    if (it == mods.begin()) return ModuleClass::Dynamic;
    --it;
    if (va - it->base >= it->size) return ModuleClass::Dynamic;
    return it->cls;
}

}  // namespace capa
