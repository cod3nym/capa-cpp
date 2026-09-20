// Deciding which of a process's modules are worth analysing.
//
// Both backends that see a whole process face the same question. capa-cpp.exe reads a
// .dmp directly; the IDA plugin works over a database opened on one. Either way the
// address space holds the sample plus every DLL Windows loaded behind it, and
// reporting ntdll's and kernel32's capabilities as if they were the sample's is worse
// than useless -- it buries the four rules that matter under four hundred that do not.
//
// The policy lives here, in one place, precisely so the two backends cannot drift:
// `capa-cpp <dump> --dump-modules` prints exactly the classification the IDA plugin
// will apply, which is the only way to check the plugin's filter without IDA open.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace capa {

enum class ModuleClass {
    MainModule,    // the process image itself
    Module,        // a loaded module outside the system directories
    SystemModule,  // Windows' own code
    Dynamic,       // memory belonging to no module: runtime allocations, shellcode
};

const char* module_class_name(ModuleClass c);

// Is this path inside a Windows system directory? Matches the several spellings a
// dump or a debugger can carry ("C:\Windows\...", "\??\C:\Windows\...",
// "\SystemRoot\...", "\Device\HarddiskVolume3\Windows\...").
bool is_system_module_path(const std::string& path);

// The package directory of a path under \Program Files\WindowsApps\, lowercased and
// including the package component; empty if the path is not there. A packaged app is
// installed beside the frameworks it binds -- WindowsAppRuntime, VCLibs, the XAML
// stack -- so the package, not the directory, is what separates the sample from
// Microsoft's code.
std::string windowsapps_package(const std::string& path);

// One module as either backend sees it, before classification.
struct ModuleEntry {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string path;  // full path where known; may be a bare name
    std::string name;  // lowercased basename
    ModuleClass cls = ModuleClass::Module;
};

// Classify `mods` in place and return it sorted by base.
//
// `image_base` is the process image's load address when the caller knows it (0 if
// not); the module containing it is the main executable and is never classified as
// system, wherever it happens to live -- a packed sample dropped into System32 is
// still the thing under analysis. Failing that, the first .exe is taken as the main
// module.
void classify_modules(std::vector<ModuleEntry>& mods, std::uint64_t image_base = 0);

// The class of `va` given a list already put through classify_modules. Anything
// outside every module is Dynamic: unbacked, runtime-allocated memory, which is the
// most interesting thing in a process dump rather than the least.
ModuleClass classify_address(const std::vector<ModuleEntry>& mods, std::uint64_t va);

}  // namespace capa
