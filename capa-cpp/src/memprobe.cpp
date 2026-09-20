#include "memprobe.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// PSAPI_VERSION 2 is what makes psapi.h declare the K32-prefixed entry points, which
// live in kernel32 -- so this costs no extra import library.
#define PSAPI_VERSION 2
#include <psapi.h>

namespace capa {

MemUsage process_memory() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!K32GetProcessMemoryInfo(GetCurrentProcess(),
                                 reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                                 sizeof(counters)))
        return {};

    MemUsage out;
    out.peak_working_set = static_cast<std::uint64_t>(counters.PeakWorkingSetSize);
    out.working_set = static_cast<std::uint64_t>(counters.WorkingSetSize);
    // PrivateUsage is the committed private bytes, which is the number that actually
    // decides whether the next allocation throws: a process can be trimmed out of its
    // working set and still be at the commit limit.
    out.peak_commit = static_cast<std::uint64_t>(counters.PeakPagefileUsage);
    return out;
}

}  // namespace capa
