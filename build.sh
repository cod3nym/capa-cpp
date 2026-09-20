#!/usr/bin/env bash
# Convenience build wrapper for capa-cpp (Git Bash).
#
# Usage: ./build.sh [Debug|Release]   build that configuration (default: Debug)
#        ./build.sh clean [Debug|Release|all]
#                                     delete build output (default: all)
#
# Every artifact -- the exe, its pdb and every .obj -- lands under build/<Configuration>/,
# which is why cleaning is just an rm. See the comment in capa-cpp/capa-cpp.vcxproj.
#
# The plugin has its own wrapper: ida-capa/build.ps1, writing to the same build/<Config>/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"

if [[ "${1:-}" == "clean" ]]; then
    case "${2:-all}" in
        all)   targets=("$BUILD") ;;
        Debug|Release) targets=("$BUILD/${2}") ;;
        *) echo "usage: $0 clean [Debug|Release|all]" >&2; exit 2 ;;
    esac
    for t in "${targets[@]}"; do
        if [[ -d "$t" ]]; then
            rm -rf "$t"
            echo "removed: $t"
        else
            echo "nothing to remove: $t"
        fi
    done
    exit 0
fi

CONFIG="${1:-Debug}"
if [[ "$CONFIG" != "Debug" && "$CONFIG" != "Release" ]]; then
    echo "usage: $0 [Debug|Release] | $0 clean [Debug|Release|all]" >&2
    exit 2
fi

VS="/c/Program Files/Microsoft Visual Studio/18/Community"
MSBUILD="$VS/MSBuild/Current/Bin/amd64/MSBuild.exe"
export VCPKG_ROOT="$VS/VC/vcpkg"

"$MSBUILD" "$ROOT/capa-cpp/capa-cpp.vcxproj" \
    -p:Configuration="$CONFIG" -p:Platform=x64 -m -nologo -v:minimal

# Checked rather than announced. This line used to print a path the build had not written
# to for weeks, where an old binary happened to sit -- so it looked like a successful build
# of code that was never compiled.
EXE="$BUILD/$CONFIG/capa-cpp.exe"
if [[ ! -f "$EXE" ]]; then
    echo "error: build reported success but $EXE is missing" >&2
    exit 1
fi
echo "built: $EXE"
