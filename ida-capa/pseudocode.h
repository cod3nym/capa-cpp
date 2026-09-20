// Showing capa's findings in the Hex-Rays pseudocode view.
//
// The decompiler does not display the disassembly comments capa writes, so the same
// findings are injected into the generated pseudocode text instead: a header listing
// the rules that matched in this function, and a trailing marker on the line each
// matched address decompiled into.
//
// This works on the *printed text* (`hxe_func_printed`, editing `cfunc_t::sv`) rather
// than on user comments. Hex-Rays user comments are anchored to a ctree location, and
// an anchor the decompiler cannot place again becomes an "orphan comment" that sticks
// in the database. Text injection has no such failure mode: it is regenerated from our
// own table every time a function is decompiled, and switching it off leaves nothing
// behind.
//
// The decompiler is optional. If it is not installed, every function here is a no-op.
#pragma once

#include "pch.h"

#include "annotate.h"

namespace idacapa {

// Bring up the decompiler bridge, once. False when there is no decompiler, in which
// case the rest of this interface does nothing.
bool pseudocode_available();

// Show these findings in decompiled output. Passing an empty map turns the display off.
// Already-open pseudocode windows are refreshed.
void set_pseudocode_annotations(const AnnotationMap& annotations);

// Drop everything and uninstall the decompiler callback.
void shutdown_pseudocode();

}  // namespace idacapa
