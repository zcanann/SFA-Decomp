#include "ghidra_import.h"

/*
 * fn_80281338 — large voice/instrument event handler with multiple
 * dispatch paths and table walks (~1488 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_80281338(u8 idx, u8 a, u8 b, u8 mask)
{
    (void)idx; (void)a; (void)b; (void)mask;
}
#pragma dont_inline reset

/*
 * fn_80281908 — wrapper that splits a 16-bit data word into two byte
 * halves and dispatches to fn_80281338 twice (~296 instructions).
 * Stubbed.
 */
#pragma dont_inline on
void fn_80281908(u8 idx, u8 a, u8 b, u32 data)
{
    (void)idx; (void)a; (void)b; (void)data;
}
#pragma dont_inline reset
