/*
 * Manual recovery stub based on claimed split coverage and the surrounding
 * DF/SC/SH corridor.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Current EN split:
 * - main/dll/DF/dll_195.c
 * - 0x801C1BCC-0x801C1BF4
 *
 * Nearby corridor context:
 * - previous split: main/dll/DF/dll_194.c
 * - next split: main/dll/DF/dll_196.c
 */

/*
 * No function names were promoted here yet.
 * Start from the current EN split window and the surrounding corridor.
 */


#include "ghidra_import.h"

/* dfropenode_setScale: copy 4 floats from obj->_b8[0x1c..0x28] to *out_dst[0..0xc]. */
void dfropenode_setScale(int *obj, f32 *out) {
    int *p = (int*)obj[0xb8/4];
    out[0] = *(f32*)((char*)p + 0x1c);
    out[1] = *(f32*)((char*)p + 0x20);
    out[2] = *(f32*)((char*)p + 0x24);
    out[3] = *(f32*)((char*)p + 0x28);
}
