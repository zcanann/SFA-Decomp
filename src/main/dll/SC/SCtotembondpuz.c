#include "ghidra_import.h"
#include "main/dll/SC/SCtotembondpuz.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void fn_801D7ED4(void *p1, int p2, int p3, int p4, s16 p5, int p6);

/*
 * --INFO--
 *
 * Function: fn_801D8060
 * EN v1.0 Address: 0x801D8060
 */
#pragma scheduling off
#pragma peephole off
void fn_801D8060(void *p1, int p2, int p3, int p4, s16 p5, int p6)
{
    GameBit_Set(p5, !GameBit_Get(p5));
    fn_801D7ED4(p1, p2, p3, p4, p5, p6);
    GameBit_Set(p5, !GameBit_Get(p5));
}
#pragma peephole reset
#pragma scheduling reset
