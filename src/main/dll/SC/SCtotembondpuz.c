#include "ghidra_import.h"
#include "main/dll/SC/SCtotembondpuz.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

/*
 * --INFO--
 *
 * Function: SCGameBitLatch_UpdateInverted
 * EN v1.0 Address: 0x801D8060
 */
#pragma scheduling off
#pragma peephole off
void SCGameBitLatch_UpdateInverted(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                   s16 clearIfClearBit, s16 latchBit, int musicId)
{
    GameBit_Set(latchBit, !GameBit_Get(latchBit));
    SCGameBitLatch_Update(state, mask, clearIfSetBit, clearIfClearBit, latchBit, musicId);
    GameBit_Set(latchBit, !GameBit_Get(latchBit));
}
#pragma peephole reset
#pragma scheduling reset
