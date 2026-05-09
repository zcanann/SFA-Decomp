#include "ghidra_import.h"
#include "main/dll/brokecannon.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/dll/SH/SHthorntail_internal.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void Music_Trigger(int trackId, int restart);

/*
 * --INFO--
 *
 * Function: SH_LevelControl_setMusic
 * EN v1.0 Address: 0x801D80F4
 * EN v1.0 Size: 532b
 */
#pragma peephole off
#pragma scheduling off
void SH_LevelControl_setMusic(short *obj)
{
    if ((*gSHthorntailAnimationInterface)->isTailSwingQueued(0) != 0) {
        if (obj[8] == 0x39 || obj[8] == -1) {
            obj[8] = 0x2d;
            if ((*(int *)obj & 1) != 0) {
                Music_Trigger(0x39, 0);
                Music_Trigger(0x2d, 1);
            }
        }
        if (obj[9] == 0xc2 || obj[9] == -1) {
            obj[9] = 0xce;
            if ((*(int *)obj & 2) != 0) {
                Music_Trigger(0xc2, 0);
                Music_Trigger(0xce, 1);
            }
        }
    } else {
        if (obj[8] == 0x2d || obj[8] == -1) {
            obj[8] = 0x39;
            if ((*(int *)obj & 1) != 0) {
                Music_Trigger(0x2d, 0);
                Music_Trigger(0x39, 1);
            }
        }
        if (obj[9] == 0xce || obj[9] == -1) {
            obj[9] = 0xc2;
            if ((*(int *)obj & 2) != 0) {
                Music_Trigger(0xce, 0);
                Music_Trigger(0xc2, 1);
            }
        }
    }
    if (GameBit_Get(0xb) != 0) {
        if (GameBit_Get(0x64b) != 0) {
            GameBit_Set(0x390, 1);
        }
        SCGameBitLatch_Update((SCGameBitLatchState *)obj, 1, 0x1a7, 0x64b, 0x372, obj[8]);
        SCGameBitLatch_Update((SCGameBitLatchState *)obj, 2, 0x1a8, 0xc0, 0x390, obj[9]);
        SCGameBitLatch_Update((SCGameBitLatchState *)obj, 4, -1, -1, 0x393, 0x36);
        SCGameBitLatch_Update((SCGameBitLatchState *)obj, 8, -1, -1, 0xa32, 0x98);
        SCGameBitLatch_Update((SCGameBitLatchState *)obj, 0x10, -1, -1, 0xbfe, 0xc3);
    }
}
#pragma scheduling reset
#pragma peephole reset
