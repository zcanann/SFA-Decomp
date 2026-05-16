#include "ghidra_import.h"

extern int synthGetNextChannelEvent(u8 i);
extern void synthInsertChannelEvent(int slot, int item);

extern int gSynthCurrentVoice;

/*
 * fn_8026E0E4 - large voice/MIDI dispatch (~1920 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026E0E4(void) {}
#pragma dont_inline reset

/*
 * Iterate 64 voice slots: for each active one, append it to the studio's
 * voice list. Uses an indirection table when present.
 *
 * EN v1.1 Address: 0x8026E864, size 168b
 */
void fn_8026E864(void)
{
    u32 i;
    u32 x;
    if (*(u32 *)(gSynthCurrentVoice + 0x14e4) == 0) {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    } else {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                u8 *table = *(u8 **)(gSynthCurrentVoice + 0x14e4);
                synthInsertChannelEvent(gSynthCurrentVoice + table[i] * 0x38 + 0x14e8, x);
            }
        }
    }
}

/*
 * fn_8026E90C - voice-loop to add one voice (~196 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026E90C(u8 voice)
{
    (void)voice;
}
#pragma dont_inline reset

/*
 * fn_8026E9D0 - large 628-instr voice update with FP math. Stubbed.
 */
#pragma dont_inline on
int fn_8026E9D0(u8 voice, int param)
{
    (void)voice; (void)param;
    return 0;
}
#pragma dont_inline reset
