#include "main/audio/synth_job.h"

extern u8 lbl_803BD150[];
u8 lbl_803BDA74[0x480];
u8 lbl_803BDEF4[0x484];
SynthJob synthJobTable[64];
extern u8 synthJobTableCountdown;
extern u8 synthJobTablePeriod;
extern u32 lbl_803DE284;

void synthInitJobTable(void)
{
    s32 i;

    synthJobTableCountdown = 0;
    synthJobTablePeriod = 3;
    for (i = 0; i < lbl_803BD150[0x210]; ++i)
    {
        synthJobTable[i].state = SYNTH_JOB_STATE_FREE;
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void)
{
}
