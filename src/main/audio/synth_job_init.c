#include "main/audio/synth_job.h"

extern u8 lbl_803BD150[];
extern SynthJob synthJobTable[];
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
        synthJobTable[i].state = 0;
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void)
{
}
