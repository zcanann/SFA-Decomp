#include "main/audio/synth_job.h"
#include "main/audio/synth_config.h"

extern u8 streamCallCnt;
extern u8 streamCallDelay;
extern u32 lbl_803DE284;
u8 lbl_803BDA74[0x480];
u8 lbl_803BDEF4[0x484];
SynthJob streamInfo[64];

void streamInit(void)
{
    s32 i;

    streamCallCnt = 0;
    streamCallDelay = 3;
    for (i = 0; i < lbl_803BD150[0x210]; ++i)
    {
        streamInfo[i].state = SYNTH_JOB_STATE_FREE;
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void)
{
}
