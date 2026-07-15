#include "main/audio/synth_job.h"
#include "main/audio/synth_config.h"

extern u8 streamCallCnt;
extern u8 streamCallDelay;
extern u32 lbl_803DE284;
extern u8 inpAuxB[0x480];
extern u8 inpAuxA[0x480];
SynthJob streamInfo[64];

void streamInit(void)
{
    s32 i;

    streamCallCnt = 0;
    streamCallDelay = 3;
    for (i = 0; i < synthInfo.voiceCount; ++i)
    {
        streamInfo[i].state = SYNTH_JOB_STATE_FREE;
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void)
{
}
