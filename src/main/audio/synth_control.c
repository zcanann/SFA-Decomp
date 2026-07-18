#include "src/main/audio/synth_internal.h"


extern void sndBegin(void);
extern void sndEnd(void);

void sndSeqStop(u32 handle)
{
    sndBegin();
    synthFreeHandle(handle);
    sndEnd();
}

void sndSeqSpeed(u32 handle, u16 speed)
{
    sndBegin();
    synthSetHandleValue16(handle, speed);
    sndEnd();
}

void sndSeqContinue(u32 handle)
{
    sndBegin();
    synthRestoreQueuedHandle(handle);
    sndEnd();
}

void sndSeqMute(u32 handle, u32 mute, u32 time)
{
    sndBegin();
    synthSetHandleMixData(handle, mute, time);
    sndEnd();
}
