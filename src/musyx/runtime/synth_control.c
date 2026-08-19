#include "musyx/sal_dsp.h"
#include "src/musyx/runtime/synth_internal.h"
#include "musyx/synth_queue.h"
#include "musyx/synth_control.h"

void sndSeqStop(u32 handle) {
    sndBegin();
    seqStop(handle);
    sndEnd();
}

void sndSeqSpeed(u32 handle, u16 speed) {
    sndBegin();
    seqSpeed(handle, speed);
    sndEnd();
}

void sndSeqContinue(u32 handle) {
    sndBegin();
    seqContinue(handle);
    sndEnd();
}

void sndSeqMute(u32 handle, u32 mute, u32 time) {
    sndBegin();
    seqMute(handle, mute, time);
    sndEnd();
}
