#include "musyx/hw_aram.h"
#include "musyx/synth_config.h"
#include "musyx/aram.h"

u32 hwExitStream(u32 value) {
    return __cvt_fp2unsigned(4096.0f * (f32)value / (f32)SYNTH_CONFIGURATION->sampleRate);
}

void hwInitSampleMem(u32 baseAddr, u32 length) {
    aramInit(length);
}

void hwExitSampleMem(void) {
    aramExit();
}
