#ifndef MAIN_DLL_DIMMAGICBRIDGE_STATE_H_
#define MAIN_DLL_DIMMAGICBRIDGE_STATE_H_

#include "global.h"

typedef struct DimMagicBridgeState {
    f32 minVertexY; /* lowest model vertex, wave reference */
    f32 unk04[0xF];
    u8 segmentLit[0xF]; /* per-segment ignition flags */
    u8 segmentCount; /* 10 */
    u8 segmentGlow[0xF]; /* per-segment burn ramp 0..0xFF */
    u8 ignited; /* gamebit 0x1E9 / anim event 1 */
    u16 wavePhase; /* texture channel 0 scroll accumulator */
    u16 wavePhaseB; /* texture channel 1 scroll accumulator */
    s16 igniteTimer; /* 0x10-frame cadence between segment ignitions */
    u8 pad66[2];
} DimMagicBridgeState;


/* extern-cleanup: consolidated prototypes */
void dimmagicbridge_scrollTextureChannels(int obj, u8* sub);

#endif
