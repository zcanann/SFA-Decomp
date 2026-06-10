#ifndef MAIN_DLL_GROUNDANIMATOR_STATE_H_
#define MAIN_DLL_GROUNDANIMATOR_STATE_H_

#include "global.h"

typedef struct GroundAnimatorState {
    int falloffBuf;       /* 0x00: f32 per-vertex weights */
    int heightBuf;        /* 0x04: s16 per-vertex base heights */
    int linkedObj;        /* 0x08: nearest group-4 object */
    f32 sinkDepth;        /* 0x0c */
    f32 lastDepth;        /* 0x10 */
    f32 radius;           /* 0x14 */
    f32 yOffset;          /* 0x18 */
    s16 blockEntries[6];  /* 0x1c: matching map-block entry indices */
    s16 vertCount;        /* 0x28 */
    u8 entryCount;        /* 0x2a */
    u8 modelVariant;      /* 0x2b */
    u8 dirtyFrames;       /* 0x2c */
    u8 flags;             /* 0x2d: 1 = on-map, 2 = done, 4 = pressed */
    u8 pad2E[2];
} GroundAnimatorState;

#endif
