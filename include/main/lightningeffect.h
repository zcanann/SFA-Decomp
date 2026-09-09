#ifndef MAIN_LIGHTNINGEFFECT_H_
#define MAIN_LIGHTNINGEFFECT_H_

#include "types.h"
#include "global.h"

/* Buffer returned by lightningCreate: beam endpoints, segmentation densities and lifetime. */
typedef struct LightningEffect {
    f32 start[3];             /* 0x00: beam source position */
    f32 end[3];               /* 0x0c: beam target position */
    f32 boltSegmentDensity;   /* 0x18 */
    f32 strandSegmentDensity; /* 0x1c */
    u16 timer;                /* 0x20: frames elapsed */
    u16 lifetime;             /* 0x22: frames until the beam expires */
    u16 seed;                 /* 0x24 */
    u8 width;                 /* 0x26 */
    u8 flags;                 /* 0x27 */
} LightningEffect;

STATIC_ASSERT(sizeof(LightningEffect) == 0x28);
STATIC_ASSERT(offsetof(LightningEffect, boltSegmentDensity) == 0x18);
STATIC_ASSERT(offsetof(LightningEffect, strandSegmentDensity) == 0x1C);
STATIC_ASSERT(offsetof(LightningEffect, lifetime) == 0x22);
STATIC_ASSERT(offsetof(LightningEffect, width) == 0x26);

#endif /* MAIN_LIGHTNINGEFFECT_H_ */
