#ifndef MAIN_SKY_STATE_H_
#define MAIN_SKY_STATE_H_

#include "global.h"

/*
 * SkyState - the global sky/time-of-day state block pointed to by
 * gSkyState (sky.c). Three 0xA4-byte light slots sit between the
 * header and the time-of-day globals; each slot carries a sun and a
 * moon direction and colour plus the ambient colour. Only fields with
 * read/write evidence in sky.c are named; everything else is padded.
 */
typedef struct SkyBlendStateFlags {
    u8 unused80 : 1;
    u8 active : 1;
    u8 visibility : 1;
    u8 cloud : 2;
    u8 rest : 3;
} SkyBlendStateFlags;

typedef struct SkyFadeFlags {
    u8 fadePending : 1;
    u8 rest : 7;
} SkyFadeFlags;

typedef struct SkyLight {
    union {
        struct {
            f32 redCurve[7];
            f32 greenCurve[7];
            f32 blueCurve[7];
        };
        f32 curves[3][7];
    };
    u8 blendTargetR;
    u8 blendTargetG;
    u8 blendTargetB;
    u8 unk57;
    u8 sunColorR;
    u8 sunColorG;
    u8 sunColorB;
    u8 unk5B;
    u8 overrideSunColorR;
    u8 overrideSunColorG;
    u8 overrideSunColorB;
    u8 unk5F;
    u8 moonColorR;
    u8 moonColorG;
    u8 moonColorB;
    u8 unk63;
    u8 overrideMoonColorR;
    u8 overrideMoonColorG;
    u8 overrideMoonColorB;
    u8 unk67;
    u8 ambientR;
    u8 ambientG;
    u8 ambientB;
    u8 unk6B;
    u8 overrideAmbientR;
    u8 overrideAmbientG;
    u8 overrideAmbientB;
    u8 unk6F;
    f32 directionX;
    f32 directionY;
    f32 directionZ;
    f32 moonDirectionX;
    f32 moonDirectionY;
    f32 moonDirectionZ;
    f32 overrideDirectionX;
    f32 overrideDirectionY;
    f32 overrideDirectionZ;
    f32 blendRate;
    f32 blendFactor;
    f32 unk9C;
    u8 blendAlpha;
    SkyBlendStateFlags flags;
    u8 unkA2[2];
} SkyLight;

STATIC_ASSERT(sizeof(SkyLight) == 0xA4);
STATIC_ASSERT(offsetof(SkyLight, flags) == 0xA1);
STATIC_ASSERT(offsetof(SkyLight, blendTargetR) == 0x54);
STATIC_ASSERT(offsetof(SkyLight, overrideMoonColorR) == 0x64);
STATIC_ASSERT(offsetof(SkyLight, blendFactor) == 0x98);

typedef struct SkyState {
    u8 unk00;
    u8 unk01;
    u8 unk02[2];
    u8* handle;
    u8* texture0;
    u8 unk0C[4];
    u8* texture1;
    s32 textureId0;
    s32 textureId1;
    f32 sunYaw; /* 0x1C: yaw applied (as quaternion rz) to the sun direction each frame */
    SkyLight lights[3];
    f32 timeOfDay;
    s32 clockTime;
    f32 timeOfDayRate;
    s32 timer;
    s32 skyTextureIds[8]; /* 0x21C: texture asset ids (id + 0xc38 -> textureLoadAsset) */
    f32 fadeFactor;       /* 0x23C: sky transition fade, 1.0->0.0 over fadeRate, clamped [0,1] */
    f32 fadeRate;         /* 0x240: 1/duration; fadeFactor -= fadeRate * dt */
    f32 lightBlendFactor;
    f32 lightBlendRate;
    u8 currentLightIndex;
    u8 previousLightIndex;
    u8 transitionLatch;
    u8 unk24F;
    s8 unk250;
    u8 swapTexIndex; /* 0x251: slot index into the sky texture pointers swapped into texture1 (gSkyState + idx*4) */
    u8 unk252;
    u8 unk253;
    u8 unk254;
    SkyFadeFlags fadeFlags; /* 0x255: fadePending selects computed fadeRate over the instant flag */
    u8 unk256[2];
} SkyState;

STATIC_ASSERT(offsetof(SkyState, lights) == 0x20);
STATIC_ASSERT(offsetof(SkyState, timeOfDay) == 0x20C);
STATIC_ASSERT(offsetof(SkyState, unk250) == 0x250);
STATIC_ASSERT(sizeof(SkyState) == 0x258);

/* Per-map sky blend config record passed to sky2_update / skyUpdateEnvfxAct. */
typedef struct Sky2Config {
    u8 unk00[0xC];
    u8 redKeys[8];
    u8 greenKeys[8];
    u8 blueKeys[8];
    u16 envfxActId; /* 0x24: 1-based env effect action id; (id-1) passed to getEnvfxAct, 0 => disabled */
    u8 unk26[4];
    u16 fadeDurationA; /* 0x2A: clamped to >=1; state+0x3c=this, rate at +0x5c = k/this (per-frame fade increment) */
    u16 fadeDurationB; /* 0x2C: clamped to >=1; state+0x40=this, rate at +0x58/+0x60 = k/this */
    union {
        struct {
            u16 skyTexId0; /* sky texture id slot 0 (+0xc38); also staged to slot+8 */
            u16 skyTexId1; /* sky texture id slot 1 (+0xc38) */
            u16 skyTexId2; /* sky texture id slot 2 (+0xc38) */
            u16 skyTexId3; /* sky texture id slot 3 (+0xc38) */
            u8 unk36[8];
            u16 skyTexId4; /* sky texture id slot 4 (+0xc38) */
            u16 skyTexId5; /* sky texture id slot 5 (+0xc38) */
            u16 skyTexId6; /* sky texture id slot 6 (+0xc38) */
            u16 skyTexId7; /* sky texture id slot 7 (+0xc38) */
        };
        struct {
            u16 fogFarKeys[8];
            u16 fogNearKeys[8];
        };
    };
    u8 unk4E[0x6];
    u16 cloudMode;
    u16 visibility; /* 0x56: drives the sky blend-state bit20 visibility flag */
    u8 flags;
    u8 flags2;
    u8 unk5A[3];
    u8 cloudBlendMode; /* 0x5D: 0 disables cloud blend; else sets SkyBlendStateFlags.cloud = (v&1)+1; >2 also enables skySetSlotFlag80 */
    u8 unk5E[2];
} Sky2Config;

STATIC_ASSERT(offsetof(Sky2Config, fadeDurationA) == 0x2A);
STATIC_ASSERT(offsetof(Sky2Config, skyTexId0) == 0x2E);
STATIC_ASSERT(offsetof(Sky2Config, fogFarKeys) == 0x2E);
STATIC_ASSERT(offsetof(Sky2Config, fogNearKeys) == 0x3E);
STATIC_ASSERT(offsetof(Sky2Config, cloudMode) == 0x54);
STATIC_ASSERT(offsetof(Sky2Config, flags) == 0x58);

#endif
