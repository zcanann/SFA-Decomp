#ifndef MAIN_SKY_STATE_H_
#define MAIN_SKY_STATE_H_

#include "global.h"

/*
 * SkyState - the global sky/time-of-day state block pointed to by
 * gSkyState (sky.c). Three 0xA4-byte light slots (sun/moon/...) sit
 * between the header and the time-of-day globals. Only fields with
 * read/write evidence in sky.c are named; everything else is padded.
 */
typedef struct SkyLight {
    u8 unk00[0x64];
    u8 unk64;
    u8 unk65[7];
    u8 unk6C;
    u8 unk6D;
    u8 unk6E;
    u8 unk6F;
    f32 directionX;
    f32 directionY;
    f32 directionZ;
    f32 moonDirectionX;
    f32 moonDirectionY;
    f32 moonDirectionZ;
    u8 unk88[0x14];
    f32 unk9C;
    u8 unkA0[4];
} SkyLight;

STATIC_ASSERT(sizeof(SkyLight) == 0xA4);

typedef struct SkyState {
    u8 unk00;
    u8 unk01;
    u8 unk02[2];
    u8 *handle;
    u8 *texture0;
    u8 unk0C[4];
    u8 *texture1;
    s32 textureId0;
    s32 textureId1;
    f32 sunYaw; /* 0x1C: yaw applied (as quaternion rz) to the sun direction each frame */
    SkyLight lights[3];
    f32 timeOfDay;
    s32 clockTime;
    f32 timeOfDayRate;
    s32 timer;
    s32 skyTextureIds[8]; /* 0x21C: texture asset ids (id + 0xc38 -> textureLoadAsset) */
    f32 fadeFactor; /* 0x23C: sky transition fade, 1.0->0.0 over fadeRate, clamped [0,1] */
    f32 fadeRate;   /* 0x240: 1/duration; fadeFactor -= fadeRate * dt */
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
    s8 flags255; /* 0x255: sky-fade flags byte; bit7 selects computed fadeRate vs instant flag */
    u8 unk256[2];
} SkyState;

STATIC_ASSERT(offsetof(SkyState, lights) == 0x20);
STATIC_ASSERT(offsetof(SkyState, timeOfDay) == 0x20C);
STATIC_ASSERT(offsetof(SkyState, unk250) == 0x250);

/* Per-map sky blend config record passed to sky2_update / Sky_func03. */
typedef struct Sky2Config {
    u8 unk00[0xC];
    u8 lightColorR;
    u8 lightColorG;
    u8 lightColorB;
    u8 lightColorA;
    u8 unk10[4];
    u8 color2R;
    u8 color2G;
    u8 color2B;
    u8 color2A;
    u8 unk18[4];
    u8 color3R;
    u8 color3G;
    u8 color3B;
    u8 color3A;
    u8 unk20[4];
    u16 unk24;
    u8 unk26[4];
    u16 unk2A;
    u16 unk2C;
    u16 skyTexId0;   /* sky texture id slot 0 (+0xc38); also staged to slot+8 */
    u16 skyTexId1;   /* sky texture id slot 1 (+0xc38) */
    u16 skyTexId2;   /* sky texture id slot 2 (+0xc38) */
    u16 skyTexId3;   /* sky texture id slot 3 (+0xc38) */
    u8 unk36[8];
    u16 skyTexId4;   /* sky texture id slot 4 (+0xc38) */
    u16 skyTexId5;   /* sky texture id slot 5 (+0xc38) */
    u16 skyTexId6;   /* sky texture id slot 6 (+0xc38) */
    u16 skyTexId7;   /* sky texture id slot 7 (+0xc38) */
    u8 unk46[0xE];
    u16 cloudMode;
    u16 visibility;  /* 0x56: drives the sky blend-state bit20 visibility flag */
    u8 flags;
    u8 flags2;
    u8 unk5A[3];
    u8 cloudBlendMode; /* 0x5D: 0 disables cloud blend; else sets SkyBlendStateFlags.cloud = (v&1)+1; >2 also enables skyFn_80088c94 */
    u8 unk5E[2];
} Sky2Config;

STATIC_ASSERT(offsetof(Sky2Config, unk2A) == 0x2A);
STATIC_ASSERT(offsetof(Sky2Config, flags) == 0x58);

int getSkyStructField24C(void);
void getAmbientColor(int slot, u8 *red, u8 *green, u8 *blue);
void fn_800897D4(int slot, f32 *x, f32 *y, f32 *z);

#endif
