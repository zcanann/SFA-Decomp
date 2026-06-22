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
    f32 unk7C;
    f32 unk80;
    f32 unk84;
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
    f32 unk1C;
    SkyLight lights[3];
    f32 timeOfDay;
    s32 clockTime;
    f32 timeOfDayRate;
    s32 timer;
    s32 skyTextureIds[8]; /* 0x21C: texture asset ids (id + 0xc38 -> textureLoadAsset) */
    f32 unk23C;
    f32 unk240;
    f32 lightBlendFactor;
    f32 lightBlendRate;
    u8 currentLightIndex;
    u8 previousLightIndex;
    u8 transitionLatch;
    u8 unk24F;
    s8 unk250;
    u8 unk251;
    u8 unk252;
    u8 unk253;
    u8 unk254;
    s8 unk255;
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
    u16 unk2E;
    u16 unk30;
    u16 unk32;
    u16 unk34;
    u8 unk36[8];
    u16 unk3E;
    u16 unk40;
    u16 unk42;
    u16 unk44;
    u8 unk46[0xE];
    u16 cloudMode;
    u16 unk56;
    u8 flags;
    u8 flags2;
    u8 unk5A[3];
    u8 unk5D;
    u8 unk5E[2];
} Sky2Config;

STATIC_ASSERT(offsetof(Sky2Config, unk2A) == 0x2A);
STATIC_ASSERT(offsetof(Sky2Config, flags) == 0x58);

int getSkyStructField24C(void);
void getAmbientColor(int slot, u8 *red, u8 *green, u8 *blue);
void fn_800897D4(int slot, f32 *x, f32 *y, f32 *z);

#endif
