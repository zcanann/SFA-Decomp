#ifndef MAIN_SKY_STATE_H_
#define MAIN_SKY_STATE_H_

#include "global.h"

/*
 * SkyState - the global sky/time-of-day state block pointed to by
 * lbl_803DD12C (sky.c). Three 0xA4-byte light slots (sun/moon/...) sit
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
    f32 unk70;
    f32 unk74;
    f32 unk78;
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
    u8 *unk04;
    u8 *unk08;
    u8 unk0C[4];
    u8 *unk10;
    s32 unk14;
    s32 unk18;
    f32 unk1C;
    SkyLight lights[3];
    f32 timeOfDay;
    s32 clockTime;
    f32 unk214;
    s32 unk218;
    s32 unk21C;
    s32 unk220;
    s32 unk224;
    s32 unk228;
    s32 unk22C;
    s32 unk230;
    s32 unk234;
    s32 unk238;
    f32 unk23C;
    f32 unk240;
    f32 unk244;
    f32 unk248;
    u8 unk24C;
    u8 unk24D;
    u8 unk24E;
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
    u8 unk0C;
    u8 unk0D;
    u8 unk0E;
    u8 unk0F;
    u8 unk10[4];
    u8 unk14;
    u8 unk15;
    u8 unk16;
    u8 unk17;
    u8 unk18[4];
    u8 unk1C;
    u8 unk1D;
    u8 unk1E;
    u8 unk1F;
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
    u16 unk54;
    u16 unk56;
    u8 unk58;
    u8 unk59;
    u8 unk5A[3];
    u8 unk5D;
    u8 unk5E[2];
} Sky2Config;

STATIC_ASSERT(offsetof(Sky2Config, unk2A) == 0x2A);
STATIC_ASSERT(offsetof(Sky2Config, unk58) == 0x58);

#endif
