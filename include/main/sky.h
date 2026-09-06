#ifndef MAIN_SKY_H_
#define MAIN_SKY_H_

#include "global.h"
#include "dolphin/gx/GXStruct.h"
#include "dolphin/mtx/vec_types.h"
#include "main/sky_api.h"

typedef struct Texture Texture;

typedef struct SkyRotQ {
    s16 rx, ry, rz;
    f32 w;
    f32 x, y, z;
} SkyRotQ;

typedef struct SkyBestIdx {
    u8 best;
    u8 second;
    u8 pad;
} SkyBestIdx;

typedef struct SkySlotAnim {
    s32 unk00;         /* 0x00 */
    u16 flags4;        /* 0x04 */
    u16 flags6;        /* 0x06 */
    s32 unk08;         /* 0x08 */
    s32 unk0C;         /* 0x0c */
    u8 pad10[4];       /* 0x10 */
    f32 fogNear;       /* 0x14 */
    f32 fogFar;        /* 0x18 */
    f32 fogNear2;      /* 0x1c */
    f32 fogFar2;       /* 0x20 */
    s32 colorR;        /* 0x24 */
    s32 colorG;        /* 0x28 */
    s32 colorB;        /* 0x2c */
    s32 colorR2;       /* 0x30 */
    s32 colorG2;       /* 0x34 */
    s32 colorB2;       /* 0x38 */
    int fadeDurationA; /* 0x3c */
    s32 fadeDurationB; /* 0x40 */
    s32 unk44;         /* 0x44 */
    s32 unk48;         /* 0x48 */
    u8 pad4C[0xC];     /* 0x4c */
    f32 fadeRate;      /* 0x58 */
    f32 unk5C;         /* 0x5c */
    f32 unk60;         /* 0x60 */
    f32 wobbleStep;    /* 0x64 */
    f32 wobbleAmp;     /* 0x68 */
    f32 wobbleOffset;  /* 0x6c */
    f32 cur[0x21];     /* 0x70 */
    f32 target[0x21];  /* 0xf4 */
    f32 vel[0x21];     /* 0x178 */
    f32 cur2[0x16];    /* 0x1fc */
    f32 target2[0x16]; /* 0x254 */
    f32 vel2[0x16];    /* 0x2ac */
    f32 t;             /* 0x304 */
    f32 step;          /* 0x308 */
    f32 prevT;         /* 0x30c */
    f32 blend;         /* 0x310 */
    s8 b314;           /* 0x314 */
    s8 b315;           /* 0x315 */
    s8 b316;           /* 0x316 */
    s8 b317;           /* 0x317 */
} SkySlotAnim;

STATIC_ASSERT(offsetof(SkySlotAnim, fogNear) == 0x14);
STATIC_ASSERT(offsetof(SkySlotAnim, colorR) == 0x24);
STATIC_ASSERT(offsetof(SkySlotAnim, wobbleOffset) == 0x6C);
STATIC_ASSERT(offsetof(SkySlotAnim, cur) == 0x70);
STATIC_ASSERT(offsetof(SkySlotAnim, cur2) == 0x1FC);
STATIC_ASSERT(sizeof(SkySlotAnim) == 0x318);

typedef struct SkyTimeBlend {
    void* texA;       /* 0x00 */
    void* texB;       /* 0x04 */
    void* texList[3]; /* 0x08 */
    int texAId;       /* 0x14 */
    int texBId;       /* 0x18 */
    u8 pad1C[0x1F0];  /* 0x1c */
    f32 time;         /* 0x20c */
    u8 pad210[0xC];   /* 0x210 */
    int palettes[8];  /* 0x21c */
    f32 blend;        /* 0x23c */
    u8 pad240[0xF];   /* 0x240 */
    u8 phase;         /* 0x24f */
    s8 prevPhase;     /* 0x250 */
    u8 texSel;        /* 0x251 */
} SkyTimeBlend;

typedef struct SkyEnvFxRampTables {
    s16 groupA[28];
    s16 groupB[28];
    s16 groupC[28];
    s16 groupD[28];
} SkyEnvFxRampTables;

STATIC_ASSERT(offsetof(SkyEnvFxRampTables, groupA) == 0x00);
STATIC_ASSERT(offsetof(SkyEnvFxRampTables, groupB) == 0x38);
STATIC_ASSERT(offsetof(SkyEnvFxRampTables, groupC) == 0x70);
STATIC_ASSERT(offsetof(SkyEnvFxRampTables, groupD) == 0xA8);
STATIC_ASSERT(sizeof(SkyEnvFxRampTables) == 0xE0);

int skyGetDayNo(void);
void skySetDayNo(int value);
void skyRefreshPlayerEnvFx(void);
void skySetEnvFxRampTables(void* groupB, void* groupA, void* groupC, void* groupD);
void skyUpdateEnvFx(void);
void loadSunAndMoon(void);
int skyGetSlotBlendAlpha(int slot);
int skyGetCurrentLightIndex(void);
void skyGetCurrentTextureColor(u8* red, u8* green, u8* blue);
void skyGetCurrentAmbientAndLightColors(u8* ambientRed, u8* ambientGreen, u8* ambientBlue, u8* lightRed, u8* lightGreen,
                                        u8* lightBlue);
Texture* skyGetSkyTexture(void);
void skyBuildSunModelMatrix(f32 mtx[3][4]);
u8 skyGetSunRenderAlpha(int slot);
void getTimeOfDay(f32* time);
void renderSky(int a, int b, int c, int d, int visible);
void skyGetSunColor(int slot, u8* red, u8* green, u8* blue);
int getSunPos(f32* outTime);
void skyGetTimer(int* outTimer);
void skyGetSunLightDirection(int slot, f32* x, f32* y, f32* z);
void sky2GetFogRange(int* fogNear, int* fogFar);
void sky2GetTargetColor(int* red, int* green, int* blue, f32* blend);
void sky2SetDrawMode1(void);
void sky2SetDrawMode2(void);
void sky2_initialise(void);
void lightningGetStartPos(Vec* out);
int skyGetVisibility(int slot);
void skyTimeToDayHourMinute(f32 time, s16* days, s16* hours, s16* minutes);
void skyGetClockTime(f32* time);
int sky2GetFogFadeAlpha(void);
int skyReservedReturnZeroB(void);
void skyReservedNopC(void);
void skyReservedNopB(void);
int skyReservedReturnZeroA(void);
void skyReservedNopA(void);
void pDll_Sky_setTimeOfDay_nop(void);
void dll_06_func0C_nop(void);
int dll_06_func07_ret_0(void);
void sky2_release(void);
void skyLoadLights(void);
void sky2ApplyFog(int obj);
void sky2ApplyTextColor(void* context);
void sky2ApplyModelTint(GameObject* obj);
void skyApplyPlayerEnvFx(u8 idx);
void sky2BlendTowardTargetColor(s32* red, s32* green, s32* blue);
void sky2_run(void);
void sky2_onMapSetup(void);
void skyUpdateTimeOfDay(void);
void skyUpdateShadowLightDirection(void);
void sky2_update(int a, int b, u8* cfg);
void sky2ResetStateFromConfig(u8* cfg, u8 flags);
void sky2StepSlotAnim(int slot);
void skyResetState(void);
void skyUpdateLightingFromTimeOfDay(void);
void skySetLightSlot(int slot, f32 x, f32 y, f32 z, int red, int green, int blue, int moonIntensity,
                     int ambientIntensity, u8 blendAlpha);
void renderSunAndMoon(int a, int b, int c, int d, int visible);
void skyRenderTimeOfDayBackdrop(void);
void skyUpdateEnvfxAct(int a, int b, u8* cfg);

#endif /* MAIN_SKY_H_ */
