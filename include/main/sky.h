#ifndef MAIN_SKY_H_
#define MAIN_SKY_H_

#include "global.h"
#include "main/sky_api.h"

typedef struct SkyBlendStateFlags
{
    u8 unused80 : 1;
    u8 active : 1;
    u8 bit20 : 1;
    u8 cloud : 2;
    u8 rest : 3;
} SkyBlendStateFlags;

typedef struct SkyVec3
{
    f32 x, y, z;
} SkyVec3;

typedef struct SkyRotQ
{
    s16 rx, ry, rz;
    f32 w;
    f32 x, y, z;
} SkyRotQ;

typedef struct Dll06InterpState
{
    u8 pad00[0x24];
    s32 targetX;
    s32 targetY;
    s32 targetZ;
    u8 pad30[0x2dc];
    f32 blend;
    u8 pad310[0x06];
    s8 active;
} Dll06InterpState;

typedef struct FogColor
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

typedef struct SkyBestIdx
{
    u8 best;
    u8 second;
    u8 pad;
} SkyBestIdx;

typedef struct SkySlotAnim
{
    u8 pad00[4];       /* 0x00 */
    u16 flags4;        /* 0x04 */
    u16 flags6;        /* 0x06 */
    u8 pad08[0x34];    /* 0x08 */
    int frameCount;    /* 0x3c */
    u8 pad40[0x30];    /* 0x40 */
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
} SkySlotAnim;

typedef struct SkyTimeBlend
{
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

int getEnvFxBit2BA(void);
void setGameBit2BA(int value);
void envFxFn_800887cc(void);
void fn_80088870(int a, int b, int c, int d);
void envFxFn_80088884(void);
void loadSunAndMoon(void);
int getSkyColorFn_80088e30(int slot);
int getSkyStructField24C(void);
void skyGetCurrentTextureColor(u8* red, u8* green, u8* blue);
void skyGetCurrentAmbientAndLightColors(u8* ambientRed, u8* ambientGreen, u8* ambientBlue, u8* lightRed, u8* lightGreen,
                                        u8* lightBlue);
void* fn_8008912C(void);
void skyBuildSunModelMatrix(f32 mtx[3][4]);
int skyFn_8008919c(int slot);
void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
void skySetOverrideLightColorEnabled(u8 enabled);
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
void skySetOverrideLightDirectionEnabled(u8 enabled);
void fn_80089510(int flags, u8 red, u8 green, u8 blue);
void fn_80089578(int flags, u8 red, u8 green, u8 blue);
void getTimeOfDay(f32* time);
void renderSky(void);
void getAmbientColor(int slot, u8* red, u8* green, u8* blue);
void textureColorFn_8008991c(int slot, u8* red, u8* green, u8* blue);
void modelTextureFn_80089970(int slot);
void* fn_80089A50(void);
void* fn_80089A58(void);
int getSunPos(f32* outTime);
void fn_8008B88C(int* outTimer);
void fn_800897D4(int slot, f32* x, f32* y, f32* z);
void objGetColor(int slot, u8* red, u8* green, u8* blue);
void dll_06_func0B(int* x, int* y);
void dll_06_func0A(int* a, int* b, int* c, f32* scale);
void dll_06_func0E(void);
void dll_06_func0D(void);
void sky2_initialise(void);
void fn_8008EDE8(f32* out);
int fn_8008B71C(int slot);
void skyTimeToDayHourMinute(f32 time, s16* days, s16* hours, s16* minutes);
void skyGetClockTime(f32* time);
int dll_06_func0F(void);
f32 fn_8008ED88(void);
int return0_80088758(void);
void doNothing_800887C4(void);
void doNothing_800887C8(void);
int return0_8008B7E8(void);
void doNothing_8008B8B0(void);
void pDll_Sky_setTimeOfDay_nop(void);
void dll_06_func0C_nop(void);
int dll_06_func07_ret_0(void);
void sky2_release(void);
void loadLightFn_8008bbc4(void);
void dll_06_func06(int obj);
void dll_06_func08(int obj);
void fn_8008DAE8(int obj);
void playerEnvFxFn_80088ad4(u8 idx);
void dll_06_func09(s32* x, s32* y, s32* z);
void sky2_run(void);
void sky2_onMapSetup(void);
void timeOfDayFn_8008b964(void);
void fn_8008923C(u8* obj, f32* x, f32* y, f32* z);
void skyFn_8008a500(void);
void sky2_update(int a, int b, u8* cfg);
void fn_8008C9F4(u8* cfg, u8 flags);
void fn_8008D088(int slot);
void fn_8008BDA8(void);
void skyFn_8008a04c(void);
void fn_80089A60(int slot, f32 x, f32 y, f32 z, int r, int g, int b, int a2, int b2, int c2);
void renderSunAndMoon(int a, int b, int c, int d, int visible);
void skyFn_8008aee8(void);
void Sky_func03(int a, int b, u8* cfg);

#endif /* MAIN_SKY_H_ */
