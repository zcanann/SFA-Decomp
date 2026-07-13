#ifndef MAIN_DLL_OBJFX_H_
#define MAIN_DLL_OBJFX_H_

#include "global.h"
#include "main/dll/objfx_api.h"
#include "main/game_object.h"
#include "main/objfx.h"

typedef struct ObjFxParticleEmitter
{
    u16 h18;
    u16 h1a;
    u16 h1c;
    u16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjFxParticleEmitter;

typedef struct ObjFxS32Table5
{
    s32 values[5];
} ObjFxS32Table5;

typedef struct ObjFxU16Table11
{
    u16 values[11];
} ObjFxU16Table11;

typedef struct ObjFxParticleParams
{
    s16 pad00[3];
    s16 effectParam;
    f32 scale;
    f32 position[3];
} ObjFxParticleParams;

typedef struct ObjFxU16Table7
{
    u16 values[7];
} ObjFxU16Table7;

typedef struct ObjFxParticleFlags
{
    s16 a;
    s16 b;
    s16 f4;
    s16 effectParam;
    f32 scale;
} ObjFxParticleFlags;

typedef struct ObjFxU16Table9
{
    u16 values[9];
} ObjFxU16Table9;

typedef struct ObjFxU16Table8
{
    u16 values[8];
} ObjFxU16Table8;

typedef struct ObjFxRandomBurstEntry
{
    u16 effectParam;
    u16 extraParam;
} ObjFxRandomBurstEntry;

typedef struct ObjFxRandomBurstTable
{
    ObjFxRandomBurstEntry entries[13];
} ObjFxRandomBurstTable;

typedef struct ObjFxColorTable
{
    u16 values[15];
} ObjFxColorTable;

STATIC_ASSERT(sizeof(ObjFxParticleEmitter) == 0x18);
STATIC_ASSERT(sizeof(ObjFxS32Table5) == 0x14);
STATIC_ASSERT(sizeof(ObjFxU16Table11) == 0x16);
STATIC_ASSERT(sizeof(ObjFxParticleParams) == 0x18);
STATIC_ASSERT(offsetof(ObjFxParticleParams, effectParam) == 0x06);
STATIC_ASSERT(offsetof(ObjFxParticleParams, scale) == 0x08);
STATIC_ASSERT(offsetof(ObjFxParticleParams, position) == 0x0C);
STATIC_ASSERT(sizeof(ObjFxU16Table7) == 0x0E);
STATIC_ASSERT(sizeof(ObjFxParticleFlags) == 0x0C);
STATIC_ASSERT(sizeof(ObjFxU16Table9) == 0x12);
STATIC_ASSERT(sizeof(ObjFxU16Table8) == 0x10);
STATIC_ASSERT(sizeof(ObjFxRandomBurstTable) == 0x34);
STATIC_ASSERT(sizeof(ObjFxColorTable) == 0x1E);

extern ObjFxS32Table5 lbl_802C1FF8;
extern ObjFxS32Table5 lbl_802C200C;
extern ObjFxU16Table11 lbl_802C20EC;
extern ObjFxU16Table7 lbl_802C2104;
extern ObjFxU16Table11 lbl_802C2114;
extern ObjFxRandomBurstTable gObjFxRandomBurstTbl;
extern u8 gObjFxCrystalSparkleTbl[];
extern f32 gObjFxCrystalAmpTbl[];
extern s16 gObjFxCrystalSpinSpeed[4];
extern u8 gObjFxLightColorTbl[];

extern s32 lbl_803DF340;
extern u16 lbl_803DF344;
extern const f32 lbl_803DF350;
extern const f32 lbl_803DF354;
extern const f32 lbl_803DF358;
extern const f32 lbl_803DF35C;
extern f32 lbl_803DF368;
extern f32 gObjFxPi;
extern f32 lbl_803DF370;
extern f32 lbl_803DF380;
extern f32 lbl_803DF384;
extern f32 lbl_803DF388;
extern f32 lbl_803DF38C;
extern f32 lbl_803DF390;
extern f32 lbl_803DF394;
extern f32 lbl_803DF398;
extern f32 lbl_803DF39C;
extern f32 lbl_803DF3A0;
extern f32 lbl_803DF3A4;
extern f32 lbl_803DF3A8;
extern f32 lbl_803DF3AC;
extern f32 lbl_803DF3B0;

void objShowButtonGlow(void* obj, u8 mode, f32 intensity);
void objfx_spawnFlaggedTrailBurst(void* obj, u8 mode, int p5, int p6, int p7, f32 fval);

#endif /* MAIN_DLL_OBJFX_H_ */
