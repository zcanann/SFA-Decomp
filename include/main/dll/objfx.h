#ifndef MAIN_DLL_OBJFX_H_
#define MAIN_DLL_OBJFX_H_

#include "global.h"
#include "main/dll/objfx_api.h"
#include "game/objects/object.h"
#include "main/objfx.h"

typedef struct ObjFxParticleEmitter
{
    u16 rotX;
    u16 rotY;
    u16 rotZ;
    u16 effectParam;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjFxParticleEmitter;

typedef struct ObjFxS32Table5
{
    s32 values[5];
} ObjFxS32Table5;

typedef struct ObjFxU16Table3
{
    u16 values[3];
} ObjFxU16Table3;

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

typedef struct ObjFxSparkleEffectTable
{
    ObjFxS32Table5 counts;
    u16 records[3][34];
} ObjFxSparkleEffectTable;

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
STATIC_ASSERT(sizeof(ObjFxSparkleEffectTable) == 0xE0);

extern const ObjFxS32Table5 gObjFxPulseVariantTbl;
extern const ObjFxSparkleEffectTable gObjFxHitPulseTbl;
extern const ObjFxU16Table11 gObjFxHitEffectParamTbl;
extern const ObjFxU16Table7 gObjFxMaskedHitSpawnIdTbl;
extern const ObjFxU16Table11 gObjFxHitEffectParamTbl2;
extern const ObjFxRandomBurstTable gObjFxRandomBurstTbl;
extern const ObjFxColorTable gObjFxCrystalSparkleTbl;
extern f32 gObjFxCrystalAmplitudes[4];
extern s16 gObjFxCrystalSpinSpeed[4];
typedef struct ObjFxLightColor {
    u8 r;
    u8 g;
    u8 b;
} ObjFxLightColor;

extern ObjFxLightColor gObjFxLightColorTbl[];


void objShowButtonGlow(void* obj, f32 intensity, u8 mode);
void objfx_spawnFlaggedTrailBurst(void* obj, f32 fval, u8 mode, int f6val, int f4val, void* origin);

#endif /* MAIN_DLL_OBJFX_H_ */
