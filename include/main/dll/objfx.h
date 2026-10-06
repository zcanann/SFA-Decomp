#ifndef MAIN_DLL_OBJFX_H_
#define MAIN_DLL_OBJFX_H_

#include "global.h"
#include "main/dll/objfx_api.h"
#include "game/objects/object.h"
#include "main/objfx.h"

typedef struct ObjFxS32Table5 {
    s32 values[5];
} ObjFxS32Table5;

typedef struct ObjFxU16Table3 {
    u16 values[3];
} ObjFxU16Table3;

typedef struct ObjFxU16Table11 {
    u16 values[11];
} ObjFxU16Table11;

typedef struct ObjFxU16Table7 {
    u16 values[7];
} ObjFxU16Table7;

typedef struct ObjFxU16Table9 {
    u16 values[9];
} ObjFxU16Table9;

typedef struct ObjFxU16Table8 {
    u16 values[8];
} ObjFxU16Table8;

typedef struct ObjFxRandomBurstEntry {
    u16 effectParam;
    u16 extraParam;
} ObjFxRandomBurstEntry;

typedef struct ObjFxRandomBurstTable {
    ObjFxRandomBurstEntry entries[13];
} ObjFxRandomBurstTable;

typedef struct ObjFxLightColor {
    u8 r;
    u8 g;
    u8 b;
} ObjFxLightColor;

typedef struct ObjFxLightColorTable {
    ObjFxLightColor values[10];
} ObjFxLightColorTable;

STATIC_ASSERT(sizeof(ObjFxS32Table5) == 0x14);
STATIC_ASSERT(sizeof(ObjFxU16Table11) == 0x16);
STATIC_ASSERT(sizeof(ObjFxU16Table7) == 0x0E);
STATIC_ASSERT(sizeof(ObjFxU16Table9) == 0x12);
STATIC_ASSERT(sizeof(ObjFxU16Table8) == 0x10);
STATIC_ASSERT(sizeof(ObjFxRandomBurstTable) == 0x34);
STATIC_ASSERT(sizeof(ObjFxLightColor) == 3);
STATIC_ASSERT(sizeof(ObjFxLightColorTable) == 0x1E);
extern const ObjFxS32Table5 gObjFxPulseVariantTbl;
extern const ObjFxS32Table5 gObjFxHitPulseCounts;
extern const ObjFxU16Table11 gObjFxHitEffectParamTbl;
extern const ObjFxU16Table7 gObjFxMaskedHitSpawnIdTbl;
extern const ObjFxU16Table11 gObjFxHitEffectParamTbl2;
extern const ObjFxRandomBurstTable gObjFxRandomBurstTbl;
extern const ObjFxLightColorTable gObjFxParticleLightColors;
extern f32 gObjFxCrystalAmplitudes[4];
extern s16 gObjFxCrystalSpinSpeed[4];
extern ObjFxLightColor gObjFxLightColorTbl[];

void objShowButtonGlow(GameObject* obj, f32 intensity, u8 mode);
void objfx_spawnFlaggedTrailBurst(GameObject* obj, f32 scale, u8 mode, int textureId, int lifetimeFrames, f32* velocity);

#endif /* MAIN_DLL_OBJFX_H_ */
