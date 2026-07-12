#ifndef MAIN_DLL_DLL_02B3_VORTEX_H
#define MAIN_DLL_DLL_02B3_VORTEX_H

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct VortexFlags
{
    u8 active : 1;
    u8 pad : 7;
} VortexFlags;

typedef struct VortexState
{
    f32 alpha;
    f32 particleTimer;
    f32 alphaScale[3];
    f32 radiusScale[3];
    s16 angles[3];
    VortexFlags flags;
    u8 pad27;
} VortexState;

typedef struct VortexSetup
{
    ObjPlacement base;
    u8 pad18[2];
    s16 radiusParam;
    s16 reverseTextureScroll;
    s16 invertGameBit;
    s16 activeGameBit;
    u8 pad22[0x24 - 0x22];
} VortexSetup;

STATIC_ASSERT(sizeof(VortexState) == 0x28);
STATIC_ASSERT(offsetof(VortexState, alphaScale) == 0x08);
STATIC_ASSERT(offsetof(VortexState, radiusScale) == 0x14);
STATIC_ASSERT(offsetof(VortexState, angles) == 0x20);
STATIC_ASSERT(offsetof(VortexState, flags) == 0x26);
STATIC_ASSERT(sizeof(VortexSetup) == 0x24);
STATIC_ASSERT(offsetof(VortexSetup, radiusParam) == 0x1a);
STATIC_ASSERT(offsetof(VortexSetup, reverseTextureScroll) == 0x1c);
STATIC_ASSERT(offsetof(VortexSetup, invertGameBit) == 0x1e);
STATIC_ASSERT(offsetof(VortexSetup, activeGameBit) == 0x20);

extern f32 lbl_803E73E0;
extern const f32 lbl_803E73D0;
extern f32 lbl_803E73D4;
extern f32 lbl_803E73D8;
extern const f32 gVortexRadiusParamScale;
extern f32 lbl_803E73E4;
extern const f32 lbl_803E73E8;
extern const f32 lbl_803E73EC;
extern double lbl_803E73F0;
extern double lbl_803E73F8;
extern f32 gVortexAlphaFadeSpeed;
extern s16 gVortexAngleSpeed83D[4];
extern s16 gVortexAngleSpeedDefault[4];
extern s16 gVortexAngleSpeed835[2];
extern s16 gVortexRotZTable[2];
extern f32 gVortexScaleParams[4][3];
extern f32 gVortexRadiusScaleInit[2];
extern f32 gVortexAlphaScaleInit835[2];
extern f32 gVortexAlphaScaleInit838[2];
extern f32 lbl_803E7404;

int Vortex_getExtraSize(void);
int Vortex_getObjectTypeId(void);
void Vortex_free(GameObject* obj);
void Vortex_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Vortex_hitDetect(void);
void Vortex_init(int obj, int initData);
void Vortex_update(GameObject* obj);
void Vortex_release(void);
void Vortex_initialise(void);

#endif
