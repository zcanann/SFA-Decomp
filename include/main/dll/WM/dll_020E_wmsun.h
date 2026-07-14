#ifndef MAIN_DLL_WM_DLL_020E_WMSUN_H_
#define MAIN_DLL_WM_DLL_020E_WMSUN_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

#define WM_SUN_GLARE_COUNT 20

typedef struct WmSunGlareParams
{
    s16 unk00[WM_SUN_GLARE_COUNT];         /* 0x00: never written */
    s16 angleOffsets[WM_SUN_GLARE_COUNT];  /* 0x28: cleared at init */
    s16 flickerTimers[WM_SUN_GLARE_COUNT]; /* 0x50: random 10..20 */
    s16 alphaValues[WM_SUN_GLARE_COUNT];   /* 0x78: random 0x50..0xFF */
} WmSunGlareParams;

typedef struct WmSunMapData
{
    ObjPlacement base;
    s8 rotXByte;  /* 0x18: rotX in 1/256 turns */
    u8 bankIndex; /* 0x19: sun layer / model bank (0..2) */
    s16 unused1A;
    s16 rootMotionScaleParam; /* 0x1C: model scale * 1000 */
    u8 pad1E[2];
} WmSunMapData;

typedef struct WmSunState
{
    s16 pad00;
    s16 riseStep; /* 0x02: crystal rise progress / rotX advance per frame */
    s16 spinStep; /* 0x04: sun rotZ advance per frame */
    u8 pad06[2];
    WmSunGlareParams* glareParams; /* 0x08: 0x2C2 variant only, else NULL */
    u8 pad0C;
    u8 renderEnabled; /* 0x0D: cleared to hide and free the crystal */
    u8 pad0E[2];
} WmSunState;

typedef struct WmSunVec3
{
    f32 x;
    f32 y;
    f32 z;
} WmSunVec3;

typedef struct WmSunGlare
{
    s16 ang[3]; /* only member consumed after the work record is filled */
    f32 intensity;
    f32 vx;
    f32 vy;
    f32 vz;
} WmSunGlare;

STATIC_ASSERT(offsetof(WmSunGlareParams, angleOffsets) == 0x28);
STATIC_ASSERT(offsetof(WmSunGlareParams, flickerTimers) == 0x50);
STATIC_ASSERT(offsetof(WmSunGlareParams, alphaValues) == 0x78);
STATIC_ASSERT(sizeof(WmSunGlareParams) == 0xA0);
STATIC_ASSERT(offsetof(WmSunMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSunMapData, bankIndex) == 0x19);
STATIC_ASSERT(offsetof(WmSunMapData, rootMotionScaleParam) == 0x1C);
STATIC_ASSERT(sizeof(WmSunMapData) == 0x20);
STATIC_ASSERT(offsetof(WmSunState, riseStep) == 0x02);
STATIC_ASSERT(offsetof(WmSunState, spinStep) == 0x04);
STATIC_ASSERT(offsetof(WmSunState, glareParams) == 0x08);
STATIC_ASSERT(offsetof(WmSunState, renderEnabled) == 0x0D);
STATIC_ASSERT(sizeof(WmSunState) == 0x10);

extern s16 gWmSunQuakeTimer; /* finale countdowns */
extern s16 lbl_803DDCAA;
extern s16 lbl_803DDCAC;
extern s16 lbl_803DDCAE;
extern s16 gWmSunEnvfxTimer;
extern f32 lbl_803E5F20;
extern f32 lbl_803E5F24;
extern f32 lbl_803E5F28;
extern f32 lbl_803E5F2C;
extern f32 gWmSunPi;
extern f32 lbl_803E5F34;
extern f32 lbl_803E5F38;
extern f32 lbl_803E5F3C;
extern f32 lbl_803E5F40;
extern f32 lbl_803E5F44;
extern f32 lbl_803E5F48;
extern f32 lbl_803E5F4C;
extern f32 lbl_803E5F50;
extern f32 lbl_803E5F54;
extern f32 lbl_803E5F58;
extern f32 lbl_803E5F5C;
extern f32 lbl_803E5F60;
extern f32 lbl_803E5F64;
extern f32 lbl_803E5F68;
extern f32 lbl_803E5F6C;
extern f32 lbl_803E5F78; /* 0.00375f */
extern f32 lbl_803E5F7C; /* 50.0f */
extern f32 lbl_803E5F80; /* 0.8f */
extern f32 lbl_803E5F84; /* 2400.0f */
extern f32 lbl_803E5F88; /* 2.8f */
extern f32 lbl_803E5F8C; /* 1000.0f */
extern WmSunVec3 gWmSunGlareDir;
extern WmSunVec3 gWmSunGlareSun;
extern f32 gWmSunGlareIntensity;
extern f32 gWmSunGlareDamping;

int wmsun_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* actor);
void wmsun_updateGlare(GameObject* obj);
int wmsun_getExtraSize(void);
int wmsun_getObjectTypeId(void);
void wmsun_free(GameObject* obj);
void wmsun_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wmsun_hitDetect(void);
void wmsun_update(GameObject* obj);
void wmsun_init(GameObject* obj, WmSunMapData* mapData);
void wmsun_release(void);
void wmsun_initialise(void);

#endif /* MAIN_DLL_WM_DLL_020E_WMSUN_H_ */
