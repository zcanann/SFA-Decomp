#ifndef MAIN_DLL_WM_DLL_0210_WMPLANETS_H_
#define MAIN_DLL_WM_DLL_0210_WMPLANETS_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmPlanetsState
{
    s16 orbitYawStep; /* 0x00: orbit advance per frame, random 100..200 */
    s16 yawStep;      /* 0x02: model-spin rate, random 200..400 (timeDelta-scaled) */
    s16 orbitYaw;     /* 0x04: current orbit angle */
    s16 pad06;
    s16 orbitPitch; /* 0x08: orbit-plane tilt, random 0..2400, fixed at init */
    s16 pad0A;
    f32 orbitRadius; /* 0x0C: arm length spun around the base point (0 = spin in place) */
    f32 baseX;       /* 0x10: orbit centre = placement position */
    f32 baseY;       /* 0x14 */
    f32 baseZ;       /* 0x18 */
} WmPlanetsState;

/* argument record for vecRotateZXY (angles in, vector in/out) */
typedef struct WmPlanetsRotationWork
{
    s16 yaw;   /* 0x00 */
    s16 pitch; /* 0x02 */
    s16 roll;  /* 0x04 */
    s16 pad06;
    f32 scale; /* 0x08 */
    f32 zeroX; /* 0x0C */
    f32 zeroY; /* 0x10 */
    f32 zeroZ; /* 0x14 */
} WmPlanetsRotationWork;

typedef union WmPlanetsVector
{
    f32 f[3];
    u32 word[3];
} WmPlanetsVector;

typedef struct WmPlanetsMapData
{
    ObjPlacement base;
    s8 scaleByte;   /* 0x18: extra whole-model scale (scale *= 1 + byte) */
    s8 radiusByte;  /* 0x19: orbit radius in 16-unit steps (negated) */
    s16 modelIndex; /* 0x1A: model bank selector (Obj_SetActiveModelIndex) */
} WmPlanetsMapData;

STATIC_ASSERT(offsetof(WmPlanetsState, orbitRadius) == 0x0C);
STATIC_ASSERT(sizeof(WmPlanetsState) == 0x1C);
STATIC_ASSERT(offsetof(WmPlanetsMapData, scaleByte) == 0x18);
STATIC_ASSERT(offsetof(WmPlanetsMapData, radiusByte) == 0x19);
STATIC_ASSERT(offsetof(WmPlanetsMapData, modelIndex) == 0x1A);
STATIC_ASSERT(sizeof(WmPlanetsMapData) == 0x1C);

extern f32 lbl_803E5F98;
extern f32 lbl_803E5F9C;
extern f32 lbl_803E5FA0;

int WM_Planets_getExtraSize(void);
int WM_Planets_getObjectTypeId(void);
void WM_Planets_free(void);
void WM_Planets_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void WM_Planets_hitDetect(void);
void WM_Planets_update(GameObject* obj);
void WM_Planets_init(GameObject* obj, WmPlanetsMapData* mapData);
void WM_Planets_release(void);
void WM_Planets_initialise(void);

#endif /* MAIN_DLL_WM_DLL_0210_WMPLANETS_H_ */
