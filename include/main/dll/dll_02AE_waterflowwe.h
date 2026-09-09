#ifndef MAIN_DLL_DLL_02AE_WATERFLOWWE_H
#define MAIN_DLL_DLL_02AE_WATERFLOWWE_H

#include "global.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

typedef struct WaterFlowWeState
{
    f32 currentX;
    f32 currentZ;
} WaterFlowWeState;

typedef struct WaterFlowWeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[3];
    u8 phaseDriverDisabled;
} WaterFlowWeSetup;

typedef struct ObjectCurrentSourceSetup
{
    ObjPlacement base;
    u8 pad18[0x29 - 0x18];
    u8 radiusCells;
    u8 pad2A[0x32 - 0x2A];
    u8 strengthTenths;
} ObjectCurrentSourceSetup;

STATIC_ASSERT(sizeof(WaterFlowWeState) == 0x8);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, phaseDriverDisabled) == 0x1f);
STATIC_ASSERT(sizeof(WaterFlowWeSetup) == 0x20);
STATIC_ASSERT(offsetof(ObjectCurrentSourceSetup, radiusCells) == 0x29);
STATIC_ASSERT(offsetof(ObjectCurrentSourceSetup, strengthTenths) == 0x32);

extern GameObject* gWaterFlowPhaseDriver;
extern f32 gWaterFlowIdlePhase;
extern f32 gWaterFlowFlowPhase;

void waterflowwe_calcCurrentVector(GameObject* obj, f32* currentX, f32* currentZ);
int waterflowwe_getExtraSize(void);
int waterflowwe_getObjectTypeId(void);
void waterflowwe_init(GameObject* obj, WaterFlowWeSetup* setup);
void waterflowwe_free(GameObject* obj);
void waterflowwe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void waterflowwe_hitDetect(void);
void waterflowwe_update(GameObject* obj);
void waterflowwe_release(void);
void waterflowwe_initialise(void);

#endif
