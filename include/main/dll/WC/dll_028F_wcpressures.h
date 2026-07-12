#ifndef MAIN_DLL_WC_DLL_028F_WCPRESSURES_H
#define MAIN_DLL_WC_DLL_028F_WCPRESSURES_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

#define WCPRESSURES_TRACKED_COUNT 10

typedef struct WCPressuresSetup
{
    union
    {
        ObjPlacement base;
        struct
        {
            u8 pad00[8];
            f32 x;
            f32 y;
            f32 z;
            u8 pad14[4];
        };
    };
    u8 objectTypeHi;
    u8 modelIndex;
    s16 solvedBit;
    u8 pressDepth;
    u8 triggerHeight;
    u8 pad1E[2];
    s16 activateBit;
} WCPressuresSetup;

typedef struct WCPressuresSavedPos
{
    f32 x;
    f32 z;
} WCPressuresSavedPos;

typedef struct WCPressuresState
{
    s8 pressTimer;
    s8 mode;
    u8 pad02[2];
    GameObject* objects[WCPRESSURES_TRACKED_COUNT];
    WCPressuresSavedPos savedPos[WCPRESSURES_TRACKED_COUNT];
} WCPressuresState;

STATIC_ASSERT(sizeof(WCPressuresState) == 0x7C);
STATIC_ASSERT(offsetof(WCPressuresState, pressTimer) == 0x00);
STATIC_ASSERT(offsetof(WCPressuresState, mode) == 0x01);
STATIC_ASSERT(offsetof(WCPressuresState, objects) == 0x04);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].x) == 0x2C);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].z) == 0x30);
STATIC_ASSERT(offsetof(WCPressuresSetup, base.posX) == 0x08);
STATIC_ASSERT(offsetof(WCPressuresSetup, base.posY) == 0x0C);
STATIC_ASSERT(offsetof(WCPressuresSetup, base.posZ) == 0x10);
STATIC_ASSERT(offsetof(WCPressuresSetup, objectTypeHi) == 0x18);
STATIC_ASSERT(offsetof(WCPressuresSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCPressuresSetup, solvedBit) == 0x1A);
STATIC_ASSERT(offsetof(WCPressuresSetup, pressDepth) == 0x1C);
STATIC_ASSERT(offsetof(WCPressuresSetup, triggerHeight) == 0x1D);
STATIC_ASSERT(offsetof(WCPressuresSetup, activateBit) == 0x20);

extern ObjectDescriptor gWCPressureSObjDescriptor;

int wcpressures_getExtraSize(void);
int wcpressures_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int wcpressures_getObjectTypeId(GameObject* obj);
void wcpressures_free(GameObject* obj);
void wcpressures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpressures_hitDetect(void);
void wcpressures_update(int obj);
void wcpressures_init(GameObject* obj, WCPressuresSetup* setup);
void wcpressures_release(void);
void wcpressures_initialise(void);

#endif /* MAIN_DLL_WC_DLL_028F_WCPRESSURES_H */
