#ifndef MAIN_DLL_DLL_0103_CURVEFISH_H_
#define MAIN_DLL_DLL_0103_CURVEFISH_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/dll/curve_walker.h"

/* Retail CurveFish placements have a fixed 0x0C-byte parameter tail. */
typedef struct CurveFishPlacement
{
    ObjPlacement base;
    u8 rootMotionScalePercent;
    u8 speedChange;
    u8 pad1A[6];
    u16 waitFrames;
    u8 targetYOffset;
    u8 playerRadius;
} CurveFishPlacement;

typedef struct CurveFishState
{
    union
    {
        RomCurveWalker route;
        struct
        {
            u8 pad00[0x10];
            int hasRouteEdge;
            u8 pad14[0x54];
            f32 targetX;
            f32 targetY;
            f32 targetZ;
            u8 pad74[0x30];
            int routeCursor;
            u8 padA8[0x60];
        };
    };
    u8 mode;
    u8 pad109[3];
    f32 animTimer;
    f32 maxSpeed;
    f32 speed;
    f32 moveStepScale;
    f32 phaseTimer;
} CurveFishState;

STATIC_ASSERT(sizeof(CurveFishPlacement) == 0x24);
STATIC_ASSERT(offsetof(CurveFishPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(CurveFishPlacement, rootMotionScalePercent) == 0x18);
STATIC_ASSERT(offsetof(CurveFishPlacement, speedChange) == 0x19);
STATIC_ASSERT(offsetof(CurveFishPlacement, waitFrames) == 0x20);
STATIC_ASSERT(offsetof(CurveFishPlacement, targetYOffset) == 0x22);
STATIC_ASSERT(offsetof(CurveFishPlacement, playerRadius) == 0x23);
STATIC_ASSERT(sizeof(CurveFishState) == 0x120);
STATIC_ASSERT(offsetof(CurveFishState, route) == 0x0);
STATIC_ASSERT(offsetof(CurveFishState, mode) == 0x108);
STATIC_ASSERT(offsetof(CurveFishState, animTimer) == 0x10C);
STATIC_ASSERT(offsetof(CurveFishState, maxSpeed) == 0x110);
STATIC_ASSERT(offsetof(CurveFishState, speed) == 0x114);
STATIC_ASSERT(offsetof(CurveFishState, moveStepScale) == 0x118);
STATIC_ASSERT(offsetof(CurveFishState, phaseTimer) == 0x11C);

int CurveFish_getExtraSize(void);
void CurveFish_update(int obj);
void CurveFish_init(GameObject* obj, CurveFishPlacement* placement);

extern ObjectDescriptor gCurveFishObjDescriptor;

#endif /* MAIN_DLL_DLL_0103_CURVEFISH_H_ */
