#ifndef MAIN_DLL_DR_DLL_026B_DRCHIMMEY_H_
#define MAIN_DLL_DR_DLL_026B_DRCHIMMEY_H_

#include "global.h"
#include "main/obj_placement.h"

typedef struct DRChimmeySetup
{
    ObjPlacement base;
    s8 yawByte;
    u8 pad19[5];
    s16 completionGameBit;
    s16 enableGameBit;
    u8 pad22[0x24 - 0x22];
} DRChimmeySetup;

typedef struct DRChimmeyState
{
    void* linkedObject;
    u8 pad04[8];
    f32 timerDuration;
    f32 timer;
    s16 completionGameBit;
    s8 offeringsRemaining;
    u8 eventActive;
} DRChimmeyState;

typedef struct DRChimmeyObject
{
    s16 yaw;
    u8 pad02[0x4a];
    DRChimmeySetup* setup;
    u8 pad50[0x5f];
    u8 renderFlags;
    u8 padB0[8];
    DRChimmeyState* state;
} DRChimmeyObject;

STATIC_ASSERT(sizeof(DRChimmeyState) == 0x18);
STATIC_ASSERT(offsetof(DRChimmeyState, timerDuration) == 0x0c);
STATIC_ASSERT(offsetof(DRChimmeyState, timer) == 0x10);
STATIC_ASSERT(offsetof(DRChimmeyState, completionGameBit) == 0x14);
STATIC_ASSERT(offsetof(DRChimmeyState, offeringsRemaining) == 0x16);
STATIC_ASSERT(offsetof(DRChimmeyState, eventActive) == 0x17);
STATIC_ASSERT(sizeof(DRChimmeySetup) == 0x24);
STATIC_ASSERT(offsetof(DRChimmeySetup, yawByte) == 0x18);
STATIC_ASSERT(offsetof(DRChimmeySetup, completionGameBit) == 0x1e);
STATIC_ASSERT(offsetof(DRChimmeySetup, enableGameBit) == 0x20);
STATIC_ASSERT(offsetof(DRChimmeyObject, setup) == 0x4c);
STATIC_ASSERT(offsetof(DRChimmeyObject, renderFlags) == 0xaf);
STATIC_ASSERT(offsetof(DRChimmeyObject, state) == 0xb8);


int drchimmey_countdownCallback(DRChimmeyObject* obj, int amount);
int DR_Chimmey_getExtraSize(void);
void DR_Chimmey_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void DR_Chimmey_update(DRChimmeyObject* obj);
void DR_Chimmey_init(DRChimmeyObject* obj, DRChimmeySetup* setup);

#endif /* MAIN_DLL_DR_DLL_026B_DRCHIMMEY_H_ */
