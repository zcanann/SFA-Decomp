#ifndef MAIN_DLL_CC_DLL_0186_CCGASVENTCONTROL_H_
#define MAIN_DLL_CC_DLL_0186_CCGASVENTCONTROL_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct CCGasVentControlPlacement
{
    ObjPlacement head;
    u8 pad18[2];
    u8 rotX;
} CCGasVentControlPlacement;

typedef struct CCGasVentControlState
{
    u8 state;
    u8 soundActive;
    u8 pad02[2];
    f32 airMeter;
    f32 fogRise;
    u8 ventCount;
    u8 pad0D[3];
} CCGasVentControlState;

STATIC_ASSERT(offsetof(CCGasVentControlPlacement, rotX) == 0x1A);
STATIC_ASSERT(offsetof(CCGasVentControlState, airMeter) == 0x4);
STATIC_ASSERT(offsetof(CCGasVentControlState, fogRise) == 0x8);
STATIC_ASSERT(offsetof(CCGasVentControlState, ventCount) == 0xC);
STATIC_ASSERT(sizeof(CCGasVentControlState) == 0x10);

extern ObjectDescriptor gCCgasventControlObjDescriptor;

int CCGasVentControl_SeqFn(GameObject* obj);
u8 CCGasVentControlFn_801a9fd0(GameObject* obj, CCGasVentControlState* state);

int ccgasventcontrol_getExtraSize(void);
void ccgasventcontrol_free(GameObject* obj);
void ccgasventcontrol_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ccgasventcontrol_update(GameObject* obj);
void ccgasventcontrol_init(GameObject* obj, CCGasVentControlPlacement* placement);

#endif
