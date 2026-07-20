#ifndef MAIN_DLL_DLL_0190_ECSHCUP_H_
#define MAIN_DLL_DLL_0190_ECSHCUP_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct EcshCupPlacement
{
    ObjPlacement base;
    u8 pad18[2];
    s16 slotId;
} EcshCupPlacement;

typedef struct EcshCupState
{
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 transitionHeight;
    f32 particleTimer;
    f32 bobTimer;
    s32 currentMode;
    s32 slotId;
    s16 spinRate;
    s8 bobDirection;
    u8 pad2F;
} EcshCupState;

typedef struct EcshCupControllerInterfaceVTable
{
    void* pad00[9];
    void (*getSlotPosition)(int slotId, f32* x, f32* z);
    void (*getMode)(int* mode, u8* activeSlot);
    void (*setSlotPosition)(int slotId, f32 x, f32 z);
    void (*activateSlot)(int slotId);
} EcshCupControllerInterfaceVTable;

STATIC_ASSERT(offsetof(EcshCupPlacement, slotId) == 0x1A);
STATIC_ASSERT(sizeof(EcshCupPlacement) == 0x1C);
STATIC_ASSERT(offsetof(EcshCupState, transitionHeight) == 0x18);
STATIC_ASSERT(offsetof(EcshCupState, currentMode) == 0x24);
STATIC_ASSERT(offsetof(EcshCupState, slotId) == 0x28);
STATIC_ASSERT(offsetof(EcshCupState, spinRate) == 0x2C);
STATIC_ASSERT(offsetof(EcshCupState, bobDirection) == 0x2E);
STATIC_ASSERT(sizeof(EcshCupState) == 0x30);
STATIC_ASSERT(offsetof(EcshCupControllerInterfaceVTable, getSlotPosition) == 0x24);
STATIC_ASSERT(offsetof(EcshCupControllerInterfaceVTable, getMode) == 0x28);
STATIC_ASSERT(offsetof(EcshCupControllerInterfaceVTable, setSlotPosition) == 0x2C);
STATIC_ASSERT(offsetof(EcshCupControllerInterfaceVTable, activateSlot) == 0x30);

extern GameObject* gEcShCupNearestObject;
extern ObjectDescriptor gECSH_CupObjDescriptor;

int ecsh_cup_getExtraSize(void);
int ecsh_cup_getObjectTypeId(void);
void ecsh_cup_free(GameObject* obj);
void ecsh_cup_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ecsh_cup_hitDetect(void);
void ecsh_cup_update(GameObject* obj);
void ecsh_cup_init(GameObject* obj, EcshCupPlacement* placement);
void ecsh_cup_release(void);
void ecsh_cup_initialise(void);

#endif /* MAIN_DLL_DLL_0190_ECSHCUP_H_ */
