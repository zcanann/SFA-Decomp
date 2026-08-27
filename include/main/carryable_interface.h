#ifndef MAIN_CARRYABLE_INTERFACE_H_
#define MAIN_CARRYABLE_INTERFACE_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/carryable_state.h"

typedef void (*CarryableInitFn)(GameObject* obj, CarryableState* state, int arg2);
typedef int (*CarryableUpdateHeldFn)(GameObject* obj, CarryableState* state);
typedef int (*CarryableUpdateRenderStateFn)(GameObject* obj, int visible);
typedef void (*CarryableFreeFn)(GameObject* obj);
typedef s32 (*CarryableGetCarryStateFn)(CarryableState* state);
typedef s32 (*CarryableWasJustGrabbedFn)(CarryableState* state);
typedef u8 (*CarryableGetSurfaceTypeFn)(CarryableState* state);
typedef void (*CarryableSetGravityEnabledFn)(CarryableState* state, u8 enabled);
typedef void (*CarryableSetDropDisabledFn)(CarryableState* state, u8 disabled);
typedef s32 (*CarryableGetDropDisabledFn)(CarryableState* state);
typedef void (*CarryableSetSuppressPositionSaveFn)(CarryableState* state, u8 suppress);
typedef void (*CarryableStopCarryingFn)(GameObject* obj, CarryableState* state);

typedef struct CarryableInterface {
    u8 pad00[0x04];
    CarryableInitFn init;
    CarryableUpdateHeldFn updateHeld;
    CarryableUpdateRenderStateFn updateRenderState;
    CarryableFreeFn free;
    CarryableGetCarryStateFn getCarryState;
    CarryableWasJustGrabbedFn wasJustGrabbed;
    CarryableGetSurfaceTypeFn getSurfaceType;
    CarryableSetGravityEnabledFn setGravityEnabled;
    CarryableSetDropDisabledFn setDropDisabled;
    CarryableGetDropDisabledFn getDropDisabled;
    CarryableSetSuppressPositionSaveFn setSuppressPositionSave;
    CarryableStopCarryingFn stopCarrying;
} CarryableInterface;

STATIC_ASSERT(offsetof(CarryableInterface, init) == 0x04);
STATIC_ASSERT(offsetof(CarryableInterface, updateHeld) == 0x08);
STATIC_ASSERT(offsetof(CarryableInterface, updateRenderState) == 0x0C);
STATIC_ASSERT(offsetof(CarryableInterface, free) == 0x10);
STATIC_ASSERT(offsetof(CarryableInterface, getCarryState) == 0x14);
STATIC_ASSERT(offsetof(CarryableInterface, setGravityEnabled) == 0x20);
STATIC_ASSERT(offsetof(CarryableInterface, setDropDisabled) == 0x24);
STATIC_ASSERT(offsetof(CarryableInterface, setSuppressPositionSave) == 0x2C);
STATIC_ASSERT(offsetof(CarryableInterface, stopCarrying) == 0x30);
STATIC_ASSERT(sizeof(CarryableInterface) == 0x34);

extern CarryableInterface** gCarryableInterface;

#endif /* MAIN_CARRYABLE_INTERFACE_H_ */
