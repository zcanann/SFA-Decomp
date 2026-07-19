#ifndef MAIN_CARRYABLE_INTERFACE_H_
#define MAIN_CARRYABLE_INTERFACE_H_

#include "global.h"
#include "main/game_object.h"

typedef void (*CarryableInitFn)(GameObject* obj, void* state, int arg2);
typedef int (*CarryableUpdateHeldFn)(GameObject* obj, void* state);
typedef int (*CarryableUpdateRenderStateFn)(GameObject* obj, int visible);
typedef void (*CarryableFreeFn)(GameObject* obj);
typedef s32 (*CarryableGetCarryStateFn)(void* state);
typedef s32 (*CarryableWasJustGrabbedFn)(void* state);
typedef u8 (*CarryableGetSurfaceTypeFn)(void* state);
typedef void (*CarryableSetGravityEnabledFn)(void* state, u8 enabled);
typedef void (*CarryableSetDropDisabledFn)(void* state, u8 disabled);
typedef s32 (*CarryableGetDropDisabledFn)(void* state);
typedef void (*CarryableSetSuppressPositionSaveFn)(void* state, u8 suppress);
typedef void (*CarryableStopCarryingFn)(GameObject* obj, void* state);

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

extern CarryableInterface **gCarryableInterface;

#endif /* MAIN_CARRYABLE_INTERFACE_H_ */
