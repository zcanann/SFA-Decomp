#ifndef MAIN_CARRYABLE_INTERFACE_H_
#define MAIN_CARRYABLE_INTERFACE_H_

#include "global.h"

typedef void (*CarryableInitAnimFn)(void *obj, int state, int animId);
typedef int (*CarryableGetAnimStateFn)(int obj, int state);
typedef int (*CarryableIsVisibleFn)(int obj, int visible);
typedef void (*CarryableFreeFn)(int obj);
typedef void (*CarryableSetVisibleFn)(int state, int visible);

typedef struct CarryableInterface {
    u8 pad00[0x04];
    CarryableInitAnimFn initAnim;
    CarryableGetAnimStateFn getAnimState;
    CarryableIsVisibleFn isVisible;
    CarryableFreeFn free;
    u8 pad14[0x24 - 0x14];
    CarryableSetVisibleFn setVisible;
} CarryableInterface;

STATIC_ASSERT(offsetof(CarryableInterface, initAnim) == 0x04);
STATIC_ASSERT(offsetof(CarryableInterface, getAnimState) == 0x08);
STATIC_ASSERT(offsetof(CarryableInterface, isVisible) == 0x0C);
STATIC_ASSERT(offsetof(CarryableInterface, free) == 0x10);
STATIC_ASSERT(offsetof(CarryableInterface, setVisible) == 0x24);

extern CarryableInterface **gCarryableInterface;

#endif /* MAIN_CARRYABLE_INTERFACE_H_ */
