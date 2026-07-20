#ifndef MAIN_DLL_DLL_003C_TUMBLEWEEDBUSH_H_
#define MAIN_DLL_DLL_003C_TUMBLEWEEDBUSH_H_

#include "global.h"

typedef void (*LinkSetupFn)(void* items, int count, int selected, void* defaultMessage, int unused1,
                            int unused2, int baseRed, int baseGreen, int baseBlue, int selectedRed,
                            int selectedGreen, int selectedBlue);

typedef struct LinkInterfaceVTable
{
    void (*reserved)(void);
    LinkSetupFn setup;
    void (*free)(void);
    u32 (*update)(void);
    void (*render)(int context);
    s32 (*getSelected)(void);
    void (*setSelected)(int selected);
    s32 (*getItemState)(int index);
    void (*setItemState)(int index, int state);
    void (*updateItems)(void* items);
    u8 (*getPulse)(void);
    void (*copyItems)(void* items);
    void (*setOpacity)(int opacity);
    void (*resetTimers)(void);
} LinkInterfaceVTable;

typedef struct LinkInterface
{
    LinkInterfaceVTable* vtable;
} LinkInterface;

STATIC_ASSERT(offsetof(LinkInterfaceVTable, setup) == 0x04);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, free) == 0x08);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, update) == 0x0C);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, render) == 0x10);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, getSelected) == 0x14);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, setSelected) == 0x18);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, updateItems) == 0x24);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, copyItems) == 0x2C);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, setOpacity) == 0x30);
STATIC_ASSERT(offsetof(LinkInterfaceVTable, resetTimers) == 0x34);
STATIC_ASSERT(sizeof(LinkInterfaceVTable) == 0x38);

void titleScreenFn_80130464(u8 v);

#endif /* MAIN_DLL_DLL_003C_TUMBLEWEEDBUSH_H_ */
