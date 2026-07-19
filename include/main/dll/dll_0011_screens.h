#ifndef MAIN_DLL_DLL_0011_SCREENS_H_
#define MAIN_DLL_DLL_0011_SCREENS_H_

#include "main/asset_load.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"

typedef struct ScreensInterfaceVTable
{
    void (*reserved)(void);
    void (*show)(int id);
    void (*remove)(void);
    void (*run)(int unused);
} ScreensInterfaceVTable;

typedef struct ScreensInterface
{
    ScreensInterfaceVTable* vtable;
} ScreensInterface;

STATIC_ASSERT(offsetof(ScreensInterfaceVTable, show) == 0x04);
STATIC_ASSERT(offsetof(ScreensInterfaceVTable, remove) == 0x08);
STATIC_ASSERT(offsetof(ScreensInterfaceVTable, run) == 0x0C);
STATIC_ASSERT(sizeof(ScreensInterfaceVTable) == 0x10);

extern ScreensInterface* gScreensInterface;

void loadTaskTexts(void);
int hintTextMapFn_800ea264(void);
u8 getCurTaskHintTextMap(void);
void gameBitFn_800ea2e0(u8 id);
void screens_initialise(void);
void screens_release(void);
void screens_remove(void);
void screens_run(int unused);
void screens_show(int id);

#endif
