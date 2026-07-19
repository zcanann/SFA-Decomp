#ifndef MAIN_DLL_DLL_003D_TITLEMENUITEM_H_
#define MAIN_DLL_DLL_003D_TITLEMENUITEM_H_

#include "global.h"
#include "main/dll/titlemenuitem_struct.h"

typedef struct TitleMenuItemInterfaceVTable
{
    void (*reserved)(void);
    TitleMenuItem* (*createWithText)(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value, int textId);
    TitleMenuItem* (*create)(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value);
    TitleMenuItem* (*createWithWindow)(int phraseId, int windowId, s16 minValue, s16 maxValue, s16 value);
    void (*free)(TitleMenuItem* item);
    void (*update)(TitleMenuItem* item);
    void (*render)(TitleMenuItem* item, int unused, int alpha);
    int (*isEnabled)(TitleMenuItem* item);
    void (*setEnabled)(TitleMenuItem* item, int enabled);
    int (*getValue)(TitleMenuItem* item);
    void (*setValue)(TitleMenuItem* item, int value);
    int (*isChanged)(TitleMenuItem* item);
    void (*setAButtonToggle)(TitleMenuItem* item, int enabled);
} TitleMenuItemInterfaceVTable;

typedef struct TitleMenuItemInterface
{
    TitleMenuItemInterfaceVTable* vtable;
} TitleMenuItemInterface;

STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, createWithText) == 0x04);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, createWithWindow) == 0x0C);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, free) == 0x10);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, update) == 0x14);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, render) == 0x18);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, getValue) == 0x24);
STATIC_ASSERT(offsetof(TitleMenuItemInterfaceVTable, isChanged) == 0x2C);
STATIC_ASSERT(sizeof(TitleMenuItemInterfaceVTable) == 0x34);

extern TitleMenuItemInterface* gTitleMenuItemInterface;
extern TitleMenuItem* lbl_803A87D0[8];

void fn_80131F0C(void);
int TitleMenuItem_isChanged(TitleMenuItem* item);
void TitleMenuItem_setVal(TitleMenuItem* item, int value);
int TitleMenuItem_getVal(TitleMenuItem* item);
void TitleMenuItem_setEnabled(TitleMenuItem* item, int enabled);
int TitleMenuItem_isEnabled(TitleMenuItem* item);
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha);
void TitleMenuItem_update(TitleMenuItem* item);
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int enabled);
void TitleMenuItem_free(TitleMenuItem* item);
void TitleMenuItem_initialise(void);
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue, s16 maxValue, s16 value);
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value);
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value, int textId);
void TitleMenuItem_release(void);

#endif
