#ifndef MAIN_DLL_DLL_0031_MINIMAP_H_
#define MAIN_DLL_DLL_0031_MINIMAP_H_

#include "global.h"

typedef struct MinimapInterfaceVTable
{
    void (*reserved)(void);
    void (*frameStart)(void);
    int (*update)(void);
    void (*reserved0C)(void);
} MinimapInterfaceVTable;

typedef struct MinimapInterface
{
    MinimapInterfaceVTable* vtable;
} MinimapInterface;

STATIC_ASSERT(offsetof(MinimapInterfaceVTable, frameStart) == 0x04);
STATIC_ASSERT(offsetof(MinimapInterfaceVTable, update) == 0x08);
STATIC_ASSERT(sizeof(MinimapInterfaceVTable) == 0x10);

extern MinimapInterface* gMinimapInterface;

int Minimap_update(void);
void Minimap_frameStart(void);
void Minimap_release(void);
void Minimap_initialise(void);

#endif /* MAIN_DLL_DLL_0031_MINIMAP_H_ */
