#ifndef MAIN_DLL_DLL_0299_H
#define MAIN_DLL_DLL_0299_H

#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/dll/dll_00A6_modgfx.h"

typedef struct Dll299State
{
    s16 id;
} Dll299State;

typedef struct Dll299Setup
{
    ObjPlacement base;
    u8 pad18[6];
    s16 id;
} Dll299Setup;

STATIC_ASSERT(sizeof(Dll299State) == 2);
STATIC_ASSERT(offsetof(Dll299Setup, id) == 0x1E);

extern ObjectDescriptor gDll299ObjDescriptor;
extern DllA6Interface** gDll299Resource;

int dll_299_getExtraSize_ret_2(void);
int dll_299_getObjectTypeId(void);
void dll_299_free(GameObject* obj);
void dll_299_render_nop(void);
void dll_299_hitDetect_nop(void);
void dll_299_update(GameObject* obj);
void dll_299_init(GameObject* obj, Dll299Setup* setup);
void dll_299_release_nop(void);
void dll_299_initialise_nop(void);

#endif
