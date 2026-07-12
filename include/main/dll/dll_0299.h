#ifndef MAIN_DLL_DLL_0299_H
#define MAIN_DLL_DLL_0299_H

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct Dll299Vtable
{
    void* pad;
    void (*slot1)(int, int, int, int, int, int);
} Dll299Vtable;

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

extern ObjectDescriptor dll_299;
extern void* lbl_803DDD80;

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
