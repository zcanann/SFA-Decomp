#ifndef MAIN_DLL_DLL_0127_DLL127_H_
#define MAIN_DLL_DLL_0127_DLL127_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct Dll127Setup
{
    ObjPlacement base;
    u8 bankIndex;
    u8 swayMagnitude;
    u8 yawBits;
} Dll127Setup;

STATIC_ASSERT(offsetof(Dll127Setup, bankIndex) == 0x18);
STATIC_ASSERT(offsetof(Dll127Setup, swayMagnitude) == 0x19);
STATIC_ASSERT(offsetof(Dll127Setup, yawBits) == 0x1a);

int dll_127_getExtraSize_ret_0(void);
int dll_127_getObjectTypeId(void);
void dll_127_free_nop(void);
void dll_127_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_127_hitDetect_nop(void);
void dll_127_update(GameObject* obj);
void dll_127_init(GameObject* obj, Dll127Setup* setup);
void dll_127_release_nop(void);
void dll_127_initialise_nop(void);

#endif /* MAIN_DLL_DLL_0127_DLL127_H_ */
