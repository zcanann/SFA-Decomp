#ifndef MAIN_DLL_DLL_01D6_DLL1D6_H_
#define MAIN_DLL_DLL_01D6_DLL1D6_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct Dll1D6Placement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19;
    s16 upTimer;
    s16 downTimer;
    u8 pad1E[0x20 - 0x1E];
} Dll1D6Placement;

STATIC_ASSERT(offsetof(Dll1D6Placement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dll1D6Placement, upTimer) == 0x1A);
STATIC_ASSERT(offsetof(Dll1D6Placement, downTimer) == 0x1C);

int dll_1D6_getExtraSize(void);
int dll_1D6_getObjectTypeId(void);
void dll_1D6_free(GameObject* obj);
void dll_1D6_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_1D6_hitDetect(void);
void dll_1D6_update(GameObject* obj);
void dll_1D6_init(GameObject* obj, Dll1D6Placement* placement);
void dll_1D6_release(void);
void dll_1D6_initialise(void);

extern s16 gDll1D6SlotTabIndex[4];
extern u8 gDll1D6SlotInUse[8];

#endif /* MAIN_DLL_DLL_01D6_DLL1D6_H_ */
