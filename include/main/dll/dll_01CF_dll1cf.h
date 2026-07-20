#ifndef MAIN_DLL_DLL_01CF_DLL1CF_H_
#define MAIN_DLL_DLL_01CF_DLL1CF_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct Dll1CFPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19;
    s16 rotYDegrees;
    s16 unk1C;
    s16 gateGameBit;
} Dll1CFPlacement;

STATIC_ASSERT(offsetof(Dll1CFPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dll1CFPlacement, rotYDegrees) == 0x1A);
STATIC_ASSERT(offsetof(Dll1CFPlacement, gateGameBit) == 0x1E);

int dll_1CF_getExtraSize(void);
int dll_1CF_getObjectTypeId(void);
void dll_1CF_free(void);
void dll_1CF_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_1CF_hitDetect(void);
void dll_1CF_update(void);
void dll_1CF_init(GameObject* obj, Dll1CFPlacement* placement);
void dll_1CF_release(void);
void dll_1CF_initialise(void);

#endif /* MAIN_DLL_DLL_01CF_DLL1CF_H_ */
