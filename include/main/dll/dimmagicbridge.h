#ifndef MAIN_DLL_DLL_1CC_H_
#define MAIN_DLL_DLL_1CC_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct Dll19APlacement
{
    ObjPlacement base;
    u8 reserved18[6];
    s8 rotX;
    s8 gateBitIndex;
} Dll19APlacement;

typedef struct Dll19AState
{
    s16 countdown;
    s16 countdownRate;
} Dll19AState;

STATIC_ASSERT(offsetof(Dll19APlacement, rotX) == 0x1e);
STATIC_ASSERT(offsetof(Dll19APlacement, gateBitIndex) == 0x1f);
STATIC_ASSERT(sizeof(Dll19APlacement) == 0x20);
STATIC_ASSERT(sizeof(Dll19AState) == 0x4);

void dll_199_update(GameObject* obj);
void dll_199_init(GameObject* obj, int def);
int dll_199_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dll_199_release(void);
void dll_199_initialise(void);
int dll_19A_getExtraSize(void);
int dll_19A_getObjectTypeId(void);
void dll_19A_free(void);
void dll_19A_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_19A_hitDetect(void);
void dll_19A_update(GameObject* obj);
void dll_19A_init(GameObject* obj, Dll19APlacement* placement);
void dll_19A_release(void);
void dll_19A_initialise(void);

extern ObjectDescriptor dll_19A;

#endif /* MAIN_DLL_DLL_1CC_H_ */
