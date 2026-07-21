#ifndef MAIN_DLL_SB_DLL_01F0_SBKYTECAGE_H_
#define MAIN_DLL_SB_DLL_01F0_SBKYTECAGE_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct SBKyteCagePlacement
{
    ObjPlacement base;
    s8 rotX;
} SBKyteCagePlacement;

STATIC_ASSERT(offsetof(SBKyteCagePlacement, rotX) == 0x18);

int SB_KyteCage_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int SB_KyteCage_getExtraSize(void);
int SB_KyteCage_getObjectTypeId(void);
void SB_KyteCage_free(GameObject* obj);
void SB_KyteCage_render(void);
void SB_KyteCage_hitDetect(void);
void SB_KyteCage_update(GameObject* obj);
void SB_KyteCage_init(GameObject* obj, SBKyteCagePlacement* placement);
void SB_KyteCage_release(void);
void SB_KyteCage_initialise(void);

extern ObjectDescriptor gSB_KyteCageObjDescriptor;

#endif /* MAIN_DLL_SB_DLL_01F0_SBKYTECAGE_H_ */
