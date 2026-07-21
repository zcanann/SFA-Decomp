#ifndef MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_
#define MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct CfPrisonCagePlacement
{
    ObjPlacement base;
    s16 openedGameBit;
    u8 rotByte;
    u8 pad1B;
    u8 pad1C[0x28 - 0x1C];
} CfPrisonCagePlacement;

STATIC_ASSERT(offsetof(CfPrisonCagePlacement, openedGameBit) == 0x18);
STATIC_ASSERT(offsetof(CfPrisonCagePlacement, rotByte) == 0x1A);
STATIC_ASSERT(sizeof(CfPrisonCagePlacement) == 0x28);

int CFPrisonCage_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int CFPrisonCage_getExtraSize(void);
int CFPrisonCage_getObjectTypeId(GameObject* obj);
void CFPrisonCage_free(void);
void CFPrisonCage_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void CFPrisonCage_hitDetect(GameObject* obj);
void CFPrisonCage_update(GameObject* obj);
void CFPrisonCage_init(GameObject* obj, CfPrisonCagePlacement* placement);
void CFPrisonCage_release(void);
void CFPrisonCage_initialise(void);

extern ObjectDescriptor gCFPrisonCageObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_ */
