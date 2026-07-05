#ifndef MAIN_DLL_CF_DLL_165_H_
#define MAIN_DLL_CF_DLL_165_H_

#include "global.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct TreasureChestSetup {
    ObjPlacement base;
    s8 type;
    u8 hitboxKind;
    s16 triggerObjectId;
    s16 dialogueId;
    s16 openGameBit;
    u8 pad20[0x24 - 0x20];
} TreasureChestSetup;

void staffactivated_init(int obj, int setup);
int treasurechest_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int treasurechest_getExtraSize(void);
int treasurechest_getObjectTypeId(void);
void treasurechest_free(void);
void treasurechest_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void treasurechest_hitDetect(int obj);

#endif /* MAIN_DLL_CF_DLL_165_H_ */
