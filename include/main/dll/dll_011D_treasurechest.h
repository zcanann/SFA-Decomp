#ifndef MAIN_DLL_DLL_011D_TREASURECHEST_H_
#define MAIN_DLL_DLL_011D_TREASURECHEST_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "types.h"

typedef struct TreasureChestSetup
{
    ObjPlacement base;
    s8 type;
    u8 hitboxKind;
    s16 triggerObjectId;
    s16 dialogueId;
    s16 openGameBit;
    u8 pad20[0x24 - 0x20];
} TreasureChestSetup;

int TreasureChest_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int TreasureChest_getExtraSize(void);
int TreasureChest_getObjectTypeId(void);
void TreasureChest_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void TreasureChest_free(void);
void TreasureChest_hitDetect(GameObject* obj);
void TreasureChest_update(GameObject* obj);
void TreasureChest_release(void);
void TreasureChest_initialise(void);
void TreasureChest_init(int* obj);

#endif /* MAIN_DLL_DLL_011D_TREASURECHEST_H_ */
