#ifndef MAIN_DLL_DLL_0200_DLL200_H_
#define MAIN_DLL_DLL_0200_DLL200_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"

/* Set of 3 item ids copied from a placement's item-set table and passed
 * (as an s32[3]) to isOneOfItemsBeingUsed to test the player's held item. */
typedef struct ItemIdSet3
{
    int itemId0;
    int itemId1;
    int itemId2;
} ItemIdSet3;

typedef struct ArwAttachTarget
{
    f32 x;
    f32 y;
    f32 moveId;
    f32 altMoveId;
    f32 speed;
} ArwAttachTarget;

void fn_801F20D4(int obj);
void fn_801F27E4(int obj);
void dll_200_free_nop(void);
void dll_200_hitDetect_nop(void);
void dll_200_release_nop(void);
void dll_200_initialise_nop(void);
int dll_200_getExtraSize_ret_40(void);
int dll_200_getObjectTypeId(void);
void dll_200_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_200_init(int* obj, int* arg);
int dll_200_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);
int dll_200_unlockFireBlasterSpell(int* obj, int unused, ObjAnimUpdateState* animUpdate, int arg3);
void dll_200_update(int obj);
void fn_801F2290(int obj);

#endif /* MAIN_DLL_DLL_0200_DLL200_H_ */
