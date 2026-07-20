#ifndef MAIN_DLL_DLL_019F_NWTREEBRID_H_
#define MAIN_DLL_DLL_019F_NWTREEBRID_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct NwTreeBirdPlacement
{
    ObjPlacement base;
    s8 initialRotX;
    s8 triggerVariant;
    s16 initialRotY;
    s16 initialRotZ;
    s16 gameBit;
} NwTreeBirdPlacement;

typedef struct NwTreeBirdState
{
    s16 gameBit;
    s16 triggerId;
    s16 preemptSequenceId;
    u8 triggerLatched;
    u8 searchDelay;
    GameObject* pathFollower;
} NwTreeBirdState;

STATIC_ASSERT(offsetof(NwTreeBirdPlacement, initialRotX) == 0x18);
STATIC_ASSERT(offsetof(NwTreeBirdPlacement, triggerVariant) == 0x19);
STATIC_ASSERT(offsetof(NwTreeBirdPlacement, initialRotY) == 0x1A);
STATIC_ASSERT(offsetof(NwTreeBirdPlacement, initialRotZ) == 0x1C);
STATIC_ASSERT(offsetof(NwTreeBirdPlacement, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(NwTreeBirdPlacement) == 0x20);
STATIC_ASSERT(offsetof(NwTreeBirdState, pathFollower) == 0x8);
STATIC_ASSERT(sizeof(NwTreeBirdState) == 0xC);

int TreeBird_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int treebird_getExtraSize(void);
void treebird_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void treebird_update(GameObject* obj);
void treebird_init(GameObject* obj, NwTreeBirdPlacement* placement);

#endif /* MAIN_DLL_DLL_019F_NWTREEBRID_H_ */
