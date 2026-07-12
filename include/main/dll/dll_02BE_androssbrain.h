#ifndef MAIN_DLL_DLL_02BE_ANDROSSBRAIN_H
#define MAIN_DLL_DLL_02BE_ANDROSSBRAIN_H

#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef enum AndrossBrainMode
{
    ANDROSSBRAIN_SHIELDED = 0,
    ANDROSSBRAIN_VULNERABLE = 1,
    ANDROSSBRAIN_DEFEATED = 2
} AndrossBrainMode;

typedef struct AndrossBrainState
{
    GameObject* andross;
    GameObject* lightning;
    u8 pad08[0x14];
    s8 brainState;
    s8 prevState;
    u8 health;
    u8 flashTimer;
    u8 pad20[8];
} AndrossBrainState;

STATIC_ASSERT(sizeof(AndrossBrainState) == 0x28);
STATIC_ASSERT(offsetof(AndrossBrainState, andross) == 0x00);
STATIC_ASSERT(offsetof(AndrossBrainState, lightning) == 0x04);
STATIC_ASSERT(offsetof(AndrossBrainState, brainState) == 0x1C);
STATIC_ASSERT(offsetof(AndrossBrainState, prevState) == 0x1D);
STATIC_ASSERT(offsetof(AndrossBrainState, health) == 0x1E);
STATIC_ASSERT(offsetof(AndrossBrainState, flashTimer) == 0x1F);

extern ObjectDescriptor gAndrossBrainObjDescriptor;

void androssbrain_setState(GameObject* obj, AndrossBrainMode newState, u8 force);
int AndrossBrain_getExtraSize(void);
int AndrossBrain_getObjectTypeId(void);
void AndrossBrain_free(void);
void AndrossBrain_render(GameObject* obj, int p2, int p3, int p4, int p5);
void AndrossBrain_hitDetect(void);
void AndrossBrain_update(GameObject* obj);
void AndrossBrain_init(GameObject* obj);

#endif
