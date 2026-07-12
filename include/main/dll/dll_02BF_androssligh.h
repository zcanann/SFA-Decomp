#ifndef MAIN_DLL_DLL_02BF_ANDROSSLIGH_H
#define MAIN_DLL_DLL_02BF_ANDROSSLIGH_H

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/lightningeffect.h"

typedef enum AndrossLighMode
{
    ANDROSSLIGH_IDLE = 0,
    ANDROSSLIGH_ACTIVE = 1,
    ANDROSSLIGH_DONE = 2
} AndrossLighMode;

typedef struct AndrossLighState
{
    GameObject* anchor;
    LightningEffect* bolt;
    f32 boltAge;
    s8 state;
    u8 prevState;
    u8 pad0E[2];
} AndrossLighState;

STATIC_ASSERT(sizeof(AndrossLighState) == 0x10);
STATIC_ASSERT(offsetof(AndrossLighState, bolt) == 0x04);
STATIC_ASSERT(offsetof(AndrossLighState, boltAge) == 0x08);
STATIC_ASSERT(offsetof(AndrossLighState, state) == 0x0C);
STATIC_ASSERT(offsetof(AndrossLighState, prevState) == 0x0D);

extern ObjectDescriptor gAndrossLighObjDescriptor;
extern f32 lbl_803DC518;
extern f32 lbl_803DC51C;
extern f32 lbl_803DC520;
extern f32 lbl_803DC524;
extern f32 lbl_803DC528;
extern f32 lbl_803DC52C;

void androssligh_updateBeam(GameObject* obj, AndrossLighState* state);
void androssligh_setState(GameObject* obj, AndrossLighMode newState, u8 force);
int androssligh_getExtraSize(void);
int androssligh_getObjectTypeId(void);
void androssligh_free(void);
void androssligh_render(GameObject* obj);
void androssligh_hitDetect(void);
void androssligh_update(GameObject* obj);
void androssligh_init(void);

#endif
