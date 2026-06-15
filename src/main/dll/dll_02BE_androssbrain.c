#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

/*
 * Per-object extra state for the Andross brain core
 * (androssbrain_getExtraSize == 0x28).
 */
typedef struct AndrossBrainState
{
    GameObject* andross; /* objId 0x47B77 main andross object */
    GameObject* lightning; /* objId 0x4C611, androssligh target */
    u8 pad08[0x1C - 0x08];
    s8 brainState; /* 0 shielded, 1 vulnerable, 2 defeated */
    s8 prevState;
    u8 health; /* 0x50; decrements per hit */
    u8 flashTimer; /* frames of red flash / hit cooldown */
    u8 pad20[8];
} AndrossBrainState;

STATIC_ASSERT(sizeof(AndrossBrainState) == 0x28);
STATIC_ASSERT(offsetof(AndrossBrainState, andross) == 0x0);
STATIC_ASSERT(offsetof(AndrossBrainState, lightning) == 0x4);
STATIC_ASSERT(offsetof(AndrossBrainState, brainState) == 0x1C);
STATIC_ASSERT(offsetof(AndrossBrainState, prevState) == 0x1D);
STATIC_ASSERT(offsetof(AndrossBrainState, health) == 0x1E);
STATIC_ASSERT(offsetof(AndrossBrainState, flashTimer) == 0x1F);


int androssbrain_getExtraSize(void) { return 0x28; }

int androssbrain_getObjectTypeId(void) { return 0; }

void androssbrain_free(void)
{
}

void androssbrain_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7600);
}

void androssbrain_hitDetect(void)
{
}

void androssbrain_setState(int obj, int newState, u8 force)
{
    AndrossBrainState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = ((GameObject*)obj)->extra;
    if (state->brainState != 2 || force != 0)
    {
        state->brainState = (s8)newState;
        if (force != 0)
        {
            state->health = 0x50;
        }
    }
    else
    {
        andross_setPartSignal((int)state->andross, 1);
    }
}

void androssbrain_init(int obj)
{
    AndrossBrainState* state = ((GameObject*)obj)->extra;

    state->health = 0x50;
    ObjHits_SetTargetMask(obj, 4);
}

void androssbrain_update(int obj)
{
    AndrossBrainState* state = ((GameObject*)obj)->extra;
    u8 flag = 0;
    int hitObj;
    int sphereIdx;
    uint hitVol;
    int hit;
    int t;
    u8 currentState;

    if (state->andross == NULL)
    {
        state->andross = (GameObject*)ObjList_FindObjectById(0x47b77);
    }
    if (state->lightning == NULL)
    {
        state->lightning = (GameObject*)ObjList_FindObjectById(0x4c611);
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);
    if (state->andross != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = state->andross->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = state->andross->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = state->andross->anim.localPosZ;
    }
    currentState = *(u8*)&state->brainState;
    if ((s8)currentState != state->prevState)
    {
        flag = 1;
    }
    *(u8*)&state->prevState = currentState;
    switch (state->brainState)
    {
    case 0:
        if (flag != 0)
        {
            (*gGameUIInterface)->airMeterShutdown();
        }
        ((GameObject*)obj)->anim.rotX = state->andross->anim.rotX;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case 1:
        if (flag != 0)
        {
            state->flashTimer = 0x3c;
            (*gGameUIInterface)->initAirMeter(0x50, 0x643);
        }
        (*gGameUIInterface)->runAirMeter(state->health);
        hit = ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol);
        t = state->flashTimer - framesThisStep;
        if (t < 0)
        {
            t = 0;
        }
        state->flashTimer = (u8)t;
        if (hit != 0)
        {
            if (state->flashTimer == 0)
            {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                state->flashTimer = 6;
                state->health -= 1;
                if (state->health == 0)
                {
                    *(u8*)&state->brainState = 2;
                    andross_setPartSignal((int)state->andross, 1);
                    Sfx_PlayFromObject(obj, 0x485);
                }
                else
                {
                    Sfx_PlayFromObject(obj, 0x484);
                }
            }
        }
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        break;
    case 2:
        if (flag != 0)
        {
            androssligh_setState((int)state->lightning, 2, 0);
            (*gGameUIInterface)->airMeterShutdown();
        }
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        andross_setPartSignal((int)state->andross, 8);
        break;
    }
}
