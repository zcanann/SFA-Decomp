/*
 * androssbrain (DLL 0x2BE) - the destructible brain core of the final
 * Andross boss. It tracks the parent andross object (0x47B77) and the
 * lightning object (0x4C611), mirroring andross's position and rotation
 * each frame. While shielded it stays hidden; once made vulnerable it
 * shows the air-meter health bar (0x50 hits), takes a hit per priority
 * collision with a flash + cooldown, and on reaching zero health flips to
 * the defeated state, signalling andross and the lightning object.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

enum
{
    ANDROSS_OBJ_ID = 0x47b77,
    ANDROSSLIGH_OBJ_ID = 0x4c611
};

enum
{
    BRAIN_SHIELDED = 0,
    BRAIN_VULNERABLE = 1,
    BRAIN_DEFEATED = 2
};

#define BRAIN_MAX_HEALTH 0x50

enum
{
    ANDROSS_SIGNAL_BRAIN_HIT = 1,
    ANDROSS_SIGNAL_BRAIN_DEFEATED = 8
};

typedef struct AndrossBrainState
{
    GameObject* andross; /* objId ANDROSS_OBJ_ID, main andross object */
    GameObject* lightning; /* objId ANDROSSLIGH_OBJ_ID, androssligh target */
    u8 pad08[0x1C - 0x08];
    s8 brainState; /* BRAIN_* */
    s8 prevState;
    u8 health; /* decrements per hit */
    u8 flashTimer; /* frames of red flash / hit cooldown */
    u8 pad20[0x28 - 0x20];
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
    if (state->brainState != BRAIN_DEFEATED || force != 0)
    {
        state->brainState = newState;
        if (force != 0)
        {
            state->health = BRAIN_MAX_HEALTH;
        }
    }
    else
    {
        andross_setPartSignal((int)state->andross, ANDROSS_SIGNAL_BRAIN_HIT);
    }
}

void androssbrain_init(int obj)
{
    AndrossBrainState* state = ((GameObject*)obj)->extra;

    state->health = BRAIN_MAX_HEALTH;
    ObjHits_SetTargetMask(obj, 4);
}

#pragma opt_common_subs off
void androssbrain_update(int obj)
{
    AndrossBrainState* state = ((GameObject*)obj)->extra;
    u8 stateChanged = 0;
    int hitObj;
    int sphereIdx;
    u32 hitVol;
    int hit;
    int flashTimer;
    u8 currentState;

    if (state->andross == NULL)
    {
        state->andross = (GameObject*)ObjList_FindObjectById(ANDROSS_OBJ_ID);
    }
    if (state->lightning == NULL)
    {
        state->lightning = (GameObject*)ObjList_FindObjectById(ANDROSSLIGH_OBJ_ID);
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);
    if (state->andross != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = state->andross->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = state->andross->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = state->andross->anim.localPosZ;
    }
    currentState = state->brainState;
    if ((s8)currentState != state->prevState)
    {
        stateChanged = 1;
    }
    *(u8*)&state->prevState = currentState;
    switch (state->brainState)
    {
    case BRAIN_SHIELDED:
        if (stateChanged != 0)
        {
            (*gGameUIInterface)->airMeterShutdown();
        }
        ((GameObject*)obj)->anim.rotX = state->andross->anim.rotX;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case BRAIN_VULNERABLE:
        if (stateChanged != 0)
        {
            state->flashTimer = 0x3c;
            (*gGameUIInterface)->initAirMeter(BRAIN_MAX_HEALTH, 0x643);
        }
        (*gGameUIInterface)->runAirMeter(state->health);
        hit = ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol);
        flashTimer = state->flashTimer - framesThisStep;
        if (flashTimer < 0)
        {
            flashTimer = 0;
        }
        state->flashTimer = flashTimer;
        if (hit != 0)
        {
            if (state->flashTimer == 0)
            {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                state->flashTimer = 6;
                state->health -= 1;
                if (state->health == 0)
                {
                    state->brainState = BRAIN_DEFEATED;
                    andross_setPartSignal((int)state->andross, ANDROSS_SIGNAL_BRAIN_HIT);
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
    case BRAIN_DEFEATED:
        if (stateChanged != 0)
        {
            androssligh_setState((int)state->lightning, BRAIN_DEFEATED, 0);
            (*gGameUIInterface)->airMeterShutdown();
        }
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        andross_setPartSignal((int)state->andross, ANDROSS_SIGNAL_BRAIN_DEFEATED);
        break;
    }
}
#pragma opt_common_subs reset

