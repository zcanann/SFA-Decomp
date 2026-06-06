#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

/*
 * Per-object extra state for the Andross brain core
 * (androssbrain_getExtraSize == 0x28).
 */
typedef struct AndrossBrainState {
    void *andross; /* objId 0x47B77 main andross object */
    void *lightning; /* objId 0x4C611, androssligh target */
    u8 pad08[0x1C - 0x08];
    s8 brainState; /* 0 shielded, 1 vulnerable, 2 defeated */
    s8 prevState;
    u8 health; /* 0x50; decrements per hit */
    u8 flashTimer; /* frames of red flash / hit cooldown */
    u8 pad20[8];
} AndrossBrainState;

STATIC_ASSERT(sizeof(AndrossBrainState) == 0x28);


#pragma peephole on
#pragma scheduling on
int androssbrain_getExtraSize(void) { return 0x28; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int androssbrain_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7600);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androssbrain_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androssbrain_setState(int obj, int newState, u8 force)
{
    AndrossBrainState *state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(AndrossBrainState **)(obj + 0xb8);
    if (state->brainState != 2 || force != 0) {
        state->brainState = (s8)newState;
        if (force != 0) {
            state->health = 0x50;
        }
    } else {
        andross_setPartSignal(*(int *)&state->andross, 1);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void androssbrain_init(int obj)
{
    AndrossBrainState *state = *(AndrossBrainState **)(obj + 0xb8);

    state->health = 0x50;
    ObjHits_SetTargetMask(obj, 4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androssbrain_update(int obj)
{
    AndrossBrainState *state = *(AndrossBrainState **)(obj + 0xb8);
    u8 flag = 0;
    int hitObj;
    int sphereIdx;
    int hitVol;
    int hit;
    int t;
    u8 currentState;

    if (state->andross == NULL) {
        *(int *)&state->andross = ObjList_FindObjectById(0x47b77);
    }
    if (state->lightning == NULL) {
        *(int *)&state->lightning = ObjList_FindObjectById(0x4c611);
    }
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);
    if (state->andross != NULL) {
        ((GameObject *)obj)->anim.localPosX = *(f32 *)(*(int *)&state->andross + 0xc);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)(*(int *)&state->andross + 0x10);
        ((GameObject *)obj)->anim.localPosZ = *(f32 *)(*(int *)&state->andross + 0x14);
    }
    currentState = *(u8 *)&state->brainState;
    if ((s8)currentState != state->prevState) {
        flag = 1;
    }
    *(u8 *)&state->prevState = currentState;
    switch (state->brainState) {
    case 0:
        if (flag != 0) {
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        *(s16 *)obj = *(s16 *)(*(int *)&state->andross);
        ((GameObject *)obj)->anim.flags |= 0x4000;
        break;
    case 1:
        if (flag != 0) {
            state->flashTimer = 0x3c;
            (*(void (**)(int, int))(*gGameUIInterface + 0x58))(0x50, 0x643);
        }
        (*(void (**)(int))(*gGameUIInterface + 0x5c))(state->health);
        hit = ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol);
        t = state->flashTimer - framesThisStep;
        if (t < 0) {
            t = 0;
        }
        state->flashTimer = (u8)t;
        if (hit != 0) {
            if (state->flashTimer == 0) {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                state->flashTimer = 6;
                state->health -= 1;
                if (state->health == 0) {
                    *(u8 *)&state->brainState = 2;
                    andross_setPartSignal(*(int *)&state->andross, 1);
                    Sfx_PlayFromObject(obj, 0x485);
                } else {
                    Sfx_PlayFromObject(obj, 0x484);
                }
            }
        }
        ((GameObject *)obj)->anim.flags &= ~0x4000;
        break;
    case 2:
        if (flag != 0) {
            androssligh_setState(*(int *)&state->lightning, 2, 0);
            (*(void (**)(void))(*gGameUIInterface + 0x64))();
        }
        ((GameObject *)obj)->anim.flags |= 0x4000;
        andross_setPartSignal(*(int *)&state->andross, 8);
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
