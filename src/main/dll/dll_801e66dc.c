/*
 * DLL 0x801E66DC - shopkeeper auxiliary state handlers.
 *
 * Three functions installed into the shopkeeper object's state-machine
 * dispatch tables by dll_0286_spshopkeeper (lbl_803AD068[6]/[7] and
 * lbl_803DDC58):
 *   - fn_801E66DC / fn_801E66E4: trivial "return 0" state slots.
 *   - fn_801E66EC: the active handler. When the linked actor flags a
 *     trigger (arg2+0x27a) and the object's flag word (arg1+0xb0) has
 *     bit 0x800 set, it spawns bone particle effect 2031. It then clears
 *     the actor's queued-state guard byte (state+0x9d6) and, if a queued
 *     state stack (state+0x9b0) is non-empty, pops the next state and
 *     returns it (1-based); otherwise returns 0.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"

#define DLL801E66DC_OBJFLAG_RENDERED 0x800

extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern int Stack_IsEmpty(int stack);          /* voxmaps.c */
extern int Stack_Pop(int stack, int* out);    /* voxmaps.c */

int fn_801E66DC(void) { return 0; }
int fn_801E66E4(void) { return 0; }

int fn_801E66EC(int arg1, int arg2)
{
    GameObject* obj = (GameObject*)arg1;
    int state;
    f32 spawnParam;
    int stk;
    int nextState;

    state = (int)obj->extra;
    spawnParam = lbl_803E59D8;

    if (*(s8*)(arg2 + 0x27a) != 0)
    {
        if ((obj->objectFlags & DLL801E66DC_OBJFLAG_RENDERED) != 0)
        {
            (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 2031, &spawnParam, 80, NULL);
        }
    }

    *(u8*)(state + 0x9d6) = 0;
    *(f32*)(arg2 + 0x280) = lbl_803E59DC;
    if (*(u8*)(state + 0x9d6) == 0)
    {
        stk = *(int*)(state + 0x9b0);
        nextState = 0;
        if (Stack_IsEmpty(stk) == 0)
        {
            Stack_Pop(stk, &nextState);
        }
        return nextState + 1;
    }
    return 0;
}
