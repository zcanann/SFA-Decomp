/*
 * dimwooddoor2 (DLL 0x1CB) - a burnable wooden door object.
 *
 * The door advances its current move animation and slowly rises (its Z
 * eased toward rest by riseSpeed). While intact (burnState > 0) and
 * sitting at map-cue 0x338 past a progress threshold it bleeds off its
 * alpha; otherwise it scans the nearby object list and, on finding a key
 * object (move id 0x18F or 0x1D6), snaps open - resetting the wobble,
 * ringing the placement's gamebit and playing the open sfx.
 *
 * The dll_1CE hatch-door variant lives in its own TU; only its forward
 * declarations appear here.
 */
#include "main/dll/dimwooddoor2placement_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

#define DIMWOODDOOR2_MAP_CUE_OPEN  0x338
#define DIMWOODDOOR2_KEY_MOVE_A    0x18f
#define DIMWOODDOOR2_KEY_MOVE_B    0x1d6


extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E49D0;
extern f32 lbl_803E49D4;
extern f32 lbl_803E49D8;
extern f32 lbl_803E49DC;
extern f32 lbl_803E49E0;
extern f32 lbl_803E49E4;

void dimwooddoor2_free(void)
{
}

void dimwooddoor2_hitDetect(void)
{
}

void dimwooddoor2_release(void)
{
}

void dimwooddoor2_initialise(void)
{
}

void dll_1CE_hitDetect(void);

int dimwooddoor2_getExtraSize(void) { return 0xc; }
int dimwooddoor2_getObjectTypeId(void) { return 0x0; }
int dll_1CE_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void dimwooddoor2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49D0);
}

void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimwooddoor2_init(u8* obj, u8* params)
{
    DimWoodDoor2State* sub;
    ObjHitsPriorityState* hitState;
    f32 fz;
    ((GameObject*)obj)->anim.rotX = (s16)(((s16)(s8)params[0x18]) << 8
    )
    ;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    sub = ((GameObject*)obj)->extra;
    sub->burnState = 3;
    fz = lbl_803E49D4;
    sub->animSpeed = fz;
    sub->riseSpeed = fz;
    if (GameBit_Get(((Dimwooddoor2Placement*)params)->openedGameBit) != 0)
    {
        sub->burnState = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
}

void dll_1CE_init(u8* obj, u8* params);

void dimwooddoor2_update(int* obj)
{
    int* placement = *(int**)&((GameObject*)obj)->anim.placementData;
    DimWoodDoor2State* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    ObjAnim_AdvanceCurrentMove(sub->animSpeed, timeDelta, (int)obj, 0);
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + sub->riseSpeed;
    {
        f32 rs = sub->riseSpeed;
        f32 ceil = lbl_803E49D4;
        if (rs != ceil)
        {
            sub->riseSpeed = rs * lbl_803E49D8;
            sub->riseSpeed = (sub->riseSpeed < ceil) ? sub->riseSpeed : ceil;
        }
    }
    if ((s8)sub->burnState <= 0 && *(s16*)placement == DIMWOODDOOR2_MAP_CUE_OPEN && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E49DC)
    {
        int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 16;
        if (v < 0) v = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = v;
    }
    else
    {
        int found;
        int i;
        int objAddr = (int)obj;
        found = 0;
        for (i = 0; i < (int)*(s8*)(*(int*)(objAddr + 0x58) + 0x10f); i++)
        {
            int o = *(int*)(*(int*)(objAddr + 0x58) + i * 4 + 0x100);
            if (((GameObject*)o)->anim.seqId == DIMWOODDOOR2_KEY_MOVE_A || ((GameObject*)o)->anim.seqId == DIMWOODDOOR2_KEY_MOVE_B)
            {
                found = 1;
                break;
            }
        }
        if (found)
        {
            sub->animSpeed = lbl_803E49E0;
            sub->riseSpeed = lbl_803E49E4;
            sub->burnState = 0;
            GameBit_Set(((Dimwooddoor2Placement*)placement)->openedGameBit, 1);
            Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c);
        }
    }
}
