/*
 * dimwooddoor2 (DLL 0x1CB) - a burnable wooden door object.
 *
 * The door advances its current move animation and slowly rises (its Z
 * eased toward rest by riseSpeed). Once burned, object setup 0x338 bleeds
 * off its alpha past a progress threshold; otherwise the door scans its
 * proximity list and, on finding a key sequence object (0x18F or 0x1D6),
 * snaps open - resetting the wobble,
 * ringing the placement's gamebit and playing the open sfx.
 *
 * The dll_1CE hatch-door variant lives in its own TU; only its forward
 * declarations appear here.
 */
#include "main/dll/dimwooddoor2placement_struct.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/DIM/dll_01CB_dimwooddoor2.h"
#include "main/object_render.h"

#define DIMWOODDOOR2_FADE_OBJECT_ID 0x338
#define DIMWOODDOOR2_KEY_SEQ_ID_A   0x18f
#define DIMWOODDOOR2_KEY_SEQ_ID_B   0x1d6


int dimwooddoor2_getExtraSize(void)
{
    return 0xc;
}
int dimwooddoor2_getObjectTypeId(void)
{
    return 0x0;
}

void dimwooddoor2_free(void)
{
}

void dimwooddoor2_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dimwooddoor2_hitDetect(void)
{
}

void dimwooddoor2_update(GameObject* obj)
{
    Dimwooddoor2Placement* placement = (Dimwooddoor2Placement*)obj->anim.placementData;
    DimWoodDoor2State* state = obj->extra;
    ObjHitsPriorityState* hitState;
    ObjAnim_AdvanceCurrentMove((int)obj, state->animSpeed, timeDelta, 0);
    obj->anim.localPosZ = obj->anim.localPosZ + state->riseSpeed;
    {
        f32 rs = state->riseSpeed;
        f32 ceil = 0.0f;
        if (rs != ceil)
        {
            state->riseSpeed *= 0.95f;
            state->riseSpeed = (state->riseSpeed < ceil) ? state->riseSpeed : ceil;
        }
    }
    if (state->burnState <= 0 && placement->base.objectId == DIMWOODDOOR2_FADE_OBJECT_ID &&
        obj->anim.currentMoveProgress > 0.9f)
    {
        int v = obj->anim.alpha - framesThisStep * 16;
        if (v < 0)
            v = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = v;
    }
    else
    {
        int found;
        int i;
        found = 0;
        for (i = 0; i < obj->anim.proximityList->count; i++)
        {
            GameObject* other = obj->anim.proximityList->objects[i];
            if (other->anim.seqId == DIMWOODDOOR2_KEY_SEQ_ID_A ||
                other->anim.seqId == DIMWOODDOOR2_KEY_SEQ_ID_B)
            {
                found = 1;
                break;
            }
        }
        if (found)
        {
            state->animSpeed = 0.025f;
            state->riseSpeed = -4.0f;
            state->burnState = 0;
            mainSetBits(placement->openedGameBit, 1);
            Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c);
        }
    }
}

void dimwooddoor2_init(GameObject* obj, Dimwooddoor2Placement* placement)
{
    DimWoodDoor2State* state;
    ObjHitsPriorityState* hitState;
    f32 fz;
    obj->anim.rotX = (s16)(((s16)placement->rotX) << 8);
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    state = obj->extra;
    state->burnState = 3;
    fz = 0.0f;
    state->animSpeed = fz;
    state->riseSpeed = fz;
    if (mainGetBit(placement->openedGameBit) != 0)
    {
        state->burnState = 0;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        obj->anim.alpha = 0;
    }
}

void dimwooddoor2_release(void)
{
}

void dimwooddoor2_initialise(void)
{
}
