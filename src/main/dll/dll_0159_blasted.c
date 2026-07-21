/*
 * Blasted (DLL 0x159) - CFBlastedRock/Wall/Tunnel + DRBlastedWall targets.
 * TU = 0x801A27B8..0x801A2BDC (helper fn_801A27B8 + blasted_*).
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/lightmap_api.h"
#include "main/gamebits.h"
#include "main/map_block.h"
#include "main/track_dolphin_map_api.h"
#include "main/dll/dll_0159_blasted.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

#define BLASTED_GAMEBIT_DAMAGE_BASE 0x2de /* base of per-damage-step progress GameBit array */

extern f32 lbl_803E4348;
int lbl_803DDB18;


int fn_801A27B8(GameObject* obj, int id)
{
    MapBlockData* block;

    block = mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if (block == NULL || (block->flags4 & 0x8) == 0)
    {
        return 0;
    }
    {
        int j;
        int i;
        for (i = 0; i < block->polyGroupCount; i++)
        {
            u8* e = mapBlockFn_800606ec(block, i);
            if (id == mapBlockFn_80060678(e))
            {
                *(int*)(e + 0x10) |= 3;
            }
        }
        for (j = 0; j < block->layerCount; j++)
        {
            u8* g = (u8*)fn_8006070C(block, j);
            u8* p;
            int k;
            k = 0;
            p = g;
            for (; k < *(u8*)(g + 0x41); k++)
            {
                if (*(u8*)(p + 0x29) == id)
                {
                    *(int*)(g + 0x3c) |= 2;
                }
                p += 8;
            }
        }
    }
    return 1;
}

int blasted_getExtraSize(void)
{
    return sizeof(BlastedTargetState);
}

int blasted_getObjectTypeId(void)
{
    return 0;
}

void blasted_free(void)
{
}

void blasted_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    BlastedTargetState* state = obj->extra;
    if (visible != 0 && state->triggerFired == 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4348);
    }
}

void blasted_hitDetect(void)
{
}

/* Blasted-target update: once the target's GameBit is latched, fires the
 * map trigger; otherwise scans the model's hit nodes for newly-destroyed
 * priority-5 pieces, records each unique piece, advances the damage model
 * index, and on the final piece latches the GameBit, fires the trigger,
 * and swaps to the destroyed model. */
void blasted_update(GameObject* obj)
{
    int i;
    BlastedTargetSetup* setup = (BlastedTargetSetup*)obj->anim.placementData;
    BlastedTargetState* state = obj->extra;
    s16 total = setup->pieceCount;

    if (state->triggerFired != 0)
    {
        return;
    }
    if ((u32)mainGetBit(setup->completedGameBit) != 0)
    {
        state->triggerFired = fn_801A27B8(obj, setup->triggerId);
        return;
    }
    {
        for (i = 0; i < ((ObjHitsPriorityState*)obj->anim.hitReactState)->priorityHitCount; i++)
        {
            int cnt;
            u32 hitObject;
            int hitPriority;
            int found;
            hitPriority = *(s8*)((u8*)obj->anim.hitReactState + i +
                                 offsetof(ObjHitsPriorityState, priorities));
            hitObject = ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitObjects[i];
            found = 0;
            if (hitPriority != 5)
            {
                continue;
            }
            if (total == 0)
            {
                mainSetBits(setup->completedGameBit, 1);
                return;
            }
            if (hitPriority == 5)
            {
                int k = 0;
                cnt = state->damageStep;
                while (k != cnt)
                {
                    if (hitObject == state->destroyedHitObjects[k++])
                    {
                        k = cnt;
                        found = 1;
                    }
                }
            }
            if (found == 0)
            {
                state->destroyedHitObjects[state->damageStep] = hitObject;
                mainSetBits(state->damageStep + BLASTED_GAMEBIT_DAMAGE_BASE, 0);
                mainSetBits(state->damageStep + (BLASTED_GAMEBIT_DAMAGE_BASE + 1), 1);
                if (setup->progressGameBit != -1)
                {
                    mainSetBits(setup->progressGameBit, state->damageStep + 1);
                }
                lbl_803DDB18 = 0x12c;
                if (state->damageStep + 1 > total)
                {
                    int gbIndex;
                    for (gbIndex = 0; gbIndex < total + 1; gbIndex++)
                    {
                        mainSetBits(gbIndex + BLASTED_GAMEBIT_DAMAGE_BASE, 0);
                    }
                    mainSetBits(setup->completedGameBit, 1);
                    fn_801A27B8(obj, setup->triggerId);
                    Obj_SetActiveModelIndex(obj, 2);
                    state->triggerFired = 1;
                }
                else
                {
                    state->damageStep++;
                    Obj_SetActiveModelIndex(obj, state->damageStep);
                }
            }
        }
    }
}

void blasted_init(GameObject* obj, BlastedTargetSetup* setup)
{
    BlastedTargetState* state = obj->extra;
    ObjHitsPriorityState* hitState;
    s16 gbid;
    u8 progress;

    state->triggerFired = 0;
    objSetSlot(obj, 0x51);
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    hitState->flags = (s16)(hitState->flags | 1);
    state->pieceCount = (u8)setup->pieceCount;
    gbid = setup->progressGameBit;
    if (gbid != -1)
    {
        progress = mainGetBit(gbid);
        state->damageStep = progress;
        if (progress != 0)
        {
            Obj_SetActiveModelIndex(obj, state->damageStep);
        }
    }
    mainSetBits(BLASTED_GAMEBIT_DAMAGE_BASE, 1);
    obj->anim.rotX = (s16)((s32)setup->rotX << 8);
    if ((u32)mainGetBit(setup->completedGameBit) != 0)
    {
        state->triggerFired = fn_801A27B8(obj, setup->triggerId);
    }
}

void blasted_release(void)
{
}

void blasted_initialise(void)
{
}

ObjectDescriptor gBlastedObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)blasted_initialise,
    (ObjectDescriptorCallback)blasted_release,
    0,
    (ObjectDescriptorCallback)blasted_init,
    (ObjectDescriptorCallback)blasted_update,
    (ObjectDescriptorCallback)blasted_hitDetect,
    (ObjectDescriptorCallback)blasted_render,
    (ObjectDescriptorCallback)blasted_free,
    (ObjectDescriptorCallback)blasted_getObjectTypeId,
    blasted_getExtraSize,
};
