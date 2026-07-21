/*
 * cfprisonuncle (DLL 0x14F) - the old CloudRunner imprisoned in the CF
 * dungeon. While caged he head-tracks the player, mutters, and runs
 * his dialog sequence on interaction; once his cage opens (GameBit
 * 0x4D - the cage placement's opened bit on clouddungeon) he runs his
 * release sequence, which thanks Fox (+2 magic here, the Power Room
 * key and the "restore the power to run the wind lifts" exposition via
 * the sequence script). Once he is gone (0x50) only his companion
 * object still renders. Carved from the sandwormBoss 10-DLL container.
 */
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_api.h"
#include "main/objprint_sound_api.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/object_api.h"
#include "main/shader_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/CF/dll_014F_cfprisonuncle.h"
#include "main/dll/player_api.h"

/* release-sequence callback: on the cued trigger, thank Fox with a
 * one-shot +2 magic (the Power Room key comes from the script) */
int CFPrisonUncle_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    CfPrisonUncleState* state = obj->extra;
    if (state->magicGranted != 0)
        return 0;
    if (animUpdate->triggerCommand == 2)
    {
        state->magicGranted = 1;
        playerAddRemoveMagic(Obj_GetPlayerObject(), 2);
    }
    return 0;
}

int cfprisonuncle_getExtraSize(void)
{
    return sizeof(CfPrisonUncleState);
}

int cfprisonuncle_getObjectTypeId(void)
{
    return 0x9;
}

void cfprisonuncle_free(void)
{
}

/* cfprisonuncle_render: render the uncle and/or his companion object
 * depending on the release gamebits, opacity and visibility; while
 * still caged, snap the uncle to the companion's path start first. */
void cfprisonuncle_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    CfPrisonUncleState* state = obj->extra;
    if (mainGetBit(GAMEBIT_CF_UncleFlewOff) != 0)
    {
        if (state->companion != NULL && objUpdateOpacity(state->companion) != 0)
        {
            objRenderModelAndHitVolumes(state->companion, p2, p3, p4, p5, 1.0f);
        }
    }
    else if (mainGetBit(GAMEBIT_CFPerchRelated004D) != 0 && visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        if (state->companion != NULL && objUpdateOpacity(state->companion) != 0)
        {
            objRenderModelAndHitVolumes(state->companion, p2, p3, p4, p5, 1.0f);
        }
    }
    else if (state != NULL && state->companion != NULL)
    {
        if (state->released == 0)
        {
            if (visible != 0)
            {
                if (objUpdateOpacity(state->companion) != 0)
                {
                    objRenderModelAndHitVolumes(state->companion, p2, p3, p4, p5, 1.0f);
                    ObjPath_GetPointWorldPosition(state->companion, 0, &obj->anim.localPosX, &obj->anim.localPosY,
                                                  &obj->anim.localPosZ, 0);
                }
                objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            }
        }
        else
        {
            if (objUpdateOpacity(state->companion) != 0)
            {
                objRenderModelAndHitVolumes(state->companion, p2, p3, p4, p5, 1.0f);
            }
            if (visible != 0)
            {
                objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            }
        }
    }
}

void cfprisonuncle_hitDetect(void)
{
}

/* cfprisonuncle_update: while still caged, drain pending messages,
 * re-acquire the companion object, then head-track the player and
 * mutter (running sequence 1 on interaction); once his cage is open,
 * disable interaction and run the release sequence. */
void cfprisonuncle_update(GameObject* obj)
{
    CfPrisonUncleState* state = obj->extra;
    GameObject* player;
    int msgArg, objectIndex, objectCount, msgType, msgFlag;
    GameObject** objects;
    int i;
    if (state == NULL)
        return;
    if (mainGetBit(GAMEBIT_CF_UncleFlewOff) != 0)
        return;
    if (ObjMsg_Pop(obj, (u32*)&msgType, (u32*)&msgArg, (u32*)&msgFlag) != 0)
    {
        state->companion = NULL;
    }
    if (state->companion == NULL)
    {
        objects = (GameObject**)ObjList_GetObjects(&objectIndex, &objectCount);
        for (i = objectIndex; i < objectCount; i++)
        {
            if (objects[i]->anim.classId == 0x3d)
            {
                state->companion = objects[i];
                i = objectCount;
            }
        }
    }
    ObjTrigger_UpdateIdBlockFlag((int)obj);
    state->released = mainGetBit(GAMEBIT_CFPerchRelated004D);
    if (state->released == 0)
    {
        player = Obj_GetPlayerObject();
        fn_8003ADC4(obj, player, ((CfPrisonUncleState*)obj->extra)->headTrackState, 0x41, 0, 3);
        if ((int)randomGetRange(0, 0x1e) == 0)
        {
            objAudioFn_80039270((int)obj, &state->soundState, 0x297);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            s16* vec;
            fn_8003ADC4(obj, player, ((CfPrisonUncleState*)obj->extra)->headTrackState, 0x41, 0, 3);
            vec = (s16*)objModelGetVecFn_800395d8(obj, 1);
            *vec = -0xaaa;
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
        else
        {
            objAnimFn_80038f38(obj, (char*)&state->soundState);
            ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, (f32)(u32)framesThisStep, 0);
        }
    }
    else
    {
        obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        if (obj->seqIndex == -1)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
}

void cfprisonuncle_init(GameObject* obj)
{
    CfPrisonUncleState* state;
    ObjMsg_AllocQueue(obj, 1);
    obj->animEventCallback = CFPrisonUncle_SeqFn;
    state = obj->extra;
    state->unk64 = 464;
    state->unk68 = 465;
    state->unk70 = 0;
    state->magicGranted = 0;
    if ((u32)mainGetBit(GAMEBIT_CFPerchRelated004D) != 0u)
    {
        mainSetBits(GAMEBIT_CF_UncleFlewOff, 1);
    }
}

void cfprisonuncle_release(void)
{
}

void cfprisonuncle_initialise(void)
{
}

ObjectDescriptor gCFPrisonUncleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfprisonuncle_initialise,
    (ObjectDescriptorCallback)cfprisonuncle_release,
    0,
    (ObjectDescriptorCallback)cfprisonuncle_init,
    (ObjectDescriptorCallback)cfprisonuncle_update,
    (ObjectDescriptorCallback)cfprisonuncle_hitDetect,
    (ObjectDescriptorCallback)cfprisonuncle_render,
    (ObjectDescriptorCallback)cfprisonuncle_free,
    (ObjectDescriptorCallback)cfprisonuncle_getObjectTypeId,
    cfprisonuncle_getExtraSize,
};
