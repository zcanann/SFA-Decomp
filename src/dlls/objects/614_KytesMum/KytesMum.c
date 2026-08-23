/*
 * KytesMum (DLL 614, object type 0x43) - the "Kyte's mum" NPC.
 *
 * The placement's mode byte selects one of three behaviours, wired up in
 * kytesmum_init:
 *   mode 1     - stationary NPC; interacting runs trigger sequence 0
 *                (kytesmum_spawnInteractionCallback).
 *   mode 2     - roams; flees toward Tricky/the player when they get close
 *                and runs a random greeting sequence on contact
 *                (kytesmum_updateNearPlayerCallback). Added to obj group 3.
 *   mode 0 / 3 - quest-giver; walks a fixed quest-bit table and runs the
 *                matching trigger sequence (kytesmum_updateQuestStateCallback).
 *
 * Every frame kytesmum_update faces the placement yaw, services the idle
 * sound timer, advances the current animation move (picking a new random
 * idle/look move at the end of a move), plays anim-event sfx, runs eye and
 * model-sound anims, and forwards a contact callback to the nearest obj in
 * group 1. Completing the active callback sets the placement's completion
 * game bit.
 */
#include "dlls/object_descriptor.h"
#include "main/dll/dll_0266_kytesmum.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/debug.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/game_ui_interface.h"
#include "main/objtype.h"
#include "main/obj_trigger.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "game/objects/object_setup.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/vecmath.h"
#include "dolphin/pad.h"
#include "main/dll/player_api.h"
#include "main/dll/savegame_object_api.h"
#include "main/object_update_list.h"
#include "main/pad_api.h"
#include "sys/objects/lifecycle.h"
#include "main/objseq.h"

s16 gKytesMumRoamEventSfxTable[4] = {0x1B4, 0x1B5, 0x1B6, 0};
s16 gKytesMumQuestEventSfxTable[4] = {0x336, 0x337, 0x337, 0};

#define KYTESMUM_OBJGROUP        0x3
#define KYTESMUM_TARGET_OBJGROUP 0x1

#define KYTESMUM_OBJECT_TYPE_ID  0x43
#define KYTESMUM_EXTRA_SIZE      0x6ec
#define KYTESMUM_HIT_VOLUME_SLOT 0xb

#define KYTESMUM_MODE_QUEST_A    0 /* shares the quest-state path with mode 3 */
#define KYTESMUM_MODE_STATIONARY 1
#define KYTESMUM_MODE_ROAMING    2
#define KYTESMUM_MODE_QUEST_B    3

const s32 gKytesMumQuestBits[3] = {0x43, 0x30A, -1};
const s32 gKytesMumTriggerIds[3] = {0, 2, -1};

int kytesmum_updateInteractionRangeCallback(GameObject* obj, int unused, u8* arg)
{
    GameObject* player = Obj_GetPlayerObject();
    KytesMumSetup* setup = (KytesMumSetup*)obj->anim.placementData;
    f32 dist;
    ObjHits_DisableObject(obj);
    dist = Vec_xzDistance(&player->anim.worldPosX, &(obj)->anim.worldPosX);
    if (dist < setup->interactionRange)
    {
        arg[0x90] |= 4;
    }
    else
    {
        arg[0x90] &= ~4;
    }
    return 0;
}

int kytesmum_idleCallback(void)
{
    Obj_GetPlayerObject();
    return 0;
}

int kytesmum_updateQuestStateCallback(GameObject* obj, int unused, u8* arg)
{
    int next;
    int questBits[3];
    int triggerIds[3];
    int count;
    KytesMumRuntime* runtime;
    *(KytesMumQuestTriple*)questBits = *(KytesMumQuestTriple*)gKytesMumQuestBits;
    *(KytesMumQuestTriple*)triggerIds = *(KytesMumQuestTriple*)gKytesMumTriggerIds;
    count = 0;
    Obj_GetPlayerObject();
    runtime = (KytesMumRuntime*)(obj)->extra;
    saveGame_saveObjectPos(obj);
    ObjHits_DisableObject(obj);
    for (; questBits[count] != -1 && mainGetBit(questBits[count]) != 0; count++)
    {
        ;
    }
    if (count > 0)
    {
        runtime->idleSfxTable = (ObjSoundDef*)gKytesMumQuestIdleSfxTable;
    }
    mainSetBits(0xeb9, count == 1);
    next = triggerIds[count];
    if (next == -1)
    {
        (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return 1;
    }
    if (ObjTrigger_IsSet(obj) != 0)
    {
        (obj)->animEventCallback = kytesmum_idleCallback;
        (*gObjectTriggerInterface)->runSequence(next, (void*)obj, -1);
    }
    return 0;
}
u8 gKytesMumMoveSets[] = {
    0x00, 0x00, 0x02, 0x06, 0x01, 0x27, 0x00, 0x00, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x35, 0x10, 0x00, 0x00, 0x00, 0x03, 0x36, 0x10,
    0x00, 0x00, 0x00, 0x03, 0x37, 0x05, 0x00, 0x00, 0x00, 0x03, 0x38, 0x05, 0x00, 0x00, 0x00,
};
int gKytesMumQuestIdleSfxTable[] = {
    0x02921000, 0x00000292, 0x10000000, 0x02920500, 0x00000292, 0x05000000,
};
ObjectDescriptor gKytesMumObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kytesmum_initialise,
    (ObjectDescriptorCallback)kytesmum_release,
    0,
    (ObjectDescriptorCallback)kytesmum_init,
    (ObjectDescriptorCallback)kytesmum_update,
    (ObjectDescriptorCallback)kytesmum_hitDetect,
    (ObjectDescriptorCallback)kytesmum_render,
    (ObjectDescriptorCallback)kytesmum_free,
    (ObjectDescriptorCallback)kytesmum_getObjectTypeId,
    kytesmum_getExtraSize,
};

void kytesmum_playAnimationEventSfx(GameObject* obj, u8* arg, s16* sfxData)
{
    int i;
    u8 flags = 0;
    for (i = 0; i < (s8)arg[0x1b]; i++)
    {
        switch (*(s8*)(arg + i + 0x13))
        {
        case 0:
            if (sfxData != 0)
            {
                Sfx_PlayFromObject(obj, sfxData[0]);
            }
            break;
        case 7:
            if (sfxData != 0)
            {
                Sfx_PlayFromObject(obj, sfxData[1]);
            }
            break;
        case 1:
            flags |= 1;
            break;
        case 2:
            flags |= 2;
            break;
        case 3:
            flags |= 4;
            break;
        case 4:
            flags |= 8;
            break;
        case 5:
        case 6:
            break;
        }
    }
    if (flags != 0 && sfxData != 0)
    {
        Sfx_PlayFromObject(obj, sfxData[3]);
    }
}

int kytesmum_updateNearPlayerCallback(GameObject* obj, int unused, u8* arg)
{
    GameObject* player = Obj_GetPlayerObject();
    GameObject* tricky = (GameObject*)getTrickyObject();
    KytesMumRuntime* runtime = obj->extra;
    if (objGetAnimState80A(player) == 0x40)
    {
        return 1;
    }
    if (((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isAnyItemBeingUsed() == 0)
        {
            buttonDisable(0, PAD_BUTTON_A);
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = 0xb;
            ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = 4;
            (*gObjectTriggerInterface)->runSequence(randomGetRange(0, 1), (void*)obj, -1);
        }
    }
    if ((tricky != 0 && Vec_xzDistance(&(obj)->anim.worldPosX, &tricky->anim.worldPosX) < 40.0f) ||
        (player != 0 &&
         Vec_xzDistance(&(obj)->anim.worldPosX, &player->anim.worldPosX) < 40.0f))
    {
        if ((obj)->anim.currentMove != 9)
        {
            ObjAnim_SetCurrentMove(obj, 9, 0.0f, 0);
            runtime->animSpeed = 0.006f;
            if (tricky != 0)
            {
                TRICKY_INTERFACE(tricky)->commandPlayBall(tricky, 0, NULL);
            }
        }
    }
    if ((obj)->anim.currentMove == 9)
    {
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = 0xb;
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = 4;
        ObjHits_SetHitVolumeSlot(&obj->anim, KYTESMUM_HIT_VOLUME_SLOT, 4, 7);
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    return 0;
}

int kytesmum_spawnInteractionCallback(GameObject* obj)
{
    Obj_GetPlayerObject();
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        if ((*gGameUIInterface)->isAnyItemBeingUsed() == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        return 0; /* callback always returns 0; the interacted path carries no result */
    }
    return 0;
}

int kytesmum_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    KytesMumRuntime* runtime = obj->extra;
    KytesMumSetup* setup;
    int i;
    Obj_GetPlayerObject();
    setup = (KytesMumSetup*)obj->anim.placementData;
    ObjHits_EnableObject(obj);
    ObjHits_RegisterActiveHitVolumeObject(obj);
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1 && setup->mode != 0)
        {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    {
        int move2 = runtime->moveSet->moves[2];
        int result = !dll_2E_updateSequenceTurn(obj, animUpdate, (MoveLibState*)runtime, move2, move2);
        return !result;
    }
}

int kytesmum_getExtraSize(void)
{
    return KYTESMUM_EXTRA_SIZE;
}

int kytesmum_getObjectTypeId(void)
{
    return KYTESMUM_OBJECT_TYPE_ID;
}

void kytesmum_free(GameObject* obj)
{
    KytesMumSetup* setup = (KytesMumSetup*)(obj)->anim.placementData;
    if (setup->mode != 0)
    {
        objFreeObjectType(obj, KYTESMUM_OBJGROUP);
    }
}

void kytesmum_render(GameObject* obj, int p2, int p3, int p4, int p5, char visible)
{
    f32 scale = 1.0f;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale);
    }
}

void kytesmum_hitDetect(void)
{
}

void kytesmum_update(GameObject* obj)
{
    KytesMumRuntime* runtime = obj->extra;
    KytesMumSetup* setup = (KytesMumSetup*)obj->anim.placementData;
    f32 nearDist;
    s16 diff;
    int absDiff;
    short moveIdx;
    GameObject* nearest;

    nearDist = 200.0f;
    if (runtime->questComplete == 0)
    {
        if (runtime->updateCallback((int)obj) != 0)
        {
            mainSetBits(setup->completionGameBit, 1);
            runtime->questComplete = 1;
        }
    }
    diff = (s16)((setup->yaw << 8) - (u16)obj->anim.rotX);
    if (diff > 0x8000)
    {
        diff = (s16)((diff - 0x10000) + 1);
    }
    if (diff < -0x8000)
    {
        diff = (s16)((diff + 0x10000) - 1);
    }
    if (diff != 0)
    {
        logPrintf(sKytesMumYawDiffMessage);
        if (obj->anim.currentMove != runtime->moveSet->moves[2])
        {
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[2], 0.0f, 0);
        }
        obj->anim.rotX = (s16)(obj->anim.rotX + ((diff + 1) >> 4));
        runtime->animSpeed = 0.01f * (f32)(diff / 1024);
        absDiff = diff;
        absDiff = (absDiff >= 0) ? absDiff : -absDiff;
        if (absDiff < 0x400)
        {
            obj->anim.rotX = (s16)(setup->yaw << 8);
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[randomGetRange(0, 1)], 0.0f, 0);
            runtime->animSpeed = 0.01f;
        }
    }
    if ((s16)(runtime->idleSfxTimer -= framesThisStep) < 0)
    {
        runtime->idleSfxTimer = randomGetRange(0x32, 0x1f4);
        objSoundStartFromDef(obj, &runtime->modelSoundState,
                            &runtime->idleSfxTable[randomGetRange(0, 3)], 0);
    }
    if (ObjAnim_AdvanceCurrentMove(obj, runtime->animSpeed, timeDelta,
                                                                    (ObjAnimEventList*)runtime->animEvents) != 0)
    {
        moveIdx = (s16)(randomGetRange(0, 7) != 0 ? 0 : (randomGetRange(0, 1) != 0 ? 1 : 4));
        ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[moveIdx], 0.0f, 0);
        runtime->animSpeed = (moveIdx == 0) ? 0.01f : 0.005f;
    }
    kytesmum_playAnimationEventSfx(obj, runtime->animEvents, runtime->eventSfxTable);
    characterDoEyeAnims(obj, &runtime->eyeAnimState);
    objSoundUpdateMouth(obj, &runtime->modelSoundState);
    nearest = objGetNearestTypeTo(KYTESMUM_TARGET_OBJGROUP, obj, &nearDist);
    if (nearest != NULL)
    {
        TRICKY_INTERFACE(nearest)
            ->sideCommandEnable(nearest, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                TRICKY_COMMAND_TYPE_DISTRACT);
    }
}

void kytesmum_init(GameObject* obj, KytesMumSetup* setup)
{
    KytesMumMoveSet* moveSets = (KytesMumMoveSet*)gKytesMumMoveSets;
    KytesMumRuntime* runtime = obj->extra;
    int startMove;
    obj->anim.rotX = (s16)(setup->yaw << 8);
    if (mainGetBit(setup->completionGameBit) != 0)
    {
        runtime->questComplete = 1;
    }
    switch (setup->mode)
    {
    case KYTESMUM_MODE_STATIONARY:
        runtime->moveSet = &moveSets[0];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_spawnInteractionCallback;
        runtime->eventSfxTable = 0;
        obj->animEventCallback = kytesmum_animEventCallback;
        break;
    case KYTESMUM_MODE_ROAMING:
        runtime->moveSet = &moveSets[1];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateNearPlayerCallback;
        runtime->eventSfxTable = (s16*)&gKytesMumRoamEventSfxTable;
        objAddObjectType(obj, KYTESMUM_OBJGROUP);
        if (runtime->questComplete != 0)
        {
            Obj_RemoveFromUpdateList(obj);
            (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        obj->animEventCallback = kytesmum_animEventCallback;
        break;
    case KYTESMUM_MODE_QUEST_A:
    case KYTESMUM_MODE_QUEST_B:
        mainSetBits(0x934, 0);
        mainSetBits(0x933, 0);
        runtime->moveSet = &moveSets[2];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateQuestStateCallback;
        runtime->eventSfxTable = gKytesMumQuestEventSfxTable;
        obj->animEventCallback = kytesmum_updateInteractionRangeCallback;
        break;
    }
    runtime->idleSfxTable = (ObjSoundDef*)&moveSets[3];
    runtime->animSpeed = 0.01f;
    startMove = randomGetRange(0, 1) * 2;
    startMove = *(s16*)((char*)runtime->moveSet + startMove);
    ObjAnim_SetCurrentMove(obj, startMove, 0.0f, 0);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void kytesmum_release(void)
{
}
void kytesmum_initialise(void)
{
}

char sKytesMumYawDiffMessage[] = " YAW DIFF ";
