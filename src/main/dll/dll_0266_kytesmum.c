/*
 * kytesmum (DLL 0x266, object type 0x43) - the "Kyte's mum" NPC.
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
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

extern void drcreator_getExtraSize(void);

extern void drcreator_getObjectTypeId(void);

extern void drcreator_free(void);

extern void drcreator_render(void);

extern void drcreator_hitDetect(void);

extern void drcreator_update(void);

extern void drcreator_init(void);

extern void drcreator_release(void);

extern void drcreator_initialise(void);

#define KYTESMUM_OBJGROUP 0x3

#define KYTESMUM_OBJFLAG_HITDETECT_DISABLED 0x2000

#define PAD_BUTTON_A 0x100

#define KYTESMUM_OBJECT_TYPE_ID 0x43
#define KYTESMUM_EXTRA_SIZE 0x6ec

#define KYTESMUM_MODE_QUEST_A 0    /* shares the quest-state path with mode 3 */
#define KYTESMUM_MODE_STATIONARY 1
#define KYTESMUM_MODE_ROAMING 2
#define KYTESMUM_MODE_QUEST_B 3

typedef int (*KytesMumUpdateCallback)(int obj);

typedef struct KytesMumMoveSet
{
    s16 moves[6];
} KytesMumMoveSet;

typedef struct KytesMumSetup
{
    ObjPlacement base;
    s8 yaw;
    s8 mode;
    s16 interactionRange;
    u8 pad1C[0x1e - 0x1c];
    s16 completionGameBit;
    u8 pad20[0x24 - 0x20];
} KytesMumSetup;

typedef struct KytesMumRuntime
{
    u8 pad000[0x654];
    u8 eyeAnimState[0x684 - 0x654];
    u8 modelSoundState[0x6b4 - 0x684];
    u8 animEvents[0x6d0 - 0x6b4];
    void* idleSfxTable;
    KytesMumUpdateCallback updateCallback;
    s16* eventSfxTable;
    KytesMumMoveSet* moveSet;
    f32 animSpeed;
    s16 idleSfxTimer;
    u8 questComplete;
} KytesMumRuntime;

typedef struct KytesMumObject
{
    union {
        ObjAnimComponent anim;
        struct {
            s16 yaw;
            u8 pad02[0x4c - 0x2];
            KytesMumSetup* setup;
            u8 pad50[0xa0 - 0x50];
            s16 currentMove;
            u8 padA2[0xaf - 0xa2];
            u8 flagsAF;
        };
    };
    u16 objectFlags;
    u8 padB2[0xb8 - 0xb2];
    KytesMumRuntime* runtime;
    void* interactionCallback;
} KytesMumObject;

STATIC_ASSERT(sizeof(KytesMumSetup) == 0x24);
STATIC_ASSERT(offsetof(KytesMumSetup, yaw) == 0x18);
STATIC_ASSERT(offsetof(KytesMumSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(KytesMumSetup, interactionRange) == 0x1A);
STATIC_ASSERT(offsetof(KytesMumSetup, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(KytesMumObject, anim) == 0x00);
STATIC_ASSERT(offsetof(KytesMumObject, yaw) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(KytesMumObject, setup) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(KytesMumObject, currentMove) == offsetof(ObjAnimComponent, currentMove));
STATIC_ASSERT(offsetof(KytesMumObject, flagsAF) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(KytesMumObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(KytesMumObject, runtime) == 0xB8);
STATIC_ASSERT(offsetof(KytesMumObject, interactionCallback) == 0xBC);

int kytesmum_getExtraSize(void) { return KYTESMUM_EXTRA_SIZE; }

int kytesmum_getObjectTypeId(void) { return KYTESMUM_OBJECT_TYPE_ID; }

void kytesmum_hitDetect(void)
{
}

void kytesmum_initialise(void)
{
}

void kytesmum_release(void)
{
}

void kytesmum_update(int obj)
{
    KytesMumObject* kytesMum = (KytesMumObject*)obj;
    KytesMumRuntime* runtime = kytesMum->runtime;
    KytesMumSetup* setup = kytesMum->setup;
    f32 nearDist;
    s16 diff;
    int absDiff;
    short moveIdx;
    int nearest;

    nearDist = gKytesMumNearestSearchDist;
    if (runtime->questComplete == 0)
    {
        if (runtime->updateCallback(obj) != 0)
        {
            GameBit_Set(setup->completionGameBit, 1);
            runtime->questComplete = 1;
        }
    }
    diff = (s16)((setup->yaw << 8) - (u16)kytesMum->yaw);
    if ((s16)diff > 0x8000)
    {
        diff = (s16)((diff - 0x10000) + 1);
    }
    if ((s16)diff < -0x8000)
    {
        diff = (s16)((diff + 0x10000) - 1);
    }
    if (diff != 0)
    {
        fn_80137948(sKytesMumYawDiffMessage);
        if (kytesMum->currentMove != runtime->moveSet->moves[2])
        {
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[2], lbl_803E698C, 0);
        }
        kytesMum->yaw = (s16)(kytesMum->yaw + ((diff + 1) >> 4));
        runtime->animSpeed = lbl_803E699C * (f32)(diff / 1024);
        absDiff = diff;
        absDiff = (absDiff >= 0) ? absDiff : -absDiff;
        if (absDiff < 0x400)
        {
            kytesMum->yaw = (s16)(setup->yaw << 8);
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[randomGetRange(0, 1)],
                                   lbl_803E698C, 0);
            runtime->animSpeed = lbl_803E699C;
        }
    }
    if ((s16)(runtime->idleSfxTimer -= framesThisStep) < 0)
    {
        runtime->idleSfxTimer = randomGetRange(0x32, 0x1f4);
        objSoundFn_800392f0(obj, (int)runtime->modelSoundState,
                            (void*)((char*)runtime->idleSfxTable + randomGetRange(0, 3) * 6), 0);
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, runtime->animSpeed, timeDelta,
                                                                    (ObjAnimEventList*)runtime->animEvents) != 0)
    {
        moveIdx = (s16)((int)randomGetRange(0, 7) != 0 ? 0 : ((int)randomGetRange(0, 1) != 0 ? 1 : 4));
        ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[moveIdx], lbl_803E698C, 0);
        runtime->animSpeed = (moveIdx == 0) ? lbl_803E699C : lbl_803E69A0;
    }
    kytesmum_playAnimationEventSfx(obj, runtime->animEvents, runtime->eventSfxTable);
    characterDoEyeAnims(obj, runtime->eyeAnimState);
    objAnimFn_80038f38(obj, runtime->modelSoundState);
    nearest = ObjGroup_FindNearestObject(1, obj, &nearDist);
    if ((void*)nearest != NULL)
    {
        (*(void (**)(int, int, int, int))(*(int*)(*(int*)&((GameObject*)nearest)->anim.dll) + 0x28))(
            nearest, obj, 1, 2);
    }
}

int kytesmum_idleCallback(void)
{
    Obj_GetPlayerObject();
    return 0;
}

void kytesmum_render(void* obj, int p2, int p3, int p4, int p5, char visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6994);
    }
}

void kytesmum_free(int obj)
{
    KytesMumSetup* setup = ((KytesMumObject*)obj)->setup;
    if (setup->mode != 0)
    {
        ObjGroup_RemoveObject(obj, KYTESMUM_OBJGROUP);
    }
}

int kytesmum_spawnInteractionCallback(int obj)
{
    Obj_GetPlayerObject();
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        if ((*gGameUIInterface)->isCurrentTriggerClear() == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        return 0; /* callback always returns 0; the interacted path carries no result */
    }
    return 0;
}

int kytesmum_updateInteractionRangeCallback(int obj, int unused, u8* arg)
{
    int* player = Obj_GetPlayerObject();
    KytesMumSetup* setup = ((KytesMumObject*)obj)->setup;
    f32 dist;
    ObjHits_DisableObject(obj);
    dist = Vec_xzDistance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
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

int kytesmum_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    KytesMumSetup* setup;
    int i;
    KytesMumRuntime* runtime = ((KytesMumObject*)obj)->runtime;
    Obj_GetPlayerObject();
    setup = ((KytesMumObject*)obj)->setup;
    ObjHits_EnableObject(obj);
    ObjHits_RegisterActiveHitVolumeObject(obj);
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1 && setup->mode != 0)
        {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    {
        int move2 = runtime->moveSet->moves[2];
        int result = !dll_2E_func07(obj, (u8*)animUpdate, (char*)runtime, move2, move2);
        return !result;
    }
}

void kytesmum_init(int obj, KytesMumSetup* setup)
{
    KytesMumMoveSet* moveSets = (KytesMumMoveSet*)gKytesMumMoveSets;
    KytesMumObject* kytesMum = (KytesMumObject*)obj;
    KytesMumRuntime* runtime = kytesMum->runtime;
    int startMove;
    kytesMum->yaw = (s16)(setup->yaw << 8);
    if (GameBit_Get(setup->completionGameBit) != 0)
    {
        runtime->questComplete = 1;
    }
    switch (setup->mode)
    {
    case KYTESMUM_MODE_STATIONARY:
        runtime->moveSet = &moveSets[0];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_spawnInteractionCallback;
        runtime->eventSfxTable = 0;
        kytesMum->interactionCallback = kytesmum_animEventCallback;
        break;
    case KYTESMUM_MODE_ROAMING:
        runtime->moveSet = &moveSets[1];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateNearPlayerCallback;
        runtime->eventSfxTable = (s16*)&gKytesMumRoamEventSfxTable;
        ObjGroup_AddObject(obj, KYTESMUM_OBJGROUP);
        if (runtime->questComplete != 0)
        {
            Obj_RemoveFromUpdateList(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        kytesMum->interactionCallback = kytesmum_animEventCallback;
        break;
    case KYTESMUM_MODE_QUEST_A:
    case KYTESMUM_MODE_QUEST_B:
        GameBit_Set(0x934, 0);
        GameBit_Set(0x933, 0);
        runtime->moveSet = &moveSets[2];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateQuestStateCallback;
        runtime->eventSfxTable = (s16*)&lbl_803DC2D0;
        kytesMum->interactionCallback = kytesmum_updateInteractionRangeCallback;
        break;
    }
    runtime->idleSfxTable = &moveSets[3];
    runtime->animSpeed = lbl_803E699C;
    startMove = randomGetRange(0, 1) * 2;
    startMove = *(s16*)((char*)runtime->moveSet + startMove);
    ObjAnim_SetCurrentMove(obj, startMove, lbl_803E698C, 0);
    kytesMum->objectFlags |= KYTESMUM_OBJFLAG_HITDETECT_DISABLED;
}

int kytesmum_updateNearPlayerCallback(int obj, int unused, u8* arg)
{
    int* player = Obj_GetPlayerObject();
    int* tricky = getTrickyObject();
    KytesMumRuntime* runtime = ((KytesMumObject*)obj)->runtime;
    if (objGetAnimState80A(player) == 0x40)
    {
        return 1;
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
    {
        if ((*gGameUIInterface)->isCurrentTriggerClear() == 0)
        {
            buttonDisable(0, PAD_BUTTON_A);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0xb;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 4;
            (*gObjectTriggerInterface)
                ->runSequence(randomGetRange(0, 1), (void*)obj, -1);
        }
    }
    if ((tricky != 0 && Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((char*)tricky + 0x18)) <
            gKytesMumFleeDistance) ||
        (player != 0 && Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            gKytesMumFleeDistance))
    {
        if (((GameObject*)obj)->anim.currentMove != 9)
        {
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E698C, 0);
            runtime->animSpeed = lbl_803E6990;
            if (tricky != 0)
            {
                (*(void (**)(int*, int, int))((char*)*(void**)*(void**)((char*)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
        }
    }
    if (((GameObject*)obj)->anim.currentMove == 9)
    {
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0xb;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 4;
        ObjHits_SetHitVolumeSlot(obj, 0xb, 4, 7);
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    return 0;
}

int kytesmum_updateQuestStateCallback(int obj, int unused, u8* arg)
{
    int next;
    int questBits[3];
    int triggerIds[3];
    int count;
    KytesMumRuntime* runtime;
    *(QuestTriple*)questBits = *(QuestTriple*)gKytesMumQuestBits;
    *(QuestTriple*)triggerIds = *(QuestTriple*)gKytesMumTriggerIds;
    count = 0;
    Obj_GetPlayerObject();
    runtime = (KytesMumRuntime*)((GameObject*)obj)->extra;
    saveGame_saveObjectPos(obj);
    ObjHits_DisableObject(obj);
    for (; questBits[count] != -1 && GameBit_Get(questBits[count]) != 0; count++)
    {
        ;
    }
    if (count > 0)
    {
        runtime->idleSfxTable = gKytesMumQuestIdleSfxTable;
    }
    GameBit_Set(0xeb9, count == 1);
    next = triggerIds[count];
    if (next == -1)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        return 1;
    }
    if (ObjTrigger_IsSet(obj) != 0)
    {
        ((GameObject*)obj)->animEventCallback = kytesmum_idleCallback;
        (*gObjectTriggerInterface)->runSequence(next, (void*)obj, -1);
    }
    return 0;
}

#pragma optimization_level 2
void kytesmum_playAnimationEventSfx(int obj, u8* arg, s16* sfxData)
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
        case 1:
            if (sfxData != 0)
            {
                Sfx_PlayFromObject(obj, sfxData[1]);
            }
            break;
        case 2:
            flags |= 1;
            break;
        case 3:
            flags |= 2;
            break;
        case 4:
            flags |= 4;
            break;
        case 5:
            flags |= 8;
            break;
        case 6:
        case 7:
            break;
        }
    }
    if (flags != 0 && sfxData != 0)
    {
        Sfx_PlayFromObject(obj, sfxData[3]);
    }
}
#pragma reset

u8 gKytesMumMoveSets[] =
{
    0x00, 0x00, 0x02, 0x06, 0x01, 0x27, 0x00, 0x00, 0x03, 0x0A, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x05, 0x00, 0x01, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x35, 0x10, 0x00, 0x00, 0x00, 0x03, 0x36, 0x10, 0x00, 0x00, 0x00,
    0x03, 0x37, 0x05, 0x00, 0x00, 0x00, 0x03, 0x38, 0x05, 0x00, 0x00, 0x00,
};

int gKytesMumQuestIdleSfxTable[] = {
    0x02921000, 0x00000292, 0x10000000, 0x02920500, 0x00000292, 0x05000000,
};

char sKytesMumYawDiffMessage[] = " YAW DIFF ";

/* descriptor/ptr table auto 0x8032a878-0x8032a8b0 */
u32 gDrCreatorObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)drcreator_initialise, (u32)drcreator_release, 0x00000000, (u32)drcreator_init, (u32)drcreator_update, (u32)drcreator_hitDetect, (u32)drcreator_render, (u32)drcreator_free, (u32)drcreator_getObjectTypeId, (u32)drcreator_getExtraSize };
