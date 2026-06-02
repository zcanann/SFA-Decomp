#include "main/dll/DR/dr_shared.h"

typedef int (*KytesMumUpdateCallback)(int obj);

typedef struct KytesMumMoveSet {
    s16 moves[6];
} KytesMumMoveSet;

typedef struct KytesMumSetup {
    u8 pad00[0x18];
    s8 yaw;
    s8 mode;
    s16 interactionRange;
    u8 pad1C[0x1e - 0x1c];
    s16 completionGameBit;
} KytesMumSetup;

typedef struct KytesMumRuntime {
    u8 pad000[0x654];
    u8 eyeAnimState[0x684 - 0x654];
    u8 modelSoundState[0x6b4 - 0x684];
    u8 animEvents[0x6d0 - 0x6b4];
    void *idleSfxTable;
    KytesMumUpdateCallback updateCallback;
    s16 *eventSfxTable;
    KytesMumMoveSet *moveSet;
    f32 animSpeed;
    s16 idleSfxTimer;
    u8 questComplete;
} KytesMumRuntime;

typedef struct KytesMumObject {
    s16 yaw;
    u8 pad02[0x4c - 0x2];
    KytesMumSetup *setup;
    u8 pad50[0xa0 - 0x50];
    s16 currentMove;
    u8 padA2[0xaf - 0xa2];
    u8 flagsAF;
    u16 objectFlags;
    u8 padB2[0xb8 - 0xb2];
    KytesMumRuntime *runtime;
    void *interactionCallback;
} KytesMumObject;

int kytesmum_getExtraSize(void) { return 0x6ec; }

int kytesmum_getObjectTypeId(void) { return 0x43; }

void kytesmum_hitDetect(void) {}

void kytesmum_initialise(void) {}

void kytesmum_release(void) {}

#pragma scheduling off
#pragma peephole off
void kytesmum_update(int obj) {
    KytesMumObject *kytesMum = (KytesMumObject *)obj;
    KytesMumRuntime *runtime = kytesMum->runtime;
    KytesMumSetup *setup = kytesMum->setup;
    f32 nearDist;
    int diff;
    int moveIdx;
    int nearest;

    nearDist = lbl_803E6998;
    if (runtime->questComplete == 0) {
        if (runtime->updateCallback(obj) != 0) {
            GameBit_Set(setup->completionGameBit, 1);
            runtime->questComplete = 1;
        }
    }
    diff = (s16)((setup->yaw << 8) - (u16)kytesMum->yaw);
    if (diff > 0x8000) {
        diff -= 0xFFFF;
    }
    if (diff < -0x8000) {
        diff += 0xFFFF;
    }
    if (diff != 0) {
        fn_80137948(sKytesMumYawDiffMessage);
        if (kytesMum->currentMove != runtime->moveSet->moves[2]) {
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[2], lbl_803E698C, 0);
        }
        kytesMum->yaw = (s16)(kytesMum->yaw + ((diff + 1) >> 4));
        runtime->animSpeed = lbl_803E699C * (f32)(diff / 1024);
        if (diff < 0) {
            diff = -diff;
        }
        if (diff < 0x400) {
            kytesMum->yaw = (s16)(setup->yaw << 8);
            ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[randomGetRange(0, 1)],
                                   lbl_803E698C, 0);
            runtime->animSpeed = lbl_803E699C;
        }
    }
    runtime->idleSfxTimer -= framesThisStep;
    if (runtime->idleSfxTimer < 0) {
        runtime->idleSfxTimer = randomGetRange(0x32, 0x1f4);
        objSoundFn_800392f0(obj, (int)runtime->modelSoundState,
                            (void *)((char *)runtime->idleSfxTable + randomGetRange(0, 3) * 6), 0);
    }
    if (ObjAnim_AdvanceCurrentMove(runtime->animSpeed, timeDelta, obj,
                                   (ObjAnimEventList *)runtime->animEvents) != 0) {
        if (randomGetRange(0, 7) != 0) {
            moveIdx = 0;
        } else if (randomGetRange(0, 1) != 0) {
            moveIdx = 1;
        } else {
            moveIdx = 4;
        }
        ObjAnim_SetCurrentMove(obj, runtime->moveSet->moves[moveIdx], lbl_803E698C, 0);
        if (moveIdx == 0) {
            runtime->animSpeed = lbl_803E699C;
        } else {
            runtime->animSpeed = lbl_803E69A0;
        }
    }
    kytesmum_playAnimationEventSfx(obj, runtime->animEvents, runtime->eventSfxTable);
    characterDoEyeAnims(obj, runtime->eyeAnimState);
    objAnimFn_80038f38(obj, runtime->modelSoundState);
    nearest = ObjGroup_FindNearestObject(1, obj, &nearDist);
    if (nearest != 0) {
        (*(void (**)(int, int, int, int))(*(int *)(*(int *)((char *)nearest + 0x68)) + 0x28))(
            nearest, obj, 1, 2);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_idleCallback(void) {
    Obj_GetPlayerObject();
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kytesmum_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6994);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kytesmum_free(int obj) {
    KytesMumSetup *setup = ((KytesMumObject *)obj)->setup;
    if (setup->mode != 0) {
        ObjGroup_RemoveObject(obj, 0x3);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_spawnInteractionCallback(int obj) {
    Obj_GetPlayerObject();
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        buttonDisable(0, 0x100);
        if ((*(int (**)(void *))((char *)*gGameUIInterface + 0x1c))(*gGameUIInterface) == 0) {
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(0, obj, -1);
        }
        return 0;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_updateInteractionRangeCallback(int obj, int unused, u8 *arg) {
    int *player = Obj_GetPlayerObject();
    KytesMumSetup *setup = ((KytesMumObject *)obj)->setup;
    f32 dist;
    ObjHits_DisableObject(obj);
    dist = Vec_xzDistance((f32 *)((char *)player + 0x18), (f32 *)((char *)obj + 0x18));
    if (dist < (f32)setup->interactionRange) {
        arg[0x90] |= 4;
    } else {
        arg[0x90] &= ~4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_animEventCallback(int obj, int unused, u8 *arg) {
    KytesMumRuntime *runtime = ((KytesMumObject *)obj)->runtime;
    KytesMumSetup *setup;
    int i;
    Obj_GetPlayerObject();
    setup = ((KytesMumObject *)obj)->setup;
    ObjHits_EnableObject(obj);
    ObjHits_RegisterActiveHitVolumeObject(obj);
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1 && setup->mode != 0) {
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    }
    return !!dll_2E_func07(obj, arg, (char *)runtime, runtime->moveSet->moves[2], runtime->moveSet->moves[2]);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kytesmum_init(int obj, char *arg) {
    KytesMumMoveSet *moveSets = (KytesMumMoveSet *)lbl_8032A7C0;
    KytesMumObject *kytesMum = (KytesMumObject *)obj;
    KytesMumRuntime *runtime = kytesMum->runtime;
    KytesMumSetup *setup = (KytesMumSetup *)arg;
    int r;
    kytesMum->yaw = (s16)(setup->yaw << 8);
    if (GameBit_Get(setup->completionGameBit) != 0) {
        runtime->questComplete = 1;
    }
    switch (setup->mode) {
    case 1:
        runtime->moveSet = &moveSets[0];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_spawnInteractionCallback;
        runtime->eventSfxTable = 0;
        kytesMum->interactionCallback = (void *)kytesmum_animEventCallback;
        break;
    case 2:
        runtime->moveSet = &moveSets[1];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateNearPlayerCallback;
        runtime->eventSfxTable = (s16 *)&lbl_803DC2C8;
        ObjGroup_AddObject(obj, 0x3);
        if (runtime->questComplete != 0) {
            objRemoveFromListFn_8002ce88(obj);
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        kytesMum->interactionCallback = (void *)kytesmum_animEventCallback;
        break;
    case 0:
    case 3:
        GameBit_Set(0x934, 0);
        GameBit_Set(0x933, 0);
        runtime->moveSet = &moveSets[2];
        runtime->updateCallback = (KytesMumUpdateCallback)kytesmum_updateQuestStateCallback;
        runtime->eventSfxTable = (s16 *)&lbl_803DC2D0;
        kytesMum->interactionCallback = (void *)kytesmum_updateInteractionRangeCallback;
        break;
    }
    runtime->idleSfxTable = &moveSets[3];
    runtime->animSpeed = lbl_803E699C;
    r = randomGetRange(0, 1) * 2;
    ObjAnim_SetCurrentMove(obj, *(s16 *)((char *)runtime->moveSet + r), lbl_803E698C, 0);
    kytesMum->objectFlags |= 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_updateNearPlayerCallback(int obj, int unused, u8 *arg) {
    int *player = Obj_GetPlayerObject();
    int *tricky = getTrickyObject();
    KytesMumRuntime *runtime = ((KytesMumObject *)obj)->runtime;
    if (objGetAnimState80A(player) == 0x40) {
        return 1;
    }
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        if ((*(int (**)(void *))((char *)*gGameUIInterface + 0x1c))(*gGameUIInterface) == 0) {
            buttonDisable(0, 0x100);
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0xb;
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 4;
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(randomGetRange(0, 1), obj, -1);
        }
    }
    if ((tricky != 0 && Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)tricky + 0x18)) < lbl_803E6988) ||
        (player != 0 && Vec_xzDistance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18)) < lbl_803E6988)) {
        if (*(s16 *)((char *)obj + 0xa0) != 9) {
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E698C, 0);
            runtime->animSpeed = lbl_803E6990;
            if (tricky != 0) {
                (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == 9) {
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0xb;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 4;
        ObjHits_SetHitVolumeSlot(obj, 0xb, 4, 7);
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kytesmum_updateQuestStateCallback(int obj, int unused, u8 *arg) {
    int questBits[3];
    int triggerIds[3];
    int count;
    char *runtime;
    int next;
    *(QuestTriple *)questBits = *(QuestTriple *)lbl_802C2578;
    *(QuestTriple *)triggerIds = *(QuestTriple *)lbl_802C2584;
    count = 0;
    Obj_GetPlayerObject();
    runtime = *(char **)((char *)obj + 0xb8);
    saveGame_saveObjectPos(obj);
    ObjHits_DisableObject(obj);
    for (; questBits[count] != -1 && GameBit_Get(questBits[count]) != 0; count++) {
        ;
    }
    if (count > 0) {
        *(int *)(runtime + 0x6d0) = (int)lbl_8032A7FC;
    }
    GameBit_Set(0xeb9, count == 1);
    next = triggerIds[count];
    if (next == -1) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        return 1;
    }
    if (ObjTrigger_IsSet(obj) != 0) {
        *(void **)((char *)obj + 0xbc) = (void *)kytesmum_idleCallback;
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(next, obj, -1);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void kytesmum_playAnimationEventSfx(int obj, u8 *arg, s16 *sfxData) {
    u8 flags = 0;
    int i;
    for (i = 0; i < (s8)arg[0x1b]; i++) {
        switch ((s8)arg[i + 0x13]) {
        case 0:
            if (sfxData != 0) {
                Sfx_PlayFromObject(obj, (u16)sfxData[0]);
            }
            break;
        case 1:
            if (sfxData != 0) {
                Sfx_PlayFromObject(obj, (u16)sfxData[1]);
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
    if (flags != 0 && sfxData != 0) {
        Sfx_PlayFromObject(obj, (u16)sfxData[3]);
    }
}
#pragma peephole reset
#pragma scheduling reset
