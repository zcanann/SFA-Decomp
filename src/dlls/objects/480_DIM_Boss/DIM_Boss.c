/*
 * DIM_Boss (DLL 0x1E0) controls the encounter and owns its animation and shared-effect tables.
 */
#include "dlls/objects/480_DIM_Boss.h"
#include "dolphin/mtx.h"

#include "dlls/objects/478_DIM2LavaCon.h"
#include "dlls/objects/482_DIM_BossTon.h"
#include "dolphin/os/OSReport.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/dll_0004_dummy04.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/player_api.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/gameloop_api.h"
#include "main/gametext_show_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/loaded_file_flags.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_dolphin.h"
#include "main/pi_flush_api.h"
#include "main/player_control_interface.h"
#include "main/rcp_dolphin.h"
#include "main/render_envfx_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/music_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/partfx_interface.h"
#include "main/gamebit_ids.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_002E_moveLib.h"

#define DIMBOSS_OBJECT_TYPE_ID 0x49

#define DIMBOSS_EVENT_CLEAR_RENDER_ATTACHMENT   0x01
#define DIMBOSS_EVENT_LAUNCH_LIFT               0x02
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_40004  0x06
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0002    0x07
#define DIMBOSS_EVENT_QUEUE_STEAM_SFX           0x08
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0040    0x09
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0040  0x0A
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0080  0x0C
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0100    0x0D
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0100  0x0E
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_2001   0x0F
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_8021   0x10
#define DIMBOSS_EVENT_TRIGGER_DEFEAT_FLAGS      0x11
#define DIMBOSS_EVENT_SPAWN_DIMBOSS_OBJECT      0x12
#define DIMBOSS_EVENT_ENABLE_DIMBOSS_MAP_AREA   0x13
#define DIMBOSS_EVENT_DISABLE_DIMBOSS_MAP_AREA  0x14
#define DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS       0x15
#define DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS        0x16
#define DIMBOSS_EVENT_SET_SEQUENCE_FLAG_80000   0x17
#define DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_80000 0x18

#define DIMBOSS_PHASE_START             0
#define DIMBOSS_PHASE_LAUNCH_LIFT       1
#define DIMBOSS_PHASE_GAMEBIT_COUNT_MET 2
#define DIMBOSS_PHASE_NO_RENDER         3
#define DIMBOSS_PHASE_RENDER_PAUSE      4

#define DIMBOSS_OBJECT_FLAG_HIDDEN 0x08
#define DIMBOSS_OBJECT_FLAG_ACTIVE 0x80

#define DIMBOSS_STATE_FLAG_START_MOVE    0x02
#define DIMBOSS_STATE_FLAG_TARGET_TRICKY 0x04
#define DIMBOSS_DEFEAT_TIMER_START       10

#define DIMBOSS_GAMEBIT_DEFEAT_STATE_B          0x17
#define DIMBOSS_GAMEBIT_RENDER_PAUSE            0x210
#define DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE 0x9E
/*
 * Established shared game-bit names are used directly at their call sites.
 */

#define DIMBOSS_MUSIC_LIFT_RUMBLE 0x27
#define DIMBOSS_MUSIC_STEAM_LOOP  0xEE
/*
 * Established music-trigger names are used directly at their call sites.
 */

#define DIMBOSS_SEQUENCE_FLAG_0001                        0x00000001
#define DIMBOSS_SEQUENCE_FLAG_0002                        0x00000002
#define DIMBOSS_SEQUENCE_FLAG_0004                        0x00000004
#define DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE         0x00000008
#define DIMBOSS_SEQUENCE_FLAG_BREATH_BURST                0x00000010
#define DIMBOSS_SEQUENCE_FLAG_0020                        0x00000020
#define DIMBOSS_SEQUENCE_FLAG_0040                        0x00000040
#define DIMBOSS_SEQUENCE_FLAG_0080                        0x00000080
#define DIMBOSS_SEQUENCE_FLAG_0100                        0x00000100
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7         0x00000200
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8         0x00000400
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9         0x00000800
#define DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10        0x00001000
#define DIMBOSS_SEQUENCE_FLAG_2000                        0x00002000
#define DIMBOSS_SEQUENCE_FLAG_ARENA_DUST_BURST            0x00004000
#define DIMBOSS_SEQUENCE_FLAG_8000                        0x00008000
#define DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY 0x00010000
#define DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT     0x00020000
#define DIMBOSS_SEQUENCE_FLAG_40000                       0x00040000
#define DIMBOSS_SEQUENCE_FLAG_80000                       0x00080000

#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS                                                                      \
    (DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8 |                           \
     DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10)
#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_AND_BREATH                                                                  \
    (DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS | DIMBOSS_SEQUENCE_FLAG_BREATH_BURST)
#define DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT (DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_8000)
#define DIMBOSS_SEQUENCE_FLAGS_ICICLE_HIT_EFFECTS                                                                      \
    (DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY | DIMBOSS_SEQUENCE_FLAG_0100 | DIMBOSS_SEQUENCE_FLAG_0080 |     \
     DIMBOSS_SEQUENCE_FLAG_0040)
#define DIMBOSS_SEQUENCE_FLAGS_40004 (DIMBOSS_SEQUENCE_FLAG_40000 | DIMBOSS_SEQUENCE_FLAG_0004)
#define DIMBOSS_SEQUENCE_FLAGS_2001  (DIMBOSS_SEQUENCE_FLAG_2000 | DIMBOSS_SEQUENCE_FLAG_0001)
#define DIMBOSS_SEQUENCE_FLAGS_8021                                                                                    \
    (DIMBOSS_SEQUENCE_FLAG_8000 | DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_0001)
#define DIMBOSS_SEQUENCE_FLAGS_PERSIST_AFTER_EFFECT_UPDATE                                                             \
    (DIMBOSS_SEQUENCE_FLAG_80000 | DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT |                                     \
     DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_POINTS | DIMBOSS_SEQUENCE_FLAG_0100 | DIMBOSS_SEQUENCE_FLAG_0080 |             \
     DIMBOSS_SEQUENCE_FLAG_0040 | DIMBOSS_SEQUENCE_FLAG_0020 | DIMBOSS_SEQUENCE_FLAG_BREATH_BURST)

#define DIMBOSS_MAP_DIR                   0x1C
#define DIMBOSS_GUT_MAP_DIR               0x1B
#define DIMTOP_MAP_DIR                    0x13
#define DIMBOSS_MAP_AREA_LIFT             0
#define DIMBOSS_MAP_AREA_BOSS             2
#define DIMBOSS_MAP_AREA_INTRO_GATE       5
#define DIMBOSS_MAP_UNLOAD_MASK           0x3FF
#define DIMBOSS_GUT_MAP_UNLOAD_MASK       0x20000000
#define DIMTOP_LOAD_PENDING_FLAGS_MASK    0xFFEFFFFF
#define DIMBOSS_HIT_EFFECT_ID             0x5A
#define DIMBOSS_HIT_EFFECT_RESOURCE_COUNT 1

#define DIMBOSS_ANIM_CONTROLLER_OFFSET      0x6C
#define DIMBOSS_ANIM_CONTROLLER_SIZE        0x624
#define DIMBOSS_ANIM_TABLE_OFFSET           0x690
#define DIMBOSS_HITDETECT_ANIM_TABLE_OFFSET 0x6A8

typedef struct DimAnimTable {
    u8 unknown000[0x168];
    s16 surprised[6];
    s16 group3[8];
    s16 group2[8];
    s16 group1[8];
} DimAnimTable;

typedef struct Dim2BossMoveChoices {
    s16 surprised[6];
    s16 group3[8];
    s16 group2[8];
    s16 group1[8];
} Dim2BossMoveChoices;

typedef struct DIMbossAnimScratch {
    union {
        f32 effectVelocity[3];
        u8 unknown000[DIMBOSS_ANIM_CONTROLLER_OFFSET];
    };
    u8 animController[DIMBOSS_ANIM_CONTROLLER_SIZE];
    DIMbossAnimHandlerTable animTable;
    DIMbossHitDetectAnimHandlerTable hitDetectAnimTable;
} DIMbossAnimScratch;

STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group3) == 0x0C);
STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group2) == 0x1C);
STATIC_ASSERT(offsetof(Dim2BossMoveChoices, group1) == 0x2C);
STATIC_ASSERT(sizeof(Dim2BossMoveChoices) == 0x3C);

STATIC_ASSERT(sizeof(DIMbossAnimScratch) == 0x6D8);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, effectVelocity) == 0x00);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animController) == DIMBOSS_ANIM_CONTROLLER_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, animTable) == DIMBOSS_ANIM_TABLE_OFFSET);
STATIC_ASSERT(offsetof(DIMbossAnimScratch, hitDetectAnimTable) == DIMBOSS_HITDETECT_ANIM_TABLE_OFFSET);

extern Dim2BossMoveChoices gDim2LiftFarMoveChoices;

extern u8 gDimBossHitReactionIndex;
extern u32 gDIMbossSequenceFlags;
extern StaffCollisionInterface** gDIMbossHitEffectResource;
extern int gDIMbossHitCooldown;
extern f32 gDIMbossRenderMtx[12];

int lbl_80325960[16] = {
    1, 8, 9, 9, 10, 10, 10, 10, 7, 7, 7, 7, 6, 6, 5, 1,
};

int DIMbossAnim_updateBossHitReaction(GameObject* obj, BaddieState* state) {
    DimAnimTable* moveTable;
    u16 targetParam;
    u16 targetDistance;
    u16 targetAnim[2];

    moveTable = (DimAnimTable*)lbl_80325960;
    if (state->moveDone != 0 || state->moveJustStartedB != 0) {
        (*gBaddieControlInterface)
            ->getTargetGeometry(obj, state->targetObj, 0x10, targetAnim, &targetParam, &targetDistance);
        state->moveDone = 0;
        if (targetDistance < 0x5a) {
            if (targetDistance > 0x1e &&
                ((u16)(targetAnim[0] - 3) <= 1 || targetAnim[0] == 0xb || targetAnim[0] == 0xc)) {
                (*gPlayerInterface)->setState(obj, state, 2);
            } else {
                (*gPlayerInterface)->setState(obj, state, 9);
            }
        } else if (targetAnim[0] == 0 || targetAnim[0] == 0xf) {
            state->moveDone = 0;
            if (targetDistance > 0x1a9 &&
                ((*gBaddieControlInterface)->getClearDirectionMask(obj, state, 200.0f) & 1) != 0) {
                s16 surprisedAnim = moveTable->surprised[randomGetRange(0, 5)];
                (*gPlayerInterface)->setState(obj, state, surprisedAnim);
            } else if (targetDistance < 0xfa) {
                (*gPlayerInterface)->setState(obj, state, 3);
            } else {
                if (gDimBossHitReactionIndex > 6) {
                    gDimBossHitReactionIndex = 0;
                }
                switch (state->hitPoints) {
                case 3:
                    (*gPlayerInterface)->setState(obj, state, moveTable->group3[gDimBossHitReactionIndex++]);
                    break;
                case 2:
                    (*gPlayerInterface)->setState(obj, state, moveTable->group2[gDimBossHitReactionIndex++]);
                    break;
                case 1:
                    (*gPlayerInterface)->setState(obj, state, moveTable->group1[gDimBossHitReactionIndex++]);
                    break;
                default:
                    (*gPlayerInterface)->setState(obj, state, 3);
                    break;
                }
            }
        } else {
            (*gPlayerInterface)->setState(obj, state, 2);
        }
    }
    if (state->controlMode == 3 || state->controlMode == 7) {
        gDIMbossAnimController.modeBits |= 1;
    } else {
        gDIMbossAnimController.modeBits &= ~1;
    }
    DIMboss_updateHitResponse(obj, state);
    return 0;
}

int lbl_803DBF30[2] = {0x17F, 0x180};
s16 gDim2LiftFarFlankMoveChoices[4] = {3, 8, 0, 0};

#define DIM2LIFT_HIT_VOLUME_SLOT_10 10
#define DIM2LIFT_HIT_VOLUME_SLOT_9  9

#define DIM2LIFT_CHILD_OBJ_BLUE_WHITE_EFFECT 656

extern int lbl_80325AA0[6];
extern f32 gDim2LiftMoveSpeedByDir[16];

typedef struct DimBossBlueWhiteEffectPlacement {
    ObjPlacement base;
    u8 unknown18[0x1E - 0x18];
    s16 gameBit;
    s16 gameBit2;
    u8 unknown22[0x24 - 0x22];
} DimBossBlueWhiteEffectPlacement;

STATIC_ASSERT(sizeof(DimBossBlueWhiteEffectPlacement) == 0x24);

int DIMbossAnim_updatePlayerHitReaction(GameObject* obj, BaddieState* runtime) {
    u16 dirSector;
    u16 unused;
    u16 distance;
    GroundBaddieState* state;
    s16 mode;
    state = obj->extra;
    if (runtime->moveDone != 0 || runtime->moveJustStartedB != 0) {
        (*gBaddieControlInterface)
            ->getTargetGeometry(obj, (GameObject*)runtime->targetObj, 0x10, &dirSector, &unused,
                                &distance);
        runtime->moveDone = 0;
        if (distance < 90) {
            if (distance > 30 && ((u16)(dirSector - 3) <= 1 || dirSector == 11 || dirSector == 12)) {
                (*gPlayerInterface)->setState(obj, runtime, 2);
            } else {
                (*gPlayerInterface)->setState(obj, runtime, 9);
            }
        } else if (dirSector == 0 || dirSector == 15) {
            runtime->moveDone = 0;
            if (distance > 240 &&
                ((*gBaddieControlInterface)->getClearDirectionMask(obj, runtime, 100.0f) & 1)) {
                (*gPlayerInterface)
                    ->setState(obj, runtime, gDim2LiftFarMoveChoices.surprised[randomGetRange(0, 5)]);
            } else if (state->flags400 & 4) {
                (*gPlayerInterface)
                    ->setState(obj, runtime, gDim2LiftFarFlankMoveChoices[randomGetRange(0, 1)]);
            } else {
                (*gPlayerInterface)->setState(obj, runtime, 3);
            }
        } else {
            (*gPlayerInterface)->setState(obj, runtime, 2);
        }
    }
    mode = runtime->controlMode;
    if (mode != 1 && mode != 4 && mode != 5) {
        gDIMbossAnimController.modeBits |= 1;
    } else {
        gDIMbossAnimController.modeBits &= ~1;
    }
    DIMboss_updateHitResponse(obj, runtime);
    return 0;
}

int DIMbossAnim_finishDefeat(GameObject* obj, BaddieState* p2) {
    GroundBaddieState* state;

    Obj_GetPlayerObject();
    state = obj->extra;

    if ((s32)p2->moveJustStartedB != 0) {
        p2->targetObj = 0;
        p2->physicsActive = 0;
        p2->hasTarget = 0;
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~0x80;
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xE0000, obj, 0);
        mainSetBits(state->gameBitB, 0);
        mainSetBits(state->gameBitA, 1);
        if (obj->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
    }
    return 0;
}

int DIMbossAnim_hasMoveDone(int unused, int* state) {
    return ((BaddieState*)state)->moveDone != 0;
}

int DIMbossAnim_returnToIdleWhenDone(GameObject* obj, BaddieState* runtime) {
    if (runtime->moveDone != 0) {
        (*gPlayerInterface)->setState(obj, runtime, 0);
    }
    return 0;
}

int DIMbossAnim_selectTargetControlMode(GameObject* obj) {
    GroundBaddieState* state = obj->extra;
    switch (state->targetState) {
    case 1:
        return 5;
    case 2:
        return 6;
    case 4:
        return 4;
    case 0:
        return 2;
    case 3:
        return 2;
    default:
        return 2;
    }
}

int DIMbossHitDetect_tonsilSlam(GameObject* obj, BaddieState* runtime) {
    f32 animSpeed;
    if (obj->anim.currentMoveProgress > 0.9f) {
        gDIMbossSequenceFlags &= ~DIMBOSS_SEQUENCE_FLAG_0020;
    }
    if (runtime->moveJustStartedA != 0) {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT;
        CameraShake_Enable();
        CameraShake_StartDampened(2.5f, 5.0f, 2.0f);
        doRumble(12.0f);
        obj->anim.activeMove = -1;
        runtime->moveSpeed = 0.002f * (f32)(runtime->hitPoints + 1);
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x15, animSpeed, 0);
            runtime->moveDone = 0;
        }
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 0, lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_liftSlam(GameObject* obj, BaddieState* runtime) {
    GroundBaddieState* state = obj->extra;
    if (runtime->moveJustStartedA != 0) {
        f32 animSpeed;
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_2000;
        CameraShake_Enable();
        CameraShake_StartDampened(2.5f, 5.0f, 2.0f);
        doRumble(12.0f);
        obj->anim.activeMove = -1;
        runtime->moveSpeed = 0.01f;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0xe, animSpeed, 0);
            runtime->moveDone = 0;
        }
        if (state->targetState == 1) {
            *(f32*)((u8*)state->control + 0xa8) = 780.0f;
        }
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 1, lbl_803DBF30);
    return 0;
}

int DIMbossHitDetect_liftImpact(GameObject* obj, BaddieState* state) {
    f32 zeroProgress;

    state->moveSpeed = 0.008f;
    zeroProgress = 0.0f;
    state->animSpeedA = zeroProgress;
    state->animSpeedB = zeroProgress;
    ObjHits_SetHitVolumeSlot(&obj->anim, DIM2LIFT_HIT_VOLUME_SLOT_10, 1, -1);

    if ((s32)state->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 15, 0.0f, 0);
        state->moveDone = 0;
    }

    if ((state->eventFlags & BADDIE_EVENT_FOOTSTEP) != 0) {
        gDIMbossSequenceFlags |= 0x4004;
        Sfx_PlayFromObject(obj, SFXTRIG_mn_dimbos46);
        CameraShake_Enable();
        CameraShake_StartDampened(5.0f, 10.0f, 4.0f);
        doRumble(20.0f);
        mainSetBits(619, 1);
    }
    return 0;
}

int DIMbossHitDetect_chooseIdleTaunt(GameObject* obj, BaddieState* runtime) {
    if (runtime->moveJustStartedA != 0) {
        f32 animSpeed;
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
        runtime->moveSpeed = 0.005f;
        if (randomGetRange(0, 1) != 0) {
            if (runtime->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 0xd, 0.0f, 0);
                runtime->moveDone = 0;
            }
        } else if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0xc, 0.0f, 0);
            runtime->moveDone = 0;
        }
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 0, lbl_80325AA0);
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 7, 1, lbl_80325AA0);
    return 0;
}

int DIMbossHitDetect_lungeAttack(GameObject* obj, BaddieState* runtime, f32 hitAmount) {
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DIM2LIFT_HIT_VOLUME_SLOT_9, 1, -1);
    if (runtime->moveJustStartedA != 0) {
        f32 animSpeed;
        runtime->moveSpeed = 0.006f;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x13, 0.0f, 0);
            runtime->moveDone = 0;
        }
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 1, lbl_80325AA0);
    (*gPlayerInterface)->rotateTowardTarget(obj, runtime, hitAmount, 0xf0);
    return 0;
}

int DIMbossHitDetect_breathBurst(GameObject* obj, BaddieState* runtime, f32 weight) {
    f32 progress;
    f32 animSpeed;
    if (runtime->moveJustStartedA != 0) {
        runtime->moveSpeed = 0.0025f;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x12, 0.0f, 0);
            runtime->moveDone = 0;
        }
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
    }
    progress = obj->anim.currentMoveProgress;
    if (progress > 0.95f || runtime->moveDone != 0) {
        return 8;
    }
    if (progress > 0.3f) {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_BREATH_BURST;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 5, lbl_80325AA0);
    (*gPlayerInterface)->rotateTowardTarget(obj, runtime, weight, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteCapture(GameObject* obj, BaddieState* runtime, f32 weight) {
    f32 progress;
    f32 animSpeed;
    if (runtime->moveJustStartedA != 0) {
        runtime->moveSpeed = 0.025f;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, 0.0f, 0);
            runtime->moveDone = 0;
        }
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
    }
    progress = obj->anim.currentMoveProgress;
    if (progress > 0.55f) {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    } else if (progress > 0.25f) {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (runtime->eventFlags & BADDIE_EVENT_FOOTSTEP) {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 3, lbl_80325AA0);
    (*gPlayerInterface)->rotateTowardTarget(obj, runtime, weight, 0xf0);
    return 0;
}

int DIMbossHitDetect_blueWhiteEventCapture(GameObject* obj, BaddieState* runtime, f32 weight) {
    f32 progress;
    f32 animSpeed;
    if (runtime->moveJustStartedA != 0) {
        runtime->moveSpeed = 0.005f;
        if (runtime->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, 0.0f, 0);
            runtime->moveDone = 0;
        }
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
    }
    progress = obj->anim.currentMoveProgress;
    if (progress > 0.55f) {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    } else if (progress > 0.35f) {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0040;
    }
    if (runtime->eventFlags & BADDIE_EVENT_LANDING) {
        gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY;
        runtime->eventFlags &= ~BADDIE_EVENT_LANDING;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, 3, lbl_80325AA0);
    (*gPlayerInterface)->rotateTowardTarget(obj, runtime, weight, 0xf0);
    return 0;
}

int DIMbossHitDetect_randomSwipe(GameObject* obj, BaddieState* runtime, f32 weight) {
    int eventFlags;
    f32 animSpeed;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DIM2LIFT_HIT_VOLUME_SLOT_9, 1, -1);
    if (runtime->moveJustStartedA != 0) {
        obj->anim.activeMove = -1;
        animSpeed = 0.0f;
        runtime->animSpeedA = animSpeed;
        runtime->animSpeedB = animSpeed;
        if (randomGetRange(0, 1) != 0) {
            if (runtime->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 0xb, 0.0f, 0);
                runtime->moveDone = 0;
            }
            runtime->moveSpeed = 0.005f;
        } else {
            if (runtime->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 0x10, 0.0f, 0);
                runtime->moveDone = 0;
            }
            runtime->moveSpeed = 0.006f;
        }
    }
    eventFlags = runtime->eventFlags;
    if (eventFlags & BADDIE_EVENT_LANDING) {
        runtime->eventFlags = eventFlags & ~BADDIE_EVENT_LANDING;
        gDIMbossSequenceFlags |= (DIMBOSS_SEQUENCE_FLAG_0001 | DIMBOSS_SEQUENCE_FLAG_0004);
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, runtime, 0, randomGetRange(0, 1), lbl_80325AA0);
    (*gPlayerInterface)->rotateTowardTarget(obj, runtime, weight, 0xf0);
    return 0;
}

int DIMbossHitDetect_trackTargetMove(GameObject* obj, BaddieState* runtime, f32 hitAmount) {
    u16 dirSector;
    u16 unused;
    u16 distance;
    runtime->animSpeedA = 0.0f;
    if (runtime->moveDone != 0 || runtime->moveJustStartedA != 0 ||
        obj->anim.currentMove == 1) {
        (*gBaddieControlInterface)
            ->getTargetGeometry(obj, (GameObject*)runtime->targetObj, 0x10, &dirSector, &unused,
                                &distance);
        ObjAnim_SetCurrentMove(obj, lbl_80325960[dirSector], 0.0f, 0);
        runtime->moveSpeed = gDim2LiftMoveSpeedByDir[dirSector];
        runtime->moveDone = 0;
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, runtime, hitAmount, 8);
    return 0;
}

int DIMbossHitDetect_applyForwardMove(int* obj, u8* state, f32 weight) {
    if (((BaddieState*)state)->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
        ((BaddieState*)state)->moveDone = 0;
    }
    ((BaddieState*)state)->moveSpeed = 0.021f;
    (*gPlayerInterface)->updateAnimRootMotion(obj, state, weight, 1);
    (*gPlayerInterface)->rotateTowardTarget(obj, state, weight, 4);
    return 0;
}

int DIMbossHitDetect_resetIdleMove(GameObject* obj, u8* state) {
    if (((BaddieState*)state)->moveJustStartedA != 0) {
        f32 fz;
        if (((BaddieState*)state)->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
            ((BaddieState*)state)->moveDone = 0;
        }
        fz = 0.0f;
        ((BaddieState*)state)->animSpeedA = fz;
        ((BaddieState*)state)->animSpeedB = fz;
        obj->anim.activeMove = -1;
    }
    return 0;
}

void DIMboss_spawnBlueWhiteEffect(DIMbossEffectMarker* source, f32* velocity) {
    GameObject* spawnedObj;
    DimBossBlueWhiteEffectPlacement* setup;
    if ((u8)Obj_CanSetupObject() != 0) {
        setup = (DimBossBlueWhiteEffectPlacement*)Obj_AllocObjectSetup(36, DIM2LIFT_CHILD_OBJ_BLUE_WHITE_EFFECT);
        setup->base.posX = source->x;
        setup->base.posY = source->y;
        setup->base.posZ = source->z;
        setup->base.color[0] = 1;
        setup->base.color[1] = 1;
        setup->base.color[2] = 255;
        setup->base.color[3] = 255;
        setup->gameBit = -1;
        setup->gameBit2 = -1;
        spawnedObj = objSetupObject(&setup->base, 5, -1, -1, NULL);
        if (spawnedObj != NULL) {
            spawnedObj->anim.velocityX = velocity[0];
            spawnedObj->anim.velocityY = velocity[1];
            spawnedObj->anim.velocityZ = velocity[2];
        }
    }
}

void DIMboss_createStateLight(GameObject* obj, u8 isGreen) {
    ModelLightStruct** lightSlot = (ModelLightStruct**)((GroundBaddieState*)obj->extra)->control;

    if (*(void**)lightSlot != NULL) {
        return;
    }

    lightSlot[0] = objCreateLight(NULL, 1);
    if (*(void**)lightSlot == NULL) {
        return;
    }

    modelLightStruct_setLightKind(lightSlot[0], MODEL_LIGHT_KIND_POINT);
    modelLightStruct_setPosition(lightSlot[0], ((f32*)lightSlot)[0x16], ((f32*)lightSlot)[0x17],
                                 ((f32*)lightSlot)[0x18]);

    if (isGreen != 0) {
        modelLightStruct_setDiffuseColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 0, 255, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 0, 255, 0, 192, 40.0f);
    } else {
        modelLightStruct_setDiffuseColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setSpecularColor(lightSlot[0], 255, 0, 0, 255);
        modelLightStruct_setupGlow(lightSlot[0], 0, 255, 0, 0, 192, 80.0f);
    }

    modelLightStruct_setDistanceAttenuation(lightSlot[0], 80.0f, 155.0f);
    lightSetField4D(lightSlot[0], 1);
    modelLightStruct_setEnabled(lightSlot[0], 1, 0.0f);
    modelLightStruct_setDiffuseTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_setSpecularTargetColor(lightSlot[0], 64, 0, 0, 64);
    modelLightStruct_startColorFade(lightSlot[0], 2, 40);
    modelLightStruct_setAffectsAabbLightSelection(lightSlot[0], 1);
    modelLightStruct_setGlowProjectionRadius(lightSlot[0], 100.0f);
}

f32 gDim2LiftMoveSpeedByDir[16] = {
    0.007f, 0.025f, 0.029f, 0.05f,  0.011f, 0.014f, 0.016f, 0.018f,
    0.018f, 0.016f, 0.014f, 0.011f, 0.05f,  0.029f, 0.025f, 0.007f,
};

#define DIM2ICICLE_ADVANCE_MSG 0xe0001 /* notify the struck object to advance its hit reaction */

#define DIMBOSS_PARTFX_DUST 0x4b7 /* dust particle effect (gDIMbossDustFxSource) */
#define DIMBOSS_PARTFX_HIT  0x328 /* icicle hit-response effect (gDIMbossHitFxBuffer) */

typedef struct DimBossMeltEntry {
    f32 resetTime;
    u16 gameBit;
    u16 unknown06;
} DimBossMeltEntry;

extern DimBossMeltEntry gDIMbossMeltEntries[];

static inline ObjModel* DIMboss_GetActiveModel(GameObject* obj) {
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

void DIMboss_updateSequenceEffects(GameObject* obj, DIMbossRuntime* runtime) {
    DIMbossTopState* topState;
    s16 brightness;
    int i;
    f32 zero;
    f32 m[12];
    u8 colA;
    u8 colB;
    u8 colG;
    u8 colR;

    topState = runtime->groundBaddie.control;
    if (topState->effect != NULL) {
        if (runtime->groundBaddie.targetState == DIMBOSS_PHASE_LAUNCH_LIFT) {
            modelLightStruct_setPosition((ModelLightStruct*)topState->effect, topState->liftGlowSource.x,
                                         topState->liftGlowSource.y, topState->liftGlowSource.z);
        } else {
            modelLightStruct_setPosition((ModelLightStruct*)topState->effect, topState->tonsilDustSource.x,
                                         topState->tonsilDustSource.y, topState->tonsilDustSource.z);
        }
        modelLightStruct_getSpecularColor((ModelLightStruct*)topState->effect, &colA, &colB, &colG, &colR);
        modelLightStruct_setGlowColor((ModelLightStruct*)topState->effect, colA, colB, colG, 0xc0);
        if (topState->effect->glowType != 0 && topState->effect->enabled != 0) {
            brightness = topState->effect->glowAlpha + topState->effect->glowAlphaStep;
            if (brightness < 0) {
                brightness = 0;
                topState->effect->glowAlphaStep = 0;
            } else if (brightness > 0xc) {
                brightness += randomGetRange(-0xc, 0xc);
                if (brightness > 0xff) {
                    brightness = 0xff;
                    topState->effect->glowAlphaStep = 0;
                }
            }
            topState->effect->glowAlpha = brightness;
        }
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7) {
        ObjPath_GetPointWorldPosition(obj, 7, &gDIMbossDustFxSource.posX,
                                      &gDIMbossDustFxSource.posY, &gDIMbossDustFxSource.posZ, 0);
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSS_PARTFX_DUST, &gDIMbossDustFxSource, 0x200001, -1, NULL);
            i += 1;
        } while (i < 0xf);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8) {
        ObjPath_GetPointWorldPosition(obj, 8, &gDIMbossDustFxSource.posX,
                                      &gDIMbossDustFxSource.posY, &gDIMbossDustFxSource.posZ, 0);
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSS_PARTFX_DUST, &gDIMbossDustFxSource, 0x200001, -1, NULL);
            i += 1;
        } while (i < 0xf);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9) {
        ObjPath_GetPointWorldPosition(obj, 9, &gDIMbossDustFxSource.posX,
                                      &gDIMbossDustFxSource.posY, &gDIMbossDustFxSource.posZ, 0);
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSS_PARTFX_DUST, &gDIMbossDustFxSource, 0x200001, -1, NULL);
            i += 1;
        } while (i < 0xf);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10) {
        ObjPath_GetPointWorldPosition(obj, 10, &gDIMbossDustFxSource.posX,
                                      &gDIMbossDustFxSource.posY, &gDIMbossDustFxSource.posZ, 0);
        i = 0;
        do {
            (*gPartfxInterface)
                ->spawnObject(obj, DIMBOSS_PARTFX_DUST, &gDIMbossDustFxSource, 0x200001, -1, NULL);
            i += 1;
        } while (i < 0xf);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_BREATH_BURST) {
        memcpy(m, (void*)ObjPath_GetPointModelMtx(obj, 0xb), 0x30);
        zero = 0.0f;
        m[3] = zero;
        m[7] = zero;
        m[11] = zero;
        i = 0;
        do {
            gDIMbossDustFxSource.posX = randomGetRange(-0x19, 0x19);
            gDIMbossDustFxSource.posY = randomGetRange(-0x19, 0x19);
            gDIMbossDustFxSource.posZ = -75.0f;
            gDIMbossAnimScratchBase[0] = gDIMbossDustFxSource.posX / (gDIMbossDustFxSource.posZ / 2.0f);
            gDIMbossAnimScratchBase[1] = gDIMbossDustFxSource.posY / (gDIMbossDustFxSource.posZ / 2.0f);
            gDIMbossAnimScratchBase[2] = 2.0f;
            PSMTXMultVec((MtxPtr)m, (Vec*)gDIMbossAnimScratchBase, (Vec*)gDIMbossAnimScratchBase);
            ObjPath_GetPointWorldPosition(obj, 0xb, &gDIMbossDustFxSource.posX,
                                          &gDIMbossDustFxSource.posY, &gDIMbossDustFxSource.posZ, 1);
            (*gPartfxInterface)
                ->spawnObject(obj, 0x4b8, &gDIMbossDustFxSource, 0x200001, -1, gDIMbossAnimScratchBase);
            i += 1;
        } while (i < 5);
    }
    topState->breathBurstSource.x = 0.0f;
    topState->breathBurstSource.y = -15.0f;
    topState->breathBurstSource.z = -20.0f;
    topState->breathBurstSource.scale = 1.0f;
    topState->breathBurstSource.rotZ = 0;
    topState->breathBurstSource.rotY = 0;
    topState->breathBurstSource.rotX = 0;
    ObjPath_GetPointWorldPosition(obj, 0xd, &topState->breathBurstSource.x,
                                  &topState->breathBurstSource.y, &topState->breathBurstSource.z, 1);
    ObjPath_GetPointWorldPosition(obj, 0xd, &topState->blueWhiteEffectSource.x,
                                  &topState->blueWhiteEffectSource.y, &topState->blueWhiteEffectSource.z, 0);
    ObjPath_GetPointWorldPosition(obj, 0xb, &topState->tonsilDustSource.x,
                                  &topState->tonsilDustSource.y, &topState->tonsilDustSource.z, 0);
    topState->liftGlowSource.x = 0.0f;
    topState->liftGlowSource.y = -6.0f;
    topState->liftGlowSource.z = 5.0f;
    topState->liftGlowSource.scale = 1.0f;
    topState->liftGlowSource.rotZ = 0;
    topState->liftGlowSource.rotY = 0;
    topState->liftGlowSource.rotX = 0;
    ObjPath_GetPointWorldPosition(obj, 0xc, &topState->liftGlowSource.x, &topState->liftGlowSource.y,
                                  &topState->liftGlowSource.z, 1);
    memcpy(topState->breathBurstMtx, (void*)ObjPath_GetPointModelMtx(obj, 0), 0x30);
    zero = 0.0f;
    topState->breathBurstMtx[3] = zero;
    topState->breathBurstMtx[7] = zero;
    topState->breathBurstMtx[11] = zero;
    gDIMbossSequenceFlags &= ~DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_AND_BREATH;
}

#define GAMEBIT_DIM2_ICICLE_ACTIVE     0x25e
#define GAMEBIT_DIM2_ICICLE_PHASE1_WIN 0x20b
#define GAMEBIT_DIM2_ICICLE_PHASE2_WIN 0x266
/* DIMBOSS_GAMEBIT_ICICLE_DEFEATED is shared by both encounter modes. */

#define DIM2ICICLE_ENVFX_A 0xdb
#define DIM2ICICLE_ENVFX_B 0xdc

extern int gDIMbossSequenceSfx[];
void DIMboss_updateWarpAndEffects(GameObject* obj, DIMbossRuntime* runtime) {
    DIMbossTopState* topState;
    int counter;
    int i;
    f32 vec[3];

    topState = runtime->groundBaddie.control;
    counter = topState->defeatTimer;
    if (counter != 0) {
        topState->defeatTimer = counter - 1;
        if (topState->defeatTimer <= 0) {
            topState->defeatTimer = 0;
            setShowWorldMapHud(0);
            warpToMap(0x77, 1);
            return;
        }
    }
    if (topState->steamFlags.sfxPending) {
        getEnvfxAct(0, 0, DIM2ICICLE_ENVFX_A, 0);
        getEnvfxAct(0, 0, DIM2ICICLE_ENVFX_B, 0);
        skySetLightsEnabled(7, 1, 0);
        skySetLightDirection(7, 0.2f, -0.3f, -1.0f);
        skySetBaseColor(7, 0xa0, 0xa0, 0xff, 0x7f, 0x28);
        topState->steamFlags.sfxPending = 0;
    }
    if (runtime->groundBaddie.baddie.eventFlags & DIMBOSS_SEQUENCE_FLAG_0004) {
        runtime->groundBaddie.baddie.eventFlags &= ~DIMBOSS_SEQUENCE_FLAG_0004;
        Sfx_PlayFromObject(obj, gDIMbossSequenceSfx[0]);
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7;
        doRumble(4.0f);
    }
    if (runtime->groundBaddie.baddie.eventFlags & DIMBOSS_SEQUENCE_FLAG_0002) {
        runtime->groundBaddie.baddie.eventFlags &= ~DIMBOSS_SEQUENCE_FLAG_0002;
        Sfx_PlayFromObject(obj, gDIMbossSequenceSfx[1]);
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8;
        doRumble(4.0f);
    }
    if (runtime->groundBaddie.baddie.eventFlags & DIMBOSS_SEQUENCE_FLAG_BREATH_BURST) {
        runtime->groundBaddie.baddie.eventFlags &= ~DIMBOSS_SEQUENCE_FLAG_BREATH_BURST;
        Sfx_PlayFromObject(obj, gDIMbossSequenceSfx[2]);
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9;
        doRumble(4.0f);
    }
    if (runtime->groundBaddie.baddie.eventFlags & DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE) {
        runtime->groundBaddie.baddie.eventFlags &= ~DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE;
        Sfx_PlayFromObject(obj, gDIMbossSequenceSfx[3]);
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10;
        doRumble(4.0f);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_2000) {
        i = 0;
        do {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b1, &topState->liftGlowSource, 0x200001, -1, NULL);
            i = i + 1;
        } while (i < 0x32);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b2, &topState->liftGlowSource, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x4b3, &topState->liftGlowSource, 0x200001, -1, NULL);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_80000) {
        (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x800, NULL, 1, NULL);
    }
    if ((gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT) ||
        runtime->groundBaddie.baddie.hitPoints < 2) {
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0020) {
            i = 0;
            do {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x4b4, &topState->tonsilDustSource, 0x200001, -1, NULL);
                i = i + 1;
            } while (i < 7);
        } else if (randomGetRange(0, runtime->groundBaddie.baddie.hitPoints) == 0 &&
                   runtime->groundBaddie.targetState == DIMBOSS_PHASE_GAMEBIT_COUNT_MET) {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b4, &topState->tonsilDustSource, 0x200001, -1, NULL);
        }
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_8000) {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b2, &topState->tonsilDustSource, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b3, &topState->tonsilDustSource, 0x200001, -1, NULL);
        }
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAGS_ICICLE_HIT_EFFECTS) {
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0040) {
            i = 0;
            do {
                vec[0] = 0.1f * (f32)randomGetRange(-5, 5);
                vec[1] = 0.1f * (f32)randomGetRange(-5, 5);
                vec[2] = -0.25f * (f32)randomGetRange(2, 8);
                PSMTXMultVec((MtxPtr)topState->breathBurstMtx, (Vec*)vec, (Vec*)vec);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x4b5, &topState->breathBurstSource, 0x200001, -1, vec);
                i = i + 1;
            } while (i < 5);
        }
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0080) {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b5, &topState->blueWhiteEffectSource, 0x200001, -1, NULL);
        }
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0100) {
            vec[0] = 0.1f;
            vec[1] = -0.2f;
            vec[2] = -0.1f * (f32)randomGetRange(4, 8);
            PSMTXMultVec((MtxPtr)topState->breathBurstMtx, (Vec*)vec, (Vec*)vec);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4b6, &topState->blueWhiteEffectSource, 0x200001, -1, vec);
        }
        if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY) {
            vec[0] = 0.0f;
            vec[1] = -0.2f;
            vec[2] = -1.5f;
            PSMTXMultVec((MtxPtr)topState->breathBurstMtx, (Vec*)vec, (Vec*)vec);
            memcpy(topState->blueWhiteVelocity, vec, 0xc);
            gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT;
        }
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ARENA_DUST_BURST) {
        i = 0;
        do {
            (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSS_PARTFX_DUST, NULL, 1, -1, NULL);
            i = i + 1;
        } while (i < 0x32);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0001) {
        CameraShake_Enable();
        doRumble(4.0f);
        CameraShake_StartDampened(2.5f, 5.0f, 2.0f);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_40000) {
        CameraShake_Enable();
        doRumble(30.0f);
        CameraShake_StartDampened(5.0f, 10.0f, 4.0f);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0002) {
        CameraShake_Enable();
        CameraShake_StartDampened(0.0f, 0.0f, 0.0f);
        CameraShake_SetOffset(0.0f);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0004) {
        mainSetBits(GAMEBIT_DIM2_ICICLE_ACTIVE, 1);
    } else {
        mainSetBits(GAMEBIT_DIM2_ICICLE_ACTIVE, 0);
    }
    gDIMbossSequenceFlags &= DIMBOSS_SEQUENCE_FLAGS_PERSIST_AFTER_EFFECT_UPDATE;
}

const s16 lbl_802C2338[7] = {10, 25, 25, 10, 20, 20, 20};

typedef struct DimBossHitDescriptor {
    int unknown00;
    int unknown04;
    int unknown08;
    int unknown0C;
} DimBossHitDescriptor;

STATIC_ASSERT(sizeof(DimBossHitDescriptor) == 0x10);

const DimBossHitDescriptor gDIMbossHitDescTemplate = {6, 0x69, 0x69, 0xFF};

typedef struct DimBossHitEntry {
    f32 unknown00;
    f32 positionX;
    f32 positionY;
    f32 positionZ;
} DimBossHitEntry;

void DIMboss_updateHitResponse(GameObject* obj, BaddieState* playerState) {
    GroundBaddieState* state;
    u8 hit;
    int hitResult;
    GameObject* player;
    DimBossHitEntry* hitEntries;
    ObjHitsPriorityState* hitState;
    int hitType;
    u32 hitVolume;
    GameObject* hitId;
    DimBossHitDescriptor desc;

    state = obj->extra;
    Obj_GetPlayerObject();
    hit = 0;
    desc = gDIMbossHitDescTemplate;
    if (gDIMbossHitCooldown != 0) {
        gDIMbossHitCooldown = gDIMbossHitCooldown - 1;
    }
    hitResult = ObjHits_GetPriorityHit(obj, &hitId, &hitType, &hitVolume);
    if (hitResult != 0) {
        gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
        if (state->targetState == 1) {
            if ((gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE) == 0 || hitType != 2) {
                hit = 1;
            }
        } else if (state->targetState == 2) {
            if (hitType != 4 || obj->anim.currentMoveProgress < 0.3f || obj->anim.currentMove != 0x12) {
                hit = 1;
            }
        }
        if (hit) {
            if (gDIMbossHitCooldown == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_sc_npu_216_4b2);
                hitEntries = (DimBossHitEntry*)DIMboss_GetActiveModel(obj)->activeHitVolumeSpheres;
                gDIMbossHitFxBuffer.x = playerMapOffsetX + hitEntries[hitType].positionX;
                gDIMbossHitFxBuffer.y = hitEntries[hitType].positionY;
                gDIMbossHitFxBuffer.z = playerMapOffsetZ + hitEntries[hitType].positionZ;
                (*gPartfxInterface)
                    ->spawnObject(obj, DIMBOSS_PARTFX_HIT, &gDIMbossHitFxBuffer, 0x200001, -1, NULL);
                gDIMbossHitFxBuffer.x = gDIMbossHitFxBuffer.x - obj->anim.worldPosX;
                gDIMbossHitFxBuffer.y = gDIMbossHitFxBuffer.y - obj->anim.worldPosY;
                gDIMbossHitFxBuffer.z = gDIMbossHitFxBuffer.z - obj->anim.worldPosZ;
                gDIMbossHitFxBuffer.scale = 1.0f;
                gDIMbossHitFxBuffer.rotX = 0;
                gDIMbossHitFxBuffer.rotY = 0;
                gDIMbossHitFxBuffer.rotZ = 0;
                desc.unknown04 += randomGetRange(0, 0x9b);
                desc.unknown08 += randomGetRange(0, 0x9b);
                (*gDIMbossHitEffectResource)
                    ->spawn(obj, 0, (PartFxSpawnParams*)&gDIMbossHitFxBuffer, 1, -1,
                            (StaffCollisionColorArgs*)&desc);
                gDIMbossHitCooldown = 0x1e;
            }
        } else {
            if (playerState->targetObj == NULL) {
                player = Obj_GetPlayerObject();
                if (playerGetStateValue(player, 1) != 0) {
                    (*gBaddieControlInterface)
                        ->startHitReaction(obj, playerState, &state->routeNav,
                                           state->gameBitB, NULL, 2, 10, -1, -1);
                    playerState->targetObj = player;
                    playerState->hasTarget = 0;
                }
            }
            if (state->targetState == 1) {
                if (playerState->hitPoints == 3) {
                    gTitleMenuControlInterfaceCopy->vtable->func04(obj, 0x68, 0, 0, 0);
                } else if (playerState->hitPoints == 2) {
                    gTitleMenuControlInterfaceCopy->vtable->func04(obj, 0x6c, 0, 0, 0);
                }
            } else if (state->targetState == 2) {
                if (playerState->hitPoints == 3) {
                    gTitleMenuControlInterfaceCopy->vtable->func04(obj, 0x77, 0, 0, 0);
                } else if (playerState->hitPoints == 2) {
                    gTitleMenuControlInterfaceCopy->vtable->func04(obj, 0x78, 0, 0, 0);
                }
            }
            playerState->moveDone = 0;
            playerState->lastHitPriority = hitResult;
            playerState->hitPoints -= 1;
            Sfx_PlayFromObject(obj, SFXTRIG_wp_mpwru1);
            if (playerState->hitPoints <= 0) {
                playerState->hitPoints = 0;
                playerState->hasTarget = 0;
                (*gPlayerInterface)->setState(obj, playerState, 0);
                hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
                hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                obj->anim.resetHitboxFlags &= ~0x80;
                mainSetBits(DIMBOSS_GAMEBIT_ICICLE_DEFEATED, 1);
                if (state->targetState == 1) {
                    mainSetBits(GAMEBIT_DIM2_ICICLE_PHASE1_WIN, 1);
                } else if (state->targetState == 2) {
                    mainSetBits(GAMEBIT_DIM2_ICICLE_PHASE2_WIN, 1);
                }
            } else if (state->targetState == 1) {
                (*gPlayerInterface)->setState(obj, playerState, 10);
            } else {
                (*gPlayerInterface)->setState(obj, playerState, 0xb);
            }
            ObjMsg_SendToObject(hitId, DIM2ICICLE_ADVANCE_MSG, obj, 0);
        }
    }
}

void DIMboss_updateCombatState(GameObject* obj, ObjSeqState* animUpdate, DIMbossRuntime* runtime,
                                  DIMbossRuntime* updateRuntime) {
    DIMbossTopState* topState;
    GameObject* gameObj;
    u8* tricky;
    f32 timer;
    f32 limit;

    gameObj = obj;
    topState = runtime->groundBaddie.control;
    tricky = (u8*)getTrickyObject();
    ObjHits_EnableObject(obj);
    updateRuntime->groundBaddie.baddie.physicsActive = 1;
    (*gBaddieControlInterface)->updateGravity(obj, updateRuntime, 0.17f, 1);
    (*gBaddieControlInterface)
        ->processMessages(obj, updateRuntime, &runtime->groundBaddie.routeNav, runtime->groundBaddie.gameBitB,
                          &runtime->groundBaddie.subMode, 0, 0, 0);
    if (updateRuntime->groundBaddie.baddie.controlMode == 6) {
        topState->icicle.meltTimer =
            -(timeDelta * (5.0f * obj->anim.currentMoveProgress + 1.0f) - topState->icicle.meltTimer);
    } else {
        topState->icicle.meltTimer = topState->icicle.meltTimer - timeDelta;
    }
    if (topState->icicle.meltTimer <= 0.0f) {
        DimBossMeltEntry* entry = gDIMbossMeltEntries;
        mainSetBits(entry[topState->meltEntryIndex].gameBit, 1);
        topState->icicle.meltTimer = entry[topState->meltEntryIndex].resetTime;
        topState->meltEntryIndex++;
        if (topState->meltEntryIndex > 0x17) {
            topState->meltEntryIndex = 0;
        }
    }
    if (tricky != NULL) {
        timer = topState->icicle.lightTimer;
        if (timer > 0.0f) {
            limit = 3600.0f;
            if (timer <= limit) {
                topState->icicle.lightTimer = timer + timeDelta;
                if (topState->icicle.lightTimer >= limit) {
                    TRICKY_INTERFACE(tricky)->commandPlayBall((GameObject*)tricky, 1, obj);
                }
            }
        }
        if (topState->icicle.fadeTimer > (timer = 0.0f)) {
            topState->icicle.fadeTimer = topState->icicle.fadeTimer + timeDelta;
            if (topState->icicle.fadeTimer >= 780.0f) {
                runtime->groundBaddie.flags400 &= ~DIMBOSS_STATE_FLAG_TARGET_TRICKY;
                topState->icicle.fadeTimer = timer;
                TRICKY_INTERFACE(tricky)->commandPlayBall((GameObject*)tricky, 0, NULL);
                topState->icicle.lightTimer = 1.0f;
            }
        } else if (runtime->groundBaddie.targetState == DIMBOSS_PHASE_LAUNCH_LIFT) {
            runtime->groundBaddie.flags400 |= DIMBOSS_STATE_FLAG_TARGET_TRICKY;
            topState->icicle.fadeTimer = 1.0f;
            DIMboss_createStateLight(obj, 0);
        }
    }
    if (runtime->groundBaddie.targetState == DIMBOSS_PHASE_GAMEBIT_COUNT_MET) {
        DIMboss_createStateLight(obj, 1);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT) {
        gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT;
        DIMboss_spawnBlueWhiteEffect(&((DIMbossTopState*)runtime->groundBaddie.control)->blueWhiteEffectSource,
                                        ((DIMbossTopState*)runtime->groundBaddie.control)->blueWhiteVelocity);
    }
    if (runtime->groundBaddie.flags400 & DIMBOSS_STATE_FLAG_TARGET_TRICKY) {
        gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE;
    }
    if (runtime->groundBaddie.targetState == DIMBOSS_PHASE_LAUNCH_LIFT) {
        TRICKY_INTERFACE(tricky)->sideCommandEnable((GameObject*)tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                   TRICKY_COMMAND_TYPE_DISTRACT);
        gameObj->hitVolumeIndex = 1;
    } else {
        gameObj->hitVolumeIndex = 2;
    }
    runtime->groundBaddie.savedPendingParentObj = gameObj->pendingParentObj;
    gameObj->pendingParentObj = 0;
    (*gPlayerInterface)
        ->update((void*)obj, updateRuntime, timeDelta, timeDelta, &gDIMbossHitDetectAnimTable, &gDIMbossAnimTable);
    gameObj->pendingParentObj = runtime->groundBaddie.savedPendingParentObj;
}

DimBossMeltEntry gDIMbossMeltEntries[] = {
    {120.0f, 2427}, {120.0f, 2428}, {240.0f, 2429}, {60.0f, 2430},  {30.0f, 2431},  {20.0f, 2432},
    {220.0f, 2427}, {120.0f, 2428}, {220.0f, 2429}, {20.0f, 2430},  {20.0f, 2431},  {20.0f, 2432},
    {120.0f, 2427}, {120.0f, 2428}, {120.0f, 2429}, {220.0f, 2430}, {220.0f, 2431}, {320.0f, 2432},
    {220.0f, 2427}, {20.0f, 2428},  {20.0f, 2429},  {50.0f, 2430},  {150.0f, 2431}, {90.0f, 2432},
};

int lbl_80325AA0[6] = {0x182, 0x183, 0x184, 0x185, 0x186, 0x187};

int gDIMbossSequenceSfx[] = {
    0x17B,
    0x17B,
    0x17C,
    0x17C,
};

Dim2BossMoveChoices gDim2LiftFarMoveChoices = {
    {1, 1, 8, 4, 5, 5},
    {3, 4, 3, 5, 4, 5, 6, 0},
    {5, 4, 3, 5, 4, 5, 6, 0},
    {4, 5, 4, 5, 4, 5, 6, 0},
};



#define DIMBOSS_OBJGROUP 3

#define DIMBOSS_ENVFX_A 0xdb
#define DIMBOSS_ENVFX_B 0xdc

ObjectDescriptor12 gDIM_BossObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    DIMboss_initialise,
    DIMboss_release,
    0,
    (ObjectDescriptorCallback)DIMboss_init,
    (ObjectDescriptorCallback)DIMboss_update,
    (ObjectDescriptorCallback)DIMboss_hitDetect,
    (ObjectDescriptorCallback)DIMboss_render,
    (ObjectDescriptorCallback)DIMboss_free,
    (ObjectDescriptorCallback)DIMboss_getObjectTypeId,
    DIMboss_getExtraSize,
    (ObjectDescriptorCallback)DIMboss_getControlMode,
    DIMboss_func0B,
};

char sDIMBossFreeingAssetsForDIMBoss[] = "<DIMBoss.c> freeing assets for DIMBoss\n";
char sDIMBossLoadingAssetsForDIMTop[] = "<DIMBoss.c> loading assets for DIMTop\n";

#define DIMBOSS_BONE_PARTICLE_EFFECT_800     0x800
#define DIMBOSS_BONE_PARTICLE_EFFECT_7FF     0x7FF
#define DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES 100
#define DIMBOSS_SPAWN_OBJECT_TIMER           0x3C

typedef struct DIMbossInitVec {
    u32 a;
    u32 b;
    u32 c;
} DIMbossInitVec;

static inline BoneParticleEffectInterface* DIMboss_GetBoneParticleEffectInterface(void) {
    return *gBoneParticleEffectInterface;
}

int DIMboss_updateState(GameObject* obj, u32 state, ObjSeqState* animUpdate) {
    DIMbossRuntime* runtime;
    DIMbossPlacementView* config;
    DIMbossTopState* topState;
    DIMbossAnimScratch* animScratch;
    int subMode;
    u8 loadWaitStarted;
    int updateResult;
    ObjModel* model;
    int mapDirIndex;
    u32 statusFlags;
    int eventIndex;
    int baddieResult;

    animScratch = (DIMbossAnimScratch*)gDIMbossAnimScratchBase;
    runtime = obj->extra;
    config = (DIMbossPlacementView*)obj->anim.placementData;
    updateResult = 0;
    Obj_GetPlayerObject();
    topState = runtime->groundBaddie.control;
    runtime->groundBaddie.targetState = DIMBOSS_PHASE_START;
    (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 0);
    if (obj->userData1 != 0) {
        return 0;
    }

    dll_2E_updateSequenceTurn(obj, animUpdate, (MoveLibState*)animScratch->animController, 1, 1);
    for (eventIndex = 0; eventIndex < (int)(u32)animUpdate->eventCount; eventIndex = eventIndex + 1) {
        switch (animUpdate->eventIds[eventIndex]) {
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_80000:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAG_80000;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_80000:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_80000;
            break;
        case DIMBOSS_EVENT_CLEAR_RENDER_ATTACHMENT:
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(obj, DIMBOSS_BONE_PARTICLE_EFFECT_800, NULL,
                                                                  DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(obj, DIMBOSS_BONE_PARTICLE_EFFECT_800, NULL,
                                                                  DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(obj, DIMBOSS_BONE_PARTICLE_EFFECT_7FF, NULL,
                                                                  DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(obj, DIMBOSS_BONE_PARTICLE_EFFECT_7FF, NULL,
                                                                  DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            model = Obj_GetActiveModel(obj);
            ObjModel_ClearRenderAttachment(model);
            Music_Trigger(DIMBOSS_MUSIC_LIFT_RUMBLE, 1);
            break;
        case DIMBOSS_EVENT_LAUNCH_LIFT:
            runtime->groundBaddie.targetState = DIMBOSS_PHASE_LAUNCH_LIFT;
            obj->anim.resetHitboxFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
            obj->anim.resetHitboxFlags |= DIMBOSS_OBJECT_FLAG_ACTIVE;
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_LIFT, 0);
            break;
        case DIMBOSS_EVENT_ENABLE_DIMBOSS_MAP_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_BOSS, 1);
            break;
        case DIMBOSS_EVENT_DISABLE_DIMBOSS_MAP_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_BOSS, 0);
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_40004:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAGS_40004;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0002:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0002;
            break;
        case DIMBOSS_EVENT_QUEUE_STEAM_SFX:
            topState = runtime->groundBaddie.control;
            topState->steamFlags.sfxPending = 1;
            Music_Trigger(DIMBOSS_MUSIC_STEAM_LOOP, 0);
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0040:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0040;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0040:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0080:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0080;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0100:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0100;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0100:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0100;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_2001:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAGS_2001;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_8021:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAGS_8021;
            break;
        case DIMBOSS_EVENT_TRIGGER_DEFEAT_FLAGS:
            topState->defeatTimer = DIMBOSS_DEFEAT_TIMER_START;
            mainSetBits(GAMEBIT_ITEM_FireSpellStone1_Got, 1);
            mainSetBits(DIMBOSS_GAMEBIT_DEFEAT_STATE_B, 1);
            Music_Trigger(DIMBOSS_MUSIC_LIFT_RUMBLE, 0);
            Music_Trigger(MUSICTRIG_Teleport, 0);
            Music_Trigger(DIMBOSS_MUSIC_STEAM_LOOP, 0);
            break;
        case DIMBOSS_EVENT_SPAWN_DIMBOSS_OBJECT:
            (*gObjectTriggerInterface)
                ->setCamVars(DIMBOSS_OBJECT_TYPE_ID, 4, (int)obj, DIMBOSS_SPAWN_OBJECT_TIMER);
            break;
        case DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS:
            OSReport(sDIMBossFreeingAssetsForDIMBoss);
            setLoadedFileFlags_blocks1();
            unlockLevel(0, 0, 1);
            mapDirIndex = mapGetDirIdx(DIMBOSS_MAP_DIR);
            mapUnload(mapDirIndex, DIMBOSS_MAP_UNLOAD_MASK);
            mapDirIndex = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
            mapUnload(mapDirIndex, DIMBOSS_GUT_MAP_UNLOAD_MASK);
            defragMemory(0);
            break;
        case DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS:
            OSReport(sDIMBossLoadingAssetsForDIMTop);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            lockLevel(mapDirIndex, 0);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_TEX1_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_TEX1_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_TEX0_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_TEX0_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_ANIM_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_ANIM_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_MODELS_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_MODELS_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_BLOCKS_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_BLOCKS_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_VOXMAP_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_VOXMAP_BIN_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_ANIMCURV_TAB_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, MLDF_FILEID_ANIMCURV_BIN_A);
            loadWaitStarted = false;
            while (statusFlags = getLoadedFileFlags(0), (int)(statusFlags & DIMTOP_LOAD_PENDING_FLAGS_MASK) != 0) {
                padUpdate();
                checkReset();
                if (loadWaitStarted) {
                    waitNextFrame();
                }
                loadDataFiles();
                dvdCheckError();
                if (loadWaitStarted) {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != '\0') {
                    loadWaitStarted = true;
                }
            }
            clearLoadedFileFlags_blocks1();
            break;
        }
    }
    if (obj->seqIndex != -1) {
        baddieResult = (*gBaddieControlInterface)->isObjectValid(obj, runtime, 1);
        if (baddieResult == 0) {
            return 1;
        }
        if (obj->childObjs[0] != NULL) {
            ((ObjAnimComponent*)obj->childObjs[0])->parent = obj->anim.parent;
        }
        if ((runtime->groundBaddie.gameBitC != -1) &&
            (statusFlags = mainGetBit((int)runtime->groundBaddie.gameBitC), statusFlags != 0)) {
            (*gObjectTriggerInterface)
                ->yield(animUpdate, config->eventId);
            runtime->groundBaddie.gameBitC = -1;
        }
        subMode = runtime->groundBaddie.subMode;
        switch (subMode) {
        case 0:
            break;
        case 2:
            animUpdate->flags = 0;
            DIMboss_updateCombatState(obj, animUpdate, runtime, runtime);
            if (runtime->groundBaddie.subMode == 1) {
                runtime->groundBaddie.baddie.substate = 0;
                (*gPlayerInterface)
                    ->update(obj, runtime, 1.0f, 1.0f, &animScratch->hitDetectAnimTable,
                             &animScratch->animTable);
                animUpdate->movementState = 0;
            }
            break;
        case 1:
            baddieResult = (*gBaddieControlInterface)->updateSequenceMovement(
                obj, animUpdate, (char*)runtime, &animScratch->hitDetectAnimTable, &animScratch->animTable, 0);
            if (baddieResult != 0) {
                (*gBaddieControlInterface)->updateGravity(obj, runtime, 0.17f, 1);
            }
            break;
        }
    }
    DIMboss_updateWarpAndEffects(obj, runtime);
    if (obj->seqIndex == -1) {
        runtime->groundBaddie.flags400 |= DIMBOSS_STATE_FLAG_START_MOVE;
        updateResult = 0;
    } else {
        updateResult = runtime->groundBaddie.subMode != 0;
    }
    return updateResult;
}

void DIMboss_func0B(void) {
}

int DIMboss_getControlMode(GameObject* obj) {
    return ((DIMbossRuntime*)obj->extra)->groundBaddie.baddie.controlMode;
}

int DIMboss_getExtraSize(void) {
    return sizeof(DIMbossRuntime) + sizeof(DIMbossTopState);
}

int DIMboss_getObjectTypeId(void) {
    return DIMBOSS_OBJECT_TYPE_ID;
}

void DIMboss_free(GameObject* obj) {
    DIMbossRuntime* runtime;
    GameObject* childObject;
    ModelLightStruct* effect;

    runtime = obj->extra;
    mainSetBits(GAMEBIT_SETPIECE_ACTIVE, 0);
    mainSetBits(0xc1e, 1);
    mainSetBits(0xc1f, 0);
    mainSetBits(0xc20, 0);
    mainSetBits(0xd8f, 0);
    mainSetBits(GAMEBIT_DIM_TriggerLostInBlizzard, 0);
    obj->anim.resetHitboxFlags &= ~DIMBOSS_OBJECT_FLAG_ACTIVE;
    CameraShake_Disable();
    objFreeObjectType(obj, DIMBOSS_OBJGROUP);
    childObject = obj->childObjs[0];
    if (childObject != NULL) {
        Obj_FreeObject(childObject);
        obj->childObjs[0] = NULL;
    }
    (*gBaddieControlInterface)->releaseState(obj, runtime, 0x20);
    if (gDIMbossHitEffectResource != 0) {
        Resource_Release(gDIMbossHitEffectResource);
    }
    gDIMbossHitEffectResource = 0;
    effect = ((DIMbossTopState*)runtime->groundBaddie.control)->effect;
    if (effect != NULL) {
        ModelLightStruct_free(effect);
    }
    Rcp_DisableHeatEffect();
}

void DIMboss_render(GameObject* obj, u32 renderArg2, u32 renderArg3, u32 renderArg4, u32 renderArg5, s8 shouldRender) {
    DIMbossRuntime* runtime;
    ModelLightStruct* effect;

    runtime = obj->extra;
    if (shouldRender == 0 || obj->userData1 != 0 ||
        runtime->groundBaddie.targetState == DIMBOSS_PHASE_NO_RENDER) {
        return;
    }

    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    DIMboss_updateSequenceEffects(obj, runtime);
    dll_2E_setTargetFromPathPoint(obj, &gDIMbossAnimController, 0);

    effect = ((DIMbossTopState*)runtime->groundBaddie.control)->effect;
    if (effect != NULL && effect->glowType != 0 && effect->enabled != 0) {
        queueGlowRender(effect);
    }
}

void DIMboss_hitDetect(GameObject* obj) {
    (*gPlayerInterface)->updateVelocityState(obj, obj->extra, &gDIMbossHitDetectAnimTable);
}

void DIMboss_update(GameObject* obj) {
    u32 gameBitCount;
    void* target;
    DIMbossTopState* topState;
    DIMbossRuntime* runtime;
    DIMbossPlacementView* config;
    ObjAnimComponent* childObject;

    runtime = obj->extra;
    config = (DIMbossPlacementView*)obj->anim.placementData;
    Obj_GetPlayerObject();
    topState = runtime->groundBaddie.control;
    if (obj->userData1 == 0) {
        if (topState->introSinkHeight > 0.0f) {
            gameTextShow(0x432);
            topState->introSinkHeight -= timeDelta;
            if (topState->introSinkHeight < 0.0f) {
                topState->introSinkHeight = 0.0f;
            }
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        if (obj->userData2 == 0) {
            obj->anim.localPosX = config->base.posX;
            obj->anim.localPosY = config->base.posY;
            obj->anim.localPosZ = config->base.posZ;
            (*gObjectTriggerInterface)->runSequence((int)config->animObjectId, obj, -1);
            obj->userData2 = 1;
        } else {
            if ((runtime->groundBaddie.flags400 & DIMBOSS_STATE_FLAG_START_MOVE) != 0) {
                (*gBaddieControlInterface)->startHitReaction(
                    obj, runtime, &runtime->groundBaddie.routeNav, runtime->groundBaddie.gameBitB,
                    &runtime->groundBaddie.subMode, 0, 0, 0, 1);
                runtime->groundBaddie.flags400 &= ~DIMBOSS_STATE_FLAG_START_MOVE;
                obj->anim.resetHitboxFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                obj->anim.resetHitboxFlags |= DIMBOSS_OBJECT_FLAG_ACTIVE;
                gameBitCount = mainGetBit(DIMBOSSTONSIL_HIT_GAMEBIT);
                if (gameBitCount >= 3) {
                    runtime->groundBaddie.targetState = DIMBOSS_PHASE_GAMEBIT_COUNT_MET;
                    runtime->groundBaddie.baddie.hitPoints = 3;
                    obj->anim.resetHitboxFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                    mainSetBits(DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE, 0);
                } else {
                    runtime->groundBaddie.targetState = DIMBOSS_PHASE_LAUNCH_LIFT;
                    runtime->groundBaddie.baddie.hitPoints = 3;
                    obj->anim.resetHitboxFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                    topState->launchLift = 1.0f;
                    mainSetBits(DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE, 1);
                }
            }
            if ((runtime->groundBaddie.targetState == DIMBOSS_PHASE_START) ||
                (runtime->groundBaddie.targetState == DIMBOSS_PHASE_NO_RENDER)) {
                if (topState->stompDustDelay != 0) {
                    topState->stompDustDelay--;
                    if (topState->stompDustDelay == 0) {
                        Obj_BuildWorldTransformMatrix(obj, gDIMbossRenderMtx, 0);
                        target = Obj_GetActiveModel(obj);
                        ObjModel_EnableDefaultRenderCallback(obj, (ObjModel*)target, gDIMbossRenderMtx, 1,
                                                             obj->anim.hitboxScale * obj->anim.rootMotionScale);
                    }
                }
                if (topState->steamFlags.sfxPending != 0) {
                    getEnvfxAct(0, 0, DIMBOSS_ENVFX_A, 0);
                    getEnvfxAct(0, 0, DIMBOSS_ENVFX_B, 0);
                    skySetLightsEnabled(7, 1, 0);
                    skySetLightDirection(7, 0.2f, -0.3f, -1.0f);
                    skySetBaseColor(7, 0xa0, 0xa0, 0xff, 0x7f, 0x28);
                    topState->steamFlags.sfxPending = 0;
                }
            } else {
                if ((runtime->groundBaddie.flags400 & DIMBOSS_STATE_FLAG_TARGET_TRICKY) != 0) {
                    target = getTrickyObject();
                    runtime->groundBaddie.baddie.targetObj = target;
                } else {
                    target = Obj_GetPlayerObject();
                    runtime->groundBaddie.baddie.targetObj = target;
                }
                childObject = obj->childObjs[0];
                if (childObject != NULL) {
                    childObject->parent = obj->anim.parent;
                }
                DIMboss_updateCombatState(obj, NULL, runtime, runtime);
                dll_2E_setLockTarget(&gDIMbossAnimController, runtime->groundBaddie.baddie.targetObj);
                dll_2E_updateLookAt(obj, &gDIMbossAnimController);
                DIMboss_updateWarpAndEffects(obj, runtime);
            }
        }
    }
}

void DIMboss_init(GameObject* obj, void* params, int isAltVariant) {
    DIMbossRuntime* runtime;
    DIMbossTopState* topState;
    u32 localVec[4];
    u8* animFlagsByte;
    u32 mapDir;
    u8 animFlags;
    f32 liftHeight;

    runtime = obj->extra;
    *(DIMbossInitVec*)localVec = *(DIMbossInitVec*)lbl_802C2338;
    *(u16*)(localVec + 3) = ((const u16*)lbl_802C2338)[6];
    setDrawCloudsAndLights(0);
    obj->hitVolumeIndex = 2;
    animFlags = 6;
    if (isAltVariant != 0) {
        animFlags |= 1;
    }
    (*gBaddieControlInterface)
        ->initGroundBaddie(obj, params, (u8*)runtime, 0xc, 6, 0x102, animFlags, 40.0f);
    obj->animEventCallback = (void*)DIMboss_updateState;
    runtime->groundBaddie.targetState = DIMBOSS_PHASE_START;
    (*gPlayerInterface)->setState(obj, runtime, 0);
    runtime->groundBaddie.baddie.substate = 0;
    runtime->groundBaddie.baddie.hitPoints = 3;
    obj->anim.resetHitboxFlags =
        (u8)(obj->anim.resetHitboxFlags | (DIMBOSS_OBJECT_FLAG_HIDDEN | DIMBOSS_OBJECT_FLAG_ACTIVE));
    if (mainGetBit(DIMBOSS_GAMEBIT_RENDER_PAUSE) != 0) {
        runtime->groundBaddie.targetState = DIMBOSS_PHASE_RENDER_PAUSE;
        obj->userData1 = 1;
    }
    if (mainGetBit(DIMBOSS_GAMEBIT_ICICLE_DEFEATED) != 0) {
        runtime->groundBaddie.targetState = DIMBOSS_PHASE_NO_RENDER;
    }
    topState = runtime->groundBaddie.control;
    liftHeight = 0.0f;
    topState->idleLift = liftHeight;
    topState->launchLift = liftHeight;
    obj->anim.activeMove = -1;
    topState->effect = NULL;
    gDimBossHitReactionIndex = 0;
    gDIMbossSequenceFlags = 0;
    mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 1);
    dll_2E_initState(obj, &gDIMbossAnimController, 0xffffd8e4, 0x1c71, 6);
    dll_2E_setMoveTables(&gDIMbossAnimController, &localVec, &localVec, 6);
    animFlagsByte = &gDIMbossAnimController.modeBits;
    *animFlagsByte |= 8;
    *animFlagsByte &= ~1;
    topState->steamFlags.sfxPending = 1;
    gDIMbossHitEffectResource = Resource_Acquire(DIMBOSS_HIT_EFFECT_ID, DIMBOSS_HIT_EFFECT_RESOURCE_COUNT);
    if (mainGetBit(GAMEBIT_DIM_ReachedBoss) == 0) {
        topState->stompDustDelay = 2;
        topState->introSinkHeight = 300.0f;
        (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 1);
    } else {
        (*gMapEventInterface)->setObjGroupStatus(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 0);
    }
    topState->defeatTimer = 0;
    if ((*gMapEventInterface)->getMapAct(7) == 2) {
        (*gMapEventInterface)->setMapAct(7, 3);
    }
    mainSetBits(GAMEBIT_SETPIECE_ACTIVE, 1);
    unlockLevel(0, 0, 1);
    mapDir = mapGetDirIdx(DIMBOSS_MAP_DIR);
    lockLevel(mapDir, 1);
    mapDir = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
    lockLevel(mapDir, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 0);
    Music_Trigger(MUSICTRIG_Teleport, 1);
    mainSetBits(DIM2_GAMEBIT_AREA_MUSIC_ACTIVE, 0);
    Music_Trigger(MUSICTRIG_WLC_Chambers, 0);
    Music_Trigger(MUSICTRIG_WLC_Puzzle_e0, 0);
}

void DIMboss_release(void) {
}

void DIMboss_initialise(void) {
    DIMboss_initialiseAnimTables();
}

void DIMboss_initialiseAnimTables(void) {
    DIMbossHitDetectAnimHandlerTable* hitDetectAnimTable;
    DIMbossAnimHandlerTable* animTable;

    hitDetectAnimTable = &gDIMbossHitDetectAnimTable;
    hitDetectAnimTable->resetIdleMove = DIMbossHitDetect_resetIdleMove;
    hitDetectAnimTable->applyForwardMove = DIMbossHitDetect_applyForwardMove;
    hitDetectAnimTable->trackTargetMove = DIMbossHitDetect_trackTargetMove;
    hitDetectAnimTable->randomSwipe = DIMbossHitDetect_randomSwipe;
    hitDetectAnimTable->blueWhiteEventCapture = DIMbossHitDetect_blueWhiteEventCapture;
    hitDetectAnimTable->blueWhiteCapture = DIMbossHitDetect_blueWhiteCapture;
    hitDetectAnimTable->breathBurst = DIMbossHitDetect_breathBurst;
    hitDetectAnimTable->lungeAttack = DIMbossHitDetect_lungeAttack;
    hitDetectAnimTable->chooseIdleTaunt = DIMbossHitDetect_chooseIdleTaunt;
    hitDetectAnimTable->liftImpact = DIMbossHitDetect_liftImpact;
    hitDetectAnimTable->liftSlam = DIMbossHitDetect_liftSlam;
    hitDetectAnimTable->tonsilSlam = DIMbossHitDetect_tonsilSlam;

    animTable = &gDIMbossAnimTable;
    animTable->selectTargetControlMode = DIMbossAnim_selectTargetControlMode;
    animTable->returnToIdleWhenDone = DIMbossAnim_returnToIdleWhenDone;
    animTable->hasMoveDone = DIMbossAnim_hasMoveDone;
    animTable->finishDefeat = DIMbossAnim_finishDefeat;
    animTable->updatePlayerHitReaction = DIMbossAnim_updatePlayerHitReaction;
    animTable->updateBossHitReaction = DIMbossAnim_updateBossHitReaction;
}

int gDIMbossHitCooldown;
StaffCollisionInterface** gDIMbossHitEffectResource;
u8 gDimBossHitReactionIndex;
u32 gDIMbossSequenceFlags;

DIMbossHitDetectAnimHandlerTable gDIMbossHitDetectAnimTable;
DIMbossAnimHandlerTable gDIMbossAnimTable;
MoveLibState gDIMbossAnimController;
f32 gDIMbossRenderMtx[12];
DIMbossEffectMarker gDIMbossHitFxBuffer;
PartFxSpawnParams gDIMbossDustFxSource;
f32 gDIMbossAnimScratchBase[3];

