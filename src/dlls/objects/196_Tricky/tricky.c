/*
 * Tricky companion DLL.
 *
 * Blend-channel weight animation (Tricky_updateBlendChannelWeight), the
 * impress fade (tricky_updateModelVariantFade / trickyImpress), queued-path particle emission
 * (Tricky_emitQueuedPathParticles), baddie target search
 * (trickyFindNearestUsableBaddie) and queued-command target selection
 * (trickySelectQueuedCommandTarget), plus small state accessors.
 */

#include "main/dll/partfx_interface.h"
#include "main/vecmath.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/tricky_state.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/model.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_0019_dll19func0.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/rom_curve_def.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/obj_list.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/objHitReact.h"
#include "main/objfx.h"
#include "main/dll/objfsa.h"
#include "main/gamebits.h"
#include "main/dll/skeetla.h"
#include "main/objprint_sound_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/baddie/trickyfollow.h"
#include "main/dll/objfsa_query_api.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0014_api.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/Hcurves_api.h"
#include "main/dll/baddie/MMP_critterspit.h"
#include "main/dll/mmp_cratercritter.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx.h"
#include "dlls/objects/243_flameblast.h"
#include "dlls/objects/235.h"
#include "dlls/objects/312_GroundAnima.h"
#include "main/dll/tumbleweedbush.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/dll/player_target.h"
#include "game/objects/object_setup.h"
#include "main/trig.h"
#include "main/frustum.h"
#include "dlls/objects/245_SidekickBal.h"
#include "dlls/objects/417_NW_mammoth.h"
#include "dlls/objects/429_SH_thorntai.h"
#include "main/dll/tricky_substates.h"
#include "dlls/objects/209_TumbleWeedB.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/dll/skeetla_route_api.h"
#include "main/dll/tricky_rollroute.h"
#include "main/game_ui_interface.h"
#include "main/sky_interface.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/pad.h"
#include "main/dll/tricky_api.h"
#include "main/objprint_api.h"
#include "main/dll/objfx_api.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/objanim.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/track_bbox_api.h"
#include "main/obj_path.h"
#include "main/model_light.h"
#include "dolphin/mtx.h"
#include "main/dll/cmenu_item_table.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/baddie_state.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state_api.h"
#include "main/dll/WC/WCbeacon.h"
#include "main/voxmaps.h"
#include "main/dll/DR/dll_026B_drchimmey.h"
#include "dlls/objects/452_DIMIceWall.h"
#include "dlls/objects/448_DIMLogFire.h"
#include "dlls/objects/465_DIMTruthHor.h"
#include "dlls/objects/435_SH_Beacon.h"
#include "dlls/objects/437.h"
#include "main/main_internal.h"
#include "main/dll/baddie_frozen.h"
#include "dlls/objects/316_XYZAnimator.h"
#include "main/dll/dll_0014_unk.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/pi_dolphin_path_api.h"
#include "main/newshadows_audio_api.h"

typedef struct {
    u16 a;
    u16 b;
} TrickySfxPair;

typedef struct TrickyBaddieTargetPlacement {
    u8 pad0[0x14];
    s32 mapEventId;
    s16 gateOffBit;
    s16 gateOnBit;
} TrickyBaddieTargetPlacement;

STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, mapEventId) == 0x14);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, gateOffBit) == 0x18);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, gateOnBit) == 0x1A);

static const u16 gTrickyInitialPathControlStartId[1] = {0x0A08};
static const TrickySfxPair sTrickyImpressSfxPair = {0x0356, 0x035C};
static const u16 gTrickyQuestPromptSfxIds[2] = {0x035A, 0x0351};
static const u16 gTrickySubstateSfxIdPairA[2] = {0x035C, 0x0361};
static const u16 gTrickySubstateSfxIdPairB[2] = {0x035C, 0x0361};
static const u16 gSkeetlaFootstepSfxIds01[2] = {0x0361, 0x0365};
static const u16 gSkeetlaFootstepSfxId2[1] = {0x0355};

extern f32 gTrickyEventTimeSentinel;
extern f32 gTrickyEventStaleSeconds;
extern f32 gTrickyMaxDistance;
extern f32 gTrickySpeedDecayStep;
extern f32 gTrickySmallSpeedStep;

extern const char sTrickyShouldNeverStopCirclingError[];

extern char sSidekickCommandDebugTextBlock[];

/* Repeated Tricky movement-animation contract values. */
#define TRICKY_FAST_MOVE_BLEND_SPEED       0.02f
#define TRICKY_LAND_MOVE_BLEND_SPEED       0.005f
#define TRICKY_TURN_MOVE_BLEND_SPEED       0.04f
#define TRICKY_TIMER_600_FRAMES            600.0f
#define TRICKY_WATER_COOLDOWN_FRAMES       TRICKY_TIMER_600_FRAMES
#define TRICKY_ROUTE_LOOKAHEAD_SCALE       1.5f
#define TRICKY_ROUTE_REVERSE_STEP          -2.0f
#define TRICKY_YAW_STEP_RATE               512.0f
#define TRICKY_AVOIDANCE_REPATH_EPSILON_SQ 0.0001f
#define TRICKY_TINY_MOVE_BLEND_SPEED       0.0001f
#define TRICKY_FAST_WALK_MOVE_THRESHOLD    0.66f
#define TRICKY_SLOW_WALK_MOVE_THRESHOLD    0.33f
#define TRICKY_PI                          3.1415927f
#define TRICKY_ANGLE_HALF_TURN_UNITS       32768.0f

#define TRICKY_STATE_FLAG_SIDESTEP               0x20  /* apply sidestepDelta lateral offset */
#define TRICKY_STATE_FLAG_BACKSTEP               0x40  /* apply backstepDelta offset */
#define TRICKY_STATE_FLAG_VERTICAL_MOVE          0x80  /* apply verticalDelta to localPosY */
#define TRICKY_STATE_FLAG_ROTATE                 0x100 /* interpolate rotation toward targetYaw target */
#define TRICKY_STATE_FLAG_COMMAND_ACTIVE         0x10u
#define TRICKY_STATE_FLAG_RECALL_REQUEST         0x10000u
#define TRICKY_STATE_FLAG_HEEL_REQUEST           0x20000u
#define TRICKY_STATE_FLAG_GUARD_REQUEST          0x40000u
#define TRICKY_STATE_FLAG_WARP_RETURNED          0x80000u
#define TRICKY_STATE_HEEL_RECALL_REQUEST_FLAGS   0x30002LL
#define TRICKY_STATE_FLAG_TURNING_U32            0x10000000
#define TRICKY_STATE_FLAG_TURNING                0x10000000LL
#define TRICKY_STATE_FLAG_SUN_VOICE_PLAYED_U32   0x20000000U
#define TRICKY_STATE_FLAG_SUN_VOICE_PLAYED       0x20000000LL
#define TRICKY_STATE_FLAG_FEED_VOICE_PENDING_U32 0x40000000
#define TRICKY_STATE_FLAG_FEED_VOICE_PENDING     0x40000000LL
#define TRICKY_STATE_FLAG_IMPRESS_PENDING_U32    0x80000000U
#define TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE    0x8000000LL

#define TRICKY_MOVE_FLAG_KEEP_PROGRESS        0x01000000
#define TRICKY_MOVE_FLAG_ROOT_TRANSLATE       0x02000000
#define TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION 0x04000000
#define TRICKY_MOVE_FLAG_WALK_LOOP            (TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_MOVE_FLAG_ROOT_TRANSLATE)
#define TRICKY_MOVE_FLAG_JUMP_ARC                                                                                      \
    (TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION | TRICKY_STATE_FLAG_BACKSTEP | TRICKY_STATE_FLAG_VERTICAL_MOVE)
#define TRICKY_MOVE_ACTIVE_FLAG_MASK 0x060001e0LL

#define TRICKY_COMMAND_FROM_STATE_BASE(base)             ((TrickyCommand*)((base) + offsetof(TrickyState, commands)))
#define TRICKY_COMMAND_TTL_FROM_STATE_BASE(base)         (*(s8*)((base) + offsetof(TrickyState, commands[0].ttl)))
#define TRICKY_FLAME_CHILD_FROM_STATE_BASE(base)         (*(GameObject**)((u8*)(base) + offsetof(TrickyState, flameChildren)))
#define TRICKY_RENDER_PATH_POINT_X_OFFSET                0x3D8
#define TRICKY_RENDER_PATH_POINT_Y_OFFSET                0x3DC
#define TRICKY_RENDER_PATH_POINT_Z_OFFSET                0x3E0
#define TRICKY_RENDER_PATH_POINT_X_FROM_STATE_BASE(base) ((float*)((base) + TRICKY_RENDER_PATH_POINT_X_OFFSET))
#define TRICKY_RENDER_PATH_POINT_Y_FROM_STATE_BASE(base) ((float*)((base) + TRICKY_RENDER_PATH_POINT_Y_OFFSET))
#define TRICKY_RENDER_PATH_POINT_Z_FROM_STATE_BASE(base) ((float*)((base) + TRICKY_RENDER_PATH_POINT_Z_OFFSET))
#define TRICKY_PATCH_ID_FROM_STATE_BASE(base)            (*(s16*)((base) + offsetof(TrickyState, patch)))
#define TRICKY_PATCH_TARGET_X_FROM_STATE_BASE(base)      (*(f32*)((base) + offsetof(TrickyState, patchTargets[0].x)))
#define TRICKY_PATCH_TARGET_Y_FROM_STATE_BASE(base)      (*(f32*)((base) + offsetof(TrickyState, patchTargets[0].y)))
#define TRICKY_PATCH_TARGET_Z_FROM_STATE_BASE(base)      (*(f32*)((base) + offsetof(TrickyState, patchTargets[0].z)))
#define OBJFSA_PATCH_GROUP_ID_FROM_INFO_BASE(base)       (*(u16*)((base) + offsetof(ObjfsaWalkGroupPatchInfo, patchGroupIds)))
#define TRICKY_CURVE_LINK_IDS_OFFSET                     0x1C
#define TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(node, off) (*(int*)((node) + (off) + TRICKY_CURVE_LINK_IDS_OFFSET))
#define TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(node, idx)  (((int*)((char*)(node) + TRICKY_CURVE_LINK_IDS_OFFSET))[idx])

/* The one partfx effect emitted along Tricky's queued impress path. */
#define TRICKY_PATH_PARTFX 0x533

#define TRICKY_BADDIE_TARGET_OBJGROUP 49 /* baddie object group scanned by trickyFindNearestUsableBaddie */
/* creatures excluded from Tricky's baddie targeting (retail OBJECTS.bin names). */
#define TRICKY_SEQID_WHIRLPOOL 2129 /* "Whirlpool" (DLL 0xC9) */
#define TRICKY_SEQID_VAMBAT    1022 /* "Vambat" (DLL 0xC9) */
#define TRICKY_SEQID_WB        1239 /* "WB" (DLL 0xC9) */
#define TRICKY_SEQID_PINPON    593  /* "PinPon" (DLL 0xC9) */

/* Bit setter at bit 6 (0x40) of obj->_b8->_58. */
void trickySetSoundSuppressed(GameObject* obj, int value) {
    ((TrickyState*)obj->extra)->soundSuppressed = value;
}

int trickyTryPlaySound(GameObject* obj, u16 sfxId, int volume) {
    TrickyState* state = obj->extra;
    s16 move;

    if (state->soundSuppressed) {
        return 0;
    }
    move = obj->anim.currentMove;
    switch (move) {
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) {
        return 0;
    }
    objSoundStartTimed(obj, &state->soundState, sfxId, volume, -1, 0);
    return 1;
}

void objAnimFreeChildren(GameObject* obj, TrickyState* state, GameObject** child) {
    char buf[4];
    void* childA;
    void* childB;
    void* zzzChild;

    if (*child == NULL) {
        return;
    }
    ObjLink_DetachChild(obj, *child);
    Obj_FreeObject(*child);
    *child = NULL;
    buf[0] = -1;
    buf[1] = -1;
    buf[2] = -1;
    childA = state->childA;
    if (childA != NULL) {
        buf[state->packedSlots.promptASlot] = 1;
    }
    childB = state->childB;
    if (childB != NULL) {
        buf[state->packedSlots.promptBSlot] = 1;
    }
    zzzChild = state->child;
    if (zzzChild != NULL) {
        buf[state->packedSlots.zzzSlot] = 1;
    }
    if (buf[0] == -1) {
        if (childA != NULL) {
            ObjLink_DetachChild(obj, childA);
            ObjLink_AttachChild(obj, state->childA, 0);
            state->packedSlots.promptASlot = 0;
        } else if (childB != NULL) {
            ObjLink_DetachChild(obj, childB);
            ObjLink_AttachChild(obj, state->childB, 0);
            state->packedSlots.promptBSlot = 0;
        } else if (zzzChild != NULL) {
            ObjLink_DetachChild(obj, zzzChild);
            ObjLink_AttachChild(obj, state->child, 0);
            state->packedSlots.zzzSlot = 0;
        }
    }
}

/* Weighted blend-channel animator. On blendPending, primes channel 1
 * (weight 0, target weight ratio in blendWeight) and latches blendActive.
 * While blendActive is set, ramps blendWeight toward data[0] / data[1] with
 * acceleration 0.004f and damping 0.7f, clamps to [0, 1.0f], and pushes the
 * result to the model's blend channel 1 as `2.0f * weight - 1.0f`. */
void Tricky_updateBlendChannelWeight(GameObject* obj, TrickyState* state) {
    ObjModel* model;
    f32 target;
    f32 max;
    Obj_GetActiveModel(obj);
    if (state->blendPending) {
        model = Obj_GetActiveModel(obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, 0.0f, 0x21);
        state->blendWeight = 10.0f;
        ObjModel_SetBlendChannelWeight(model, 0, 0.0f);
        state->blendPending = 0;
        state->blendActive = 1;
    }
    if (state->blendActive) {
        u8* data = state->progressPtr;
        target = (f32)(u32)data[0] / (f32)(u32)data[1];
        if (target > state->blendWeight) {
            state->blendVelocity = 0.004f * timeDelta + state->blendVelocity;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            if (state->blendWeight > (max = 1.0f)) {
                state->blendVelocity = 0.0f;
                state->blendWeight = max;
            } else if (state->blendWeight > target) {
                if (state->blendVelocity < 0.01f) {
                    state->blendVelocity = 0.0f;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= 0.7f;
                }
            }
        } else if (target < state->blendWeight) {
            state->blendVelocity = state->blendVelocity - 0.004f * timeDelta;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            if (state->blendWeight < 0.0f) {
                state->blendWeight = state->blendVelocity = 0.0f;
            }
            if (state->blendWeight < target) {
                if (state->blendVelocity > -0.01f) {
                    state->blendVelocity = 0.0f;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= 0.7f;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(Obj_GetActiveModel(obj), 1, 2.0f * state->blendWeight - 1.0f);
    }
}

void tricky_updateModelVariantFade(GameObject* obj, TrickyState* state) {
    u8 ratio = state->progressPtr[2] / 10;

    if (state->modelVariant != ratio) {
        f32 t;
        if (mainGetBit(1005) == 0) {
            mainSetBits(1005, 1);
            (*gObjectTriggerInterface)->runSequence(5, obj, -1);
            state->stateFlags |= 0x4000;
            state->variantFadeTimer += 20.0f;
        }
        state->variantFadeTimer -= timeDelta;
        t = state->variantFadeTimer;
        if (!(t > 20.0f)) {
            if (t > 0.0f) {
                f32 alpha;
                if (t > 10.0f) {
                    alpha = 1.0f - (t - 10.0f) / 10.0f;
                } else {
                    Obj_GetActiveModel(obj)->textureRefs->swapSelector = ratio;
                    alpha = state->variantFadeTimer / 10.0f;
                }
                Obj_SetModelColorOverrideRecursive(obj, 255, 255, 255, 196.0f * alpha, 1);
            } else {
                state->modelVariant = ratio;
                Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
            }
        }
    }
}

static inline int skeetla_isInWater(TrickyState* state) {
    if (0.0f == state->waterLevel) {
        return 0;
    }
    if (gTrickyEventTimeSentinel == state->eventTime) {
        return 1;
    }
    if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
        return 1;
    }
    return 0;
}

/* Latch the impress move and prime impressTimer. */
void trickyImpress(GameObject* obj) {
    TrickyState* state = obj->extra;
    state->stateFlags |= TRICKY_STATE_FLAG_IMPRESS_PENDING_U32;
    state->impressTimer = 20.0f;
}

/* GameBit-gated recall request. Returns 1 only when Tricky is already in an active command. */
int Tricky_requestRecallAndCheckBusy(GameObject* obj) {
    TrickyState* state = obj->extra;
    if ((u32)mainGetBit(GAMEBIT_Tricky_Usable) != 0u) {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0u) {
            return 1;
        }
    }
    return 0;
}

PPCWGPipe GXWGFifo : (0xCC008000);

f32 trickyGetAnimSpeed(GameObject* obj) {
    return ((TrickyState*)obj->extra)->speed;
}

GameObject* trickyGetStayPoint(GameObject* obj) {
    return ((TrickyState*)obj->extra)->followObj;
}
int trickyGetAimPitchOffset(GameObject* obj) {
    return ((TrickyState*)obj->extra)->modelAnchorRotY;
}
f32* trickyGetQueuedPathParticlePos(GameObject* obj) {
    return &((TrickyState*)obj->extra)->renderPosX;
}

GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes) {
    GameObject** objs;
    GameObject** tmpList;
    GameObject* closest;
    int i;
    f32 bestDistSq;
    int count;

    bestDistSq = maxRadius;
    closest = 0;
    tmpList = (GameObject**)objGetAllOfType(3, &count);
    bestDistSq = bestDistSq * bestDistSq;
    i = 0;
    objs = tmpList;

    for (; i < count; objs++, i++) {
        TrickyBaddieTargetPlacement* placement;
        f32 obj_extra;
        int v1, v2;
        s32 g1, g2;

        if (dll_19_isBaddieControlObject(*objs) != 0) {
            obj_extra = (*gBaddieControlInterface)->getHealthFraction(*objs);
        } else {
            obj_extra = enemy_getHealthFraction(*objs);
        }

        placement = (TrickyBaddieTargetPlacement*)(*objs)->anim.placementData;
        g1 = placement->gateOffBit;
        if (g1 == -1) {
            v1 = 0;
        } else {
            v1 = mainGetBit(g1);
        }
        g2 = placement->gateOnBit;
        if (g2 == -1) {
            v2 = 1;
        } else {
            v2 = mainGetBit(g2);
        }

        if (objIsObjectType(*objs, TRICKY_BADDIE_TARGET_OBJGROUP) == 0 && obj_extra > 0.0f && v1 == 0 && v2 != 0) {
            if ((*objs)->anim.romDefNo != TRICKY_SEQID_WHIRLPOOL) {
                if ((*gMapEventInterface)->shouldNotSaveTime(placement->mapEventId) != 0) {
                    if (allowSpecialTypes == 0) {
                        s16 m = (*objs)->anim.romDefNo;
                        if (m == TRICKY_SEQID_VAMBAT || m == TRICKY_SEQID_WB ||
                            m == DLL1B5_SEQUENCE_ID_SC_BABY_LIGHTFOOT || m == TRICKY_SEQID_PINPON) {
                            continue;
                        }
                    }
                    {
                        f32 dist = vec3f_distanceSquared(&origin->anim.worldPosX, &(*objs)->anim.worldPosX);
                        if (dist < bestDistSq) {
                            bestDistSq = dist;
                            closest = *objs;
                        }
                    }
                }
            }
        }
    }
    return closest;
}

void Tricky_emitQueuedPathParticles(GameObject* obj, TrickyState* state) {
    struct {
        s16 hx, hy, hz;
        f32 fk;
        f32 dx, dy, dz;
    } stk;
    u8 i = 0x14;
    u32 flags = state->stateFlags;
    if ((flags & 0x1800) == 0) {
        return;
    }
    stk.dx = state->renderPosX - obj->anim.worldPosX;
    stk.dy = state->renderPosY - obj->anim.worldPosY;
    stk.dz = state->renderPosZ - obj->anim.worldPosZ;
    stk.fk = 1.0f;
    stk.hx = obj->anim.rotX;
    stk.hy = obj->anim.rotY;
    stk.hz = obj->anim.rotZ;
    if ((flags & 0x800) == 0) {
        while (i-- != 0) {
            (*gPartfxInterface)->spawnObject(obj, TRICKY_PATH_PARTFX, &stk, 2, -1, NULL);
        }
        state->stateFlags = state->stateFlags & ~0x1000LL;
    }
}

__declspec(section ".sdata2") f32 gTrickyEventTimeSentinel = -100000.0f;
__declspec(section ".sdata2") f32 gTrickyEventStaleSeconds = 8.0f;
__declspec(section ".sdata2") f32 gTrickyMaxDistance = 340282346638528859811704183484516925440.0f;
__declspec(section ".sdata2") f32 gTrickySpeedDecayStep = -0.15f;
__declspec(section ".sdata2") f32 gTrickySmallSpeedStep = 0.05f;

int trickySelectQueuedCommandTarget(TrickyState* state, int commandType) {
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    int ref;
    int i;
    GameObject* bestPriorityTarget;
    GameObject* bestFallbackTarget;

    bestPriorityDist = gTrickyMaxDistance;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (i = 0, ref = (int)state; i < state->commandCount; ref += 8, i++) {
        if (TRICKY_COMMAND_FROM_STATE_BASE(ref)->type == commandType) {
            f32 dist = getXZDistanceSquared(&state->playerObj->anim.worldPosX,
                                            &TRICKY_COMMAND_FROM_STATE_BASE(ref)->targetObj->anim.worldPosX);

            if (TRICKY_COMMAND_FROM_STATE_BASE(ref)->kind == TRICKY_COMMAND_KIND_PRIORITY) {
                if (dist < bestPriorityDist) {
                    bestPriorityDist = dist;
                    bestPriorityTarget = TRICKY_COMMAND_FROM_STATE_BASE(ref)->targetObj;
                }
            } else if (dist < bestFallbackDist) {
                bestFallbackDist = dist;
                bestFallbackTarget = TRICKY_COMMAND_FROM_STATE_BASE(ref)->targetObj;
            }
        }
    }

    if (bestPriorityTarget != NULL) {
        state->followObj = bestPriorityTarget;
    } else {
        if (bestFallbackTarget == NULL) {
            return 0;
        }
        state->followObj = bestFallbackTarget;
    }

    {
        f32* targetPos = &state->followObj->anim.worldPosX;
        if (state->targetPosPtr != targetPos) {
            state->targetPosPtr = targetPos;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
    }

    state->substate = 0;
    return 1;
}

/*
 * Tricky per-frame collision, ground
 * snapping and path-control update.
 *
 * trickyUpdateCollisionAndPathState snaps Tricky to the ground, applies water
 * buoyancy, processes priority hits (lighting fx, hit sparks, out-of-water
 * bark), then drives the path-control interface and copies the resulting
 * yaw/roll back onto the object. trickyAdvanceRouteTargetAhead walks the
 * RomCurve route target forward and trickyTurnTowardYaw eases the object's
 * facing toward a requested yaw.
 */

/* group owned by another DLL, queried here */
#define SIDEREPEL_OBJGROUP      0x40 /* DLL 0xEB siderepel */
#define SKEETLA_TARGET_OBJGROUP 5
/* Per-node fan-out limit: status[]/bestDistances[]/outRoutes[] hold at most
 * this many linked route candidates (status[8] / f32 bestDistances[8]). */
#define TRICKY_ROUTE_CANDIDATE_COUNT   8
#define SKEETLA_LINKED_SOURCE_ID_OBJ_A 0x1ca
#define SKEETLA_LINKED_SOURCE_ID_OBJ_B 0x160
#define SKEETLA_PARTICLE_SPARK_A       0xca
#define SKEETLA_PARTICLE_SPARK_B       0xcb

/* attacker romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define SKEETLA_ATTACKER_SEQID_STAFF 0x69
/* "staff" (DLL 0xE2) */
#define SKEETLA_PARTICLE_SPAWN_FLAGS 0x200001
#define SKEETLA_PARTICLE_RANDOM_RATE 4
void tricky_state06_nop(void);
void trickyFlame();
void trickyGuard();
void tricky_moveToFollowTarget();
void tricky_idleAndEat();
void tricky_fetchBall();
void trickyUpdateCirclingTargetPosition();
void trickyUpdateCircling();
void tricky_trackTumbleweed();

typedef void (*TrickyStateHandler)(void* obj, void* state);

#define TRICKY_HANDLER_TABLE_OFFSET          0x24
#define TRICKY_SUBSTATE_HANDLER_TABLE_OFFSET 0x6c

typedef enum TrickyDebugStringOffset {
    TRICKY_DBG_IN_WATER = 0x184,
    TRICKY_DBG_OUT_OF_WATER = 0x190,
    TRICKY_DBG_MOVE_OUT_OF_WATER = 0x1a0,
    TRICKY_DBG_TURN_IN_WATER = 0x1bc,
    TRICKY_DBG_TURN_OUT_OF_WATER = 0x1d0,
    TRICKY_DBG_WALK_GROUP_STATUS = 0x1e8,
    TRICKY_DBG_ZERO_ACTIVE_WALK_GROUP = 0x214,
    TRICKY_DBG_SPEED_UPDATE = 0x268,
    TRICKY_DBG_TARGET_IN_WALKGROUP_OR_PATCH = 0x284,
    TRICKY_DBG_TARGET_OUTSIDE_WALKGROUP_AND_PATCHES = 0x2b0,
    TRICKY_DBG_TARGET_PATCH_GROUP = 0x2e4,
    TRICKY_DBG_PATCH_LAST_XYZ = 0x308,
    TRICKY_DBG_LAST_PATCH_POINT = 0x328,
    TRICKY_DBG_NOT_IN_WALKGROUP_OR_PATCH = 0x344,
    TRICKY_DBG_PATCH_ROUTE_ERROR = 0x374,
    TRICKY_DBG_PATCH_ROUTE_ERROR_2 = 0x3ec,
    TRICKY_DBG_MOVEMENT_STATE = 0x404,
    TRICKY_DBG_WALK_WAIT = 0x41c,
    TRICKY_DBG_WALK_FREE = 0x428,
    TRICKY_DBG_WALK_START_PATCH = 0x434,
    TRICKY_DBG_WALK_PATCH_EXIT = 0x448,
    TRICKY_DBG_WALK_END_PATCH = 0x45c,
    TRICKY_DBG_WALK_TO_NODE = 0x46c,
    TRICKY_DBG_CURVE_SETUP = 0x480,
    TRICKY_DBG_WALK_NODES = 0x490,
    TRICKY_DBG_JUMP_RUN_UP = 0x49c,
    TRICKY_DBG_JUMP_PREP = 0x4ac,
    TRICKY_DBG_JUMPING = 0x4b8,
    TRICKY_DBG_JUMP_UP_RUN_UP = 0x4c4,
    TRICKY_DBG_JUMP_DOWN_OR_UP = 0x4d4,
    TRICKY_DBG_JUMPDOWN_RUNUP = 0x4e8,
    TRICKY_DBG_INVALID_MOVEMENT_STATE = 0x4f8,
    TRICKY_DBG_GROWLAT_GOTO = 0x558,
    TRICKY_DBG_GROWLAT_GROWLING = 0x568,
    TRICKY_DBG_GROWLAT_GOTOFLAME = 0x57c,
    TRICKY_DBG_GROWLAT_FLAME = 0x590,
    TRICKY_DBG_BADDIEALERT_GOTO = 0x5a0,
    TRICKY_DBG_BADDIEALERT_BARK = 0x5b4,
    TRICKY_DBG_BADDIEALERT_GOTOFLAME = 0x5cc,
    TRICKY_DBG_BADDIEALERT_FLAME = 0x5e4,
    TRICKY_DBG_GUARD_INIT = 0x648,
    TRICKY_DBG_GUARD_FINDING = 0x654,
    TRICKY_DBG_GUARD_TOSPOT = 0x664,
    TRICKY_DBG_GUARD_TOFRONT = 0x674,
    TRICKY_DBG_GUARD_TOBADDIE = 0x684,
    TRICKY_DBG_GUARD_FLAME = 0x694,
    TRICKY_DBG_GUARD_DOWNTOGROWL = 0x6a4,
    TRICKY_DBG_GUARD_GROWL = 0x6b8,
    TRICKY_DBG_GUARD_UPFROMGROWL = 0x6c8,
    TRICKY_DBG_FLAME_NONE = 0x700,
    TRICKY_DBG_FLAME_FINDING_OUT = 0x70c,
    TRICKY_DBG_FLAME_GOINGTOEDGE = 0x720,
    TRICKY_DBG_FLAME_TOSTART = 0x734,
    TRICKY_DBG_FLAME_OUT = 0x744,
    TRICKY_DBG_FLAME_FINDING_IN = 0x750,
    TRICKY_DBG_FLAME_TURNING_IN = 0x764,
    TRICKY_DBG_FLAME_IN = 0x778,
    TRICKY_DBG_FLAME_TOEND = 0x784,
    TRICKY_DBG_DIGTUNNEL_FINDING = 0x7b8,
    TRICKY_DBG_DIGTUNNEL_GOINGTOSTART = 0x7cc,
    TRICKY_DBG_DIGTUNNEL_DIGGING = 0x7e4,
    TRICKY_DBG_DIGTUNNEL_TOEND1 = 0x7f8,
    TRICKY_DBG_DIGTUNNEL_TOEND2 = 0x810,
    TRICKY_DBG_DIGTUNNEL_WAIT = 0x824,
    TRICKY_DBG_SIDECOMMAND_HITS = 0x894,
    TRICKY_DBG_SIDECOMMAND_ENERGY = 0x8b4,
    TRICKY_DBG_COMMAND_WRONG_OBJECT = 0x8c4,
} TrickyDebugStringOffset;

typedef enum TrickyStateId {
    TRICKY_STATE_ATTACH_TO_WALKGROUP = 0,
    TRICKY_STATE_FOLLOW_PLAYER = 1,
    TRICKY_STATE_FIND_SECRET_DIG = 2,
    TRICKY_STATE_DIG_TUNNEL = 3,
    TRICKY_STATE_NOP_4 = 4,
    TRICKY_STATE_BALL_ROLL = 5,
    TRICKY_STATE_NOP_6 = 6,
    TRICKY_STATE_FLAME = 7,
    TRICKY_STATE_GUARD = 8,
    TRICKY_STATE_MOVE_TO_FOLLOW_TARGET = 9,
    TRICKY_STATE_IDLE_AND_EAT = 10,
    TRICKY_STATE_FETCH_BALL = 11,
    TRICKY_STATE_CIRCLING_TARGET_POS = 12,
    TRICKY_STATE_CIRCLING = 13,
    TRICKY_STATE_GROWL = 14,
    TRICKY_STATE_IDLE_WANDER = 15,
    TRICKY_STATE_TRACK_TUMBLEWEED = 16,
    TRICKY_STATE_GO_TO_WARP_POINT = 17,
} TrickyStateId;

char gTrickyDebugStringTable[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x41, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

f32 gTrickyPathPointCollision[3] = {0.0f, 0.0f, 0.0f};

TrickyStateHandler gTrickyStateHandlers[] = {
    (TrickyStateHandler)tricky_attachToWalkGroup,
    (TrickyStateHandler)tricky_stateFollowPlayer,
    (TrickyStateHandler)tricky_stateFindSecretDig,
    (TrickyStateHandler)trickyDigTunnel,
    (TrickyStateHandler)tricky_state04_nop,
    (TrickyStateHandler)tricky_updateBallRoll,
    (TrickyStateHandler)tricky_state06_nop,
    (TrickyStateHandler)trickyFlame,
    (TrickyStateHandler)trickyGuard,
    (TrickyStateHandler)tricky_moveToFollowTarget,
    (TrickyStateHandler)tricky_idleAndEat,
    (TrickyStateHandler)tricky_fetchBall,
    (TrickyStateHandler)trickyUpdateCirclingTargetPosition,
    (TrickyStateHandler)trickyUpdateCircling,
    (TrickyStateHandler)trickyGrowl,
    (TrickyStateHandler)tricky_stateIdleWander,
    (TrickyStateHandler)tricky_trackTumbleweed,
    (TrickyStateHandler)tricky_stateGoToWarpPoint,
    (TrickyStateHandler)tricky_substateFollowIdle,
    (TrickyStateHandler)tricky_substateReturnToHeel,
    (TrickyStateHandler)tricky_substateWaitQueuedMove,
    (TrickyStateHandler)tricky_substateSleep,
    (TrickyStateHandler)tricky_substateHowlCall,
    (TrickyStateHandler)tricky_substateWaitMoveEnd,
    (TrickyStateHandler)tricky_substateFidgetB,
    (TrickyStateHandler)tricky_substateFidgetA,
    (TrickyStateHandler)tricky_substateIdlePick,
    (TrickyStateHandler)tricky_substateDigForFood,
    (TrickyStateHandler)tricky_substateBegForFood,
    (TrickyStateHandler)tricky_substateFlameBreath,
    (TrickyStateHandler)tricky_substateApproachThorntail,
};

ObjectDescriptor21 gTrickyObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_20_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)Tricky_init,
        (ObjectDescriptorCallback)Tricky_update,
        (ObjectDescriptorCallback)Tricky_hitDetect,
        (ObjectDescriptorCallback)Tricky_render,
        (ObjectDescriptorCallback)Tricky_free,
        0,
        (ObjectDescriptorExtraSizeCallback)Tricky_getExtraSize,
        (ObjectDescriptorCallback)Tricky_getAvailableCommands,
        (ObjectDescriptorCallback)Tricky_updateSideCommandPrompts,
        (ObjectDescriptorCallback)sideCommandEnable,
        (ObjectDescriptorCallback)Tricky_getEnergy,
        (ObjectDescriptorCallback)Tricky_getEnergyMax,
        (ObjectDescriptorCallback)Tricky_commandPlayBall,
        (ObjectDescriptorCallback)Tricky_requestMoveToObject,
        (ObjectDescriptorCallback)Tricky_requestRecall,
        (ObjectDescriptorCallback)Tricky_isPlayingBall,
        (ObjectDescriptorCallback)Tricky_isGuarding,
    },
    (ObjectDescriptorCallback)Tricky_getCurrentCommandType,
};

void trickyUpdateCollisionAndPathState(GameObject* obj) {
    TrickyState* state;
    f32 hitOffsetY;
    GameObject* lastContactObj;
    f32 nearestDistance;
    f32 hitPos[3];
    f32 lightArgs[3];
    f32* hitPosPtr;
    u8 doGroundSnap;
    int doHeightSnap;
    int hitKind;

    state = (TrickyState*)obj->extra;
    doGroundSnap = 0;
    nearestDistance = 100.0f;

    if ((objPosToMapBlockIdx(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ) == -1) &&
        ((state->stateFlags & 0x80000) == 0)) {
        state->heightUpdateActive = 0;
        obj->anim.localPosX = obj->anim.previousLocalPosX;
        obj->anim.localPosY = obj->anim.previousLocalPosY;
        obj->anim.localPosZ = obj->anim.previousLocalPosZ;
    }

    state->stateFlags &= ~0x80000LL;

    if (state->groundSnapCounter != 0) {
        state->groundSnapCounter -= 1;
        doGroundSnap = 1;
    } else if ((state->stateFlags & 0x2000) != 0) {
        doGroundSnap = 1;
    }

    if (doGroundSnap != 0) {
        trackGetNearestGroundOffset(obj, obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, &hitOffsetY, 0);
        obj->anim.localPosY -= hitOffsetY;
        state->heightUpdateActive = 0;
    }

    if (((s8)state->heightUpdateActive != 0) && (state->heightTracking == 0u)) {
        if (0.0f == state->waterLevel) {
            doHeightSnap = 0;
        } else if (gTrickyEventTimeSentinel == state->eventTime) {
            doHeightSnap = 1;
        } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
            doHeightSnap = 1;
        } else {
            doHeightSnap = 0;
        }

        if (doHeightSnap != 0) {
            obj->anim.velocityY = 0.0f;
            obj->anim.localPosY = state->currentTime - 0.01f;
        } else {
            obj->anim.velocityY += -0.17f * timeDelta;
            obj->anim.localPosY += obj->anim.velocityY * timeDelta;
        }
    } else {
        obj->anim.velocityY = 0.0f;
    }

    lastContactObj = (GameObject*)obj->anim.hitReactState->activeHit;
    if (((obj->anim.hitReactState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) == 0) ||
        (lastContactObj->anim.romDefNo == 0x1f)) {
        lastContactObj = NULL;
    }

    if ((state->stateFlags & 8) != 0) {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= 40.0f) {
            if (vec3f_distanceSquared(&obj->anim.worldPosX, &Obj_GetPlayerObject()->anim.worldPosX) > 400.0f) {
                state->contactTimer -= 40.0f;
                obj->anim.modelInstance->runtimeSourceHitMask = 0x7f;
                state->stateFlags &= ~8LL;
            }
        }
    } else if ((state->lastContactObj != NULL) && (lastContactObj == state->lastContactObj)) {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= 10.0f) {
            state->contactTimer -= 10.0f;
            state->stateFlags |= 8;
            obj->anim.modelInstance->runtimeSourceHitMask = 0x7e;
        }
    } else {
        state->contactTimer = 0.0f;
    }

    state->lastContactObj = lastContactObj;
    hitKind = ObjHits_PollPriorityHitWithCooldown(obj, &state->hitCooldown, &lastContactObj, (hitPosPtr = hitPos));
    state->light = hitKind;

    switch (state->light) {
    case 1:
    case 2:
    case 4:
    case 5:
    case 0xe:
    case 0xf:
    case 0x11:
    case 0x13:
        objDoHitParticleFx(obj, 0.014f, lightArgs, 1, 0);
        break;
    case 7:
    case 8:
    case 9:
    case 0xa:
    case 0xb:
    case 0xc:
        objfx_spawnHitEmitterAtPos(hitPosPtr, 8, 0xff, 0x20, 0x20);
        objDoHitParticleFx(obj, 0.014f, lightArgs, 4, 0);
        if (lastContactObj->anim.romDefNo == SKEETLA_ATTACKER_SEQID_STAFF) {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
        }
        break;
    case 0x1f:
        state->particleTimer = 300.0f;
        break;
    }

    if ((s8)state->heightUpdateActive == 0) {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
    }

    if ((coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ) == 0xe) ||
        (objGetNearestTypeTo(SKEETLA_TARGET_OBJGROUP, obj, &nearestDistance) != NULL)) {
        state->pathControlFlags &= ~4;
    } else {
        state->pathControlFlags |= 4;
    }

    (*gPathControlInterface)->update(obj, &state->pathControlFlags, timeDelta);
    (*gPathControlInterface)->apply(obj, &state->pathControlFlags);
    (*gPathControlInterface)->advance(obj, &state->pathControlFlags, timeDelta);

    obj->anim.rotY = state->pathRotY;
    obj->anim.rotZ = state->pathRotZ;
}

int trickyAdvanceRouteTargetAhead(GameObject* obj, RomCurveWalker* route, f32 speed) {
    f32 limit;
    f32 maxSq, dist, step;
    int iter;
    int result;
    f32 maxDist;

    result = 0;
    maxDist = TRICKY_ROUTE_LOOKAHEAD_SCALE * (speed * timeDelta);
    maxSq = maxDist * maxDist;
    dist = getXZDistanceSquared(&route->posX, &obj->anim.worldPosX);
    if (route->reverse != 0) {
        step = TRICKY_ROUTE_REVERSE_STEP;
    } else {
        step = 2.0f;
    }
    iter = 0;
    limit = 100.0f;
    for (; iter < 5; iter++) {
        if (dist > limit && maxSq < dist) {
            return result;
        }
        result = 1;
        RomCurve_stepClamped(route, step);
        dist = getXZDistanceSquared(&route->posX, &obj->anim.worldPosX);
    }
    return 1;
}

int trickyTurnTowardYaw(GameObject* obj, s16 targetYaw) {
    TrickyState* state;
    int currentYaw;
    int wrappedYaw;
    int delta;
    int step;

    state = obj->extra;
    state->targetYaw = targetYaw;

    wrappedYaw = (u16)(s16)targetYaw;
    currentYaw = obj->anim.rotX;
    delta = currentYaw - wrappedYaw;
    if (delta > 0x8000) {
        delta -= 0xffff;
    }
    if (delta < -0x8000) {
        delta += 0xffff;
    }

    if ((state->stateFlags & 0x100000) != 0) {
        state->stateFlags |= 0x200000LL;
    } else {
        state->stateFlags &= ~0x200000LL;
    }
    state->stateFlags &= 0xef2fffff;

    if (delta > 0x10) {
        state->stateFlags |= 0x900000LL;
    } else if (delta < -0x10) {
        state->stateFlags |= 0x500000LL;
    } else {
        obj->anim.rotX = targetYaw;
        return 0;
    }

    if (delta > 0x200) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw - step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else if (delta < -0x200) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw + step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else {
        obj->anim.rotX = targetYaw;
    }

    return delta;
}

/*
 * Tricky steering, animation selection and RomCurve route walking.
 *
 * moveTricky steers toward a target point with object-avoidance
 * (trickyApplyObjectAvoidanceToStep) and picks a walk/run/turn anim plus
 * footstep sfx by speed. The RomCurve helpers (trickySelectRouteEntry and
 * friends) choose and walk the spline route Tricky follows, gated by game
 * bits on each curve. skeetla_spawnLinkedSparks emits the contact-spark
 * particles for the object Tricky is linked to.
 */

f32 gTrickyPathControlSetupParams[2] = {0.05f, 8.5f};
f32 gTrickyPathPointCollisionRadius = 8.0f;
char sSkeetlaVelDebugFmt[] = "Vel %f\n";
char sSkeetlaVelDebugPadding[4] = "";

/* group owned by another DLL, queried here */

/* Per-node fan-out limit: status[]/bestDistances[]/outRoutes[] hold at most
 * this many linked route candidates (status[8] / f32 bestDistances[8]). */

/* attacker romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */

static inline f32 skeetla_pathSpeedDelta(GameObject* obj) {
    TrickyState* state = (TrickyState*)obj->extra;
    f32* currentPathPoint;
    f32 dx;
    f32 dz;
    f32 previousSpeed;
    f32 currentSpeed;

    currentPathPoint = state->targetPosPtr;
    if (state->targetPosPtr == state->previousPathPoint) {
        dx = state->previousPathX - obj->anim.worldPosX;
        dz = state->previousPathZ - obj->anim.worldPosZ;
        previousSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));

        dx = currentPathPoint[0] - obj->anim.worldPosX;
        dz = currentPathPoint[2] - obj->anim.worldPosZ;
        currentSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));
        return currentSpeed - previousSpeed;
    }
    return 0.0f;
}

static inline void skeetla_updateFacingFromMoveVector(GameObject* obj, s16* turnDeltaOut) {
    TrickyState* state;
    int yaw;

    state = (TrickyState*)obj->extra;

    if (((state->dirX * state->dirX) + (state->dirZ * state->dirZ)) > 0.01f) {
        yaw = (s16)getAngle(-state->dirX, -state->dirZ);
        *turnDeltaOut = trickyTurnTowardYaw(obj, yaw);
        state->dirX = -mathSinf((TRICKY_PI * (f32)(int)*(s16*)obj) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->dirZ = -mathCosf((TRICKY_PI * (f32)(int)*(s16*)obj) / TRICKY_ANGLE_HALF_TURN_UNITS);
    }
}

static inline void skeetla_faceMoveVector(GameObject* obj) {
    s16 ignoredTurnDelta;

    skeetla_updateFacingFromMoveVector(obj, &ignoredTurnDelta);
}

static inline void skeetla_playFootstepSfx(GameObject* obj, u16 sfxId) {
    TrickyState* state = obj->extra;
    if (((TrickyState*)obj->extra)->soundSuppressed == 0u &&
        ((obj->anim.currentMove >= 0x30) || (obj->anim.currentMove < 0x29)) &&
        (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)) {
        objSoundStartTimed(obj, &state->soundState, sfxId, 0x500, -1, 0);
    }
}

int moveTricky(GameObject* obj, f32* targetPos) {
    f32 prospectivePos[3];
    f32 adjustedPos[3];
    u16 sfxIds[3];
    u16 sfxId;
    char* debugStrings;
    TrickyState* state;
    f32 moveSpeed;
    f32 length;
    int td;

    debugStrings = gTrickyDebugStringTable;
    state = obj->extra;
    moveSpeed = state->speed;
    trickyDebugPrint(sSkeetlaVelDebugFmt, moveSpeed);

    state->dirX = targetPos[0] - obj->anim.worldPosX;
    state->dirZ = targetPos[2] - obj->anim.worldPosZ;
    length = sqrtf((state->dirX * state->dirX) + (state->dirZ * state->dirZ));
    if (0.0f != length) {
        state->dirX /= length;
        state->dirZ /= length;
    }

    if (moveSpeed < 0.05f) {
        prospectivePos[0] = (0.05f * state->dirX) * timeDelta + obj->anim.worldPosX;
        prospectivePos[1] = obj->anim.worldPosY;
        prospectivePos[2] = (0.05f * state->dirZ) * timeDelta + obj->anim.worldPosZ;
    } else {
        prospectivePos[0] = timeDelta * (state->dirX * moveSpeed) + obj->anim.worldPosX;
        prospectivePos[1] = obj->anim.worldPosY;
        prospectivePos[2] = timeDelta * (state->dirZ * moveSpeed) + obj->anim.worldPosZ;
    }

    adjustedPos[0] = prospectivePos[0];
    adjustedPos[1] = prospectivePos[1];
    adjustedPos[2] = prospectivePos[2];
    trickyApplyObjectAvoidanceToStep(&obj->anim.worldPosX, adjustedPos, targetPos);
    if (vec3f_distanceSquared(prospectivePos, adjustedPos) > TRICKY_AVOIDANCE_REPATH_EPSILON_SQ) {
        state->dirX = adjustedPos[0] - obj->anim.worldPosX;
        state->dirZ = adjustedPos[2] - obj->anim.worldPosZ;
        length = sqrtf((state->dirX * state->dirX) + (state->dirZ * state->dirZ));
        if (0.0f != length) {
            state->dirX /= length;
            state->dirZ /= length;
        }
    }

    if (moveSpeed >= 0.05f) {
        skeetla_faceMoveVector(obj);
        if (skeetla_isInWater(state) != 0) {
            trickyRequestMove(obj, 7, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_ROOT_TRANSLATE);
            state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
            state->particleTimer = 0.0f;
            trickyDebugPrint(debugStrings + TRICKY_DBG_IN_WATER);
        } else {
            if (state->stateIndex == TRICKY_STATE_FOLLOW_PLAYER) {
                if ((skeetla_pathSpeedDelta(obj) >= 0.0f ? skeetla_pathSpeedDelta(obj) : -skeetla_pathSpeedDelta(obj)) >
                    0.0f) {
                    state->sfxIntervalTimer -= timeDelta;
                    if (state->sfxIntervalTimer <= 0.0f) {
                        state->sfxIntervalTimer = (f32)(int)randomGetRange(600, 1200);
                        if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            if (moveSpeed > 1.0f) {
                                sfxId = randomGetRange(0x34d, 0x34e);
                                skeetla_playFootstepSfx(obj, sfxId);
                            } else {
                                *(u32*)sfxIds = *(u32*)gSkeetlaFootstepSfxIds01;
                                sfxIds[2] = gSkeetlaFootstepSfxId2[0];
                                if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
                                    randomGetRange(0, 2);
                                } else {
                                    randomGetRange(0, 1);
                                }
                                sfxId = sfxIds[randomGetRange(0, 2)];
                                skeetla_playFootstepSfx(obj, sfxId);
                            }
                        }
                    }
                }
            }

            if (moveSpeed > 2.5f) {
                state->voiceCooldown = 600.0f;
                trickyRequestMove(obj, 0x30, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (moveSpeed > 1.0f) {
                trickyRequestMove(obj, 5, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (moveSpeed > TRICKY_FAST_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, 4, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (moveSpeed > TRICKY_SLOW_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, 2, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else {
                trickyRequestMove(obj, 1, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            }
            trickyDebugPrint(debugStrings + TRICKY_DBG_MOVE_OUT_OF_WATER);
        }
    } else {
        s16 previousYaw;
        s16 turnDelta;
        u32 stateFlags;

        previousYaw = obj->anim.rotX;
        turnDelta = 0;
        skeetla_updateFacingFromMoveVector(obj, &turnDelta);
        td = turnDelta;

        if ((state->stateFlags & 0x100000) != 0) {
            if (skeetla_isInWater(state) != 0) {
                trickyDebugPrint(debugStrings + TRICKY_DBG_TURN_IN_WATER);
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
            } else {
                int animId;
                u32 flags;

                trickyDebugPrint(debugStrings + TRICKY_DBG_TURN_OUT_OF_WATER);
                flags = state->stateFlags;
                if ((flags & 0x400000) != 0) {
                    if ((td >= 0 ? td : -td) > 0x3555) {
                        animId = 0x27;
                    } else {
                        td = td >= 0 ? turnDelta : -td;
                        if (td > 0x2000) {
                            animId = 0xb;
                        } else {
                            animId = 9;
                        }
                    }
                } else if ((flags & 0x800000) != 0) {
                    if ((td >= 0 ? td : -td) > 0x3555) {
                        animId = 0x28;
                    } else {
                        td = td >= 0 ? turnDelta : -td;
                        if (td > 0x2000) {
                            animId = 0xc;
                        } else {
                            animId = 10;
                        }
                    }
                }
                obj->anim.rotX = previousYaw;
                trickyRequestMove(obj, animId, TRICKY_TURN_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_STATE_FLAG_ROTATE);
            }
        }

        state->speed = 0.05f;
        stateFlags = state->stateFlags;
        if (((stateFlags & 0x100000) == 0) && ((stateFlags & 0x200000) == 0)) {
            return 0;
        }
    }
    return 1;
}

int trickyRequestMove(GameObject* obj, int newState, f32 speed, u32 flags) {
    TrickyState* state = obj->extra;
    f32 fz;
    if (state->moveId == newState) {
        if (obj->anim.currentMove == newState) {
            state->moveProgress = speed;
            state->stateFlags = state->stateFlags | flags;
        }
        return 1;
    }
    if ((flags & TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION) != 0) {
        state->animTransitionTimer = 15.0f;
    }
    state->moveId = newState;
    state->moveProgressTarget = speed;
    state->pendingStateFlags = flags;
    if ((flags & TRICKY_STATE_FLAG_SIDESTEP) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_SIDESTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_BACKSTEP) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_BACKSTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_VERTICAL_MOVE) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_VERTICAL_MOVE;
    }
    if ((flags & TRICKY_STATE_FLAG_ROTATE) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_ROTATE;
    }
    fz = 1.0f;
    state->sidestepDelta = fz;
    state->backstepDelta = fz;
    state->verticalDelta = fz;
    state->rotStepScale = fz;
    if (state->animTransitionTimer >= 15.0f) {
        return 1;
    }
    return 0;
}

static inline void* skeetla_validateRouteEntry(void* entry) {
    if (entry == NULL) {
        return NULL;
    }
    if (((((RomCurveDef*)entry)->requiredBit == -1) || (mainGetBit(((RomCurveDef*)entry)->requiredBit) != 0)) &&
        ((((RomCurveDef*)entry)->forbiddenBit == -1) || (mainGetBit(((RomCurveDef*)entry)->forbiddenBit) == 0))) {
        return entry;
    }

    return NULL;
}

void* trickyFindNearestLinkedRouteEntry(TrickyState* context, u8* routeDef, int linkSelector, int routeFlagValue) {
    void* candidates[4];
    RomCurveDef* entry;
    f32 bestDistance;
    f32 distance;
    u16 mask;
    u16 i;
    u16 count;
    u16 bestIndex;
    int curveId;
    s16 requiredBit;
    s16 forbiddenBit;

    i = 0;
    count = 0;
    mask = 1;
    while (i < 4) {
        curveId = ((RomCurveDef*)routeDef)->linkIds[i];
        if ((curveId > -1) && (((((RomCurveDef*)routeDef)->blockedLinkMask & mask) ^ routeFlagValue) == 0)) {
            candidates[count] = (*gRomCurveInterface)->getById(curveId);
            if (candidates[count] != NULL) {
                entry = candidates[count];
                if ((linkSelector == 0) || (((RomCurveDef*)routeDef)->linkWalkGroups[count] == linkSelector)) {
                    requiredBit = entry->requiredBit;
                    if ((requiredBit == -1) || (mainGetBit(requiredBit) != 0)) {
                        forbiddenBit = entry->forbiddenBit;
                        if ((forbiddenBit == -1) || (mainGetBit(forbiddenBit) == 0)) {
                            if ((((RomCurveDef*)routeDef)->unk1A != 9) || (entry->unk1A != 8)) {
                                count++;
                            }
                        }
                    }
                }
            }
        }
        i++;
        mask <<= 1;
        routeFlagValue <<= 1;
    }

    if (count != 0) {
        bestDistance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &((RomCurveDef*)candidates[0])->x);
        bestIndex = 0;
        for (i = 1; i < count; i++) {
            distance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &((RomCurveDef*)candidates[i])->x);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestIndex = i;
            }
        }

        return candidates[bestIndex];
    }
    return NULL;
}

void* trickyFindPathRouteEntry(TrickyState* state, u32 route, int pathId) {
    if (pathId == 0) {
        return NULL;
    }

    if ((state->cachedPathId == pathId) && (*(u32*)&state->cachedRouteEntry == route)) {
        state->cachedRouteEntry = pathSearchGetNextPoint(&state->pathSearches[8]);
        if (state->cachedRouteEntry == NULL) {
            return NULL;
        }

        state->cachedRouteEntry = skeetla_validateRouteEntry(state->cachedRouteEntry);
        if (state->cachedRouteEntry != NULL) {
            return (state)->cachedRouteEntry;
        }
    }

    pathSearchBegin(&state->pathSearches[8], (RomCurveDef*)route, state->targetPosPtr, pathId, state->route.reverse);
    if (pathSearchStep(&state->pathSearches[8], 0x1f4) != 1) {
        return NULL;
    }

    pathSearchBuildPath(&state->pathSearches[8]);
    state->cachedRouteEntry = pathSearchGetNextPoint(&state->pathSearches[8]);
    state->cachedPathId = pathId;
    return (state)->cachedRouteEntry;
}

int trickyFindReachableRouteIndex(TrickyState* state, RomCurveDef** routes, u8* routeFlags, int pathId) {
    RomCurveDef** initRouteCursor;
    u8* searchCursor;
    RomCurveDef** routeCursor;
    u8* initSearchCursor;
    s8* statusCursor;
    s8 i;
    s8 status[TRICKY_ROUTE_CANDIDATE_COUNT];
    s8 initIndex;
    s8 k;
    s8 routeIndex;
    s8 failedCount;

    for (initIndex = 0, initRouteCursor = routes, initSearchCursor = (u8*)state;
         initIndex < TRICKY_ROUTE_CANDIDATE_COUNT; initIndex++) {
        if (*initRouteCursor != NULL) {
            pathSearchBegin((PathSearch*)(initSearchCursor + offsetof(TrickyState, pathSearches)), *initRouteCursor,
                            state->targetPosPtr, pathId, routeFlags[initIndex]);
        }
        initRouteCursor++;
        initSearchCursor += sizeof(PathSearch);
    }

    for (i = 0; i < 100; i++) {
        failedCount = 0;
        for (routeIndex = 0, routeCursor = routes, searchCursor = (u8*)state, statusCursor = status;
             routeIndex < TRICKY_ROUTE_CANDIDATE_COUNT; routeIndex++) {
            if (*routeCursor != NULL) {
                *statusCursor = pathSearchStep((PathSearch*)(searchCursor + offsetof(TrickyState, pathSearches)), 1);
            } else {
                *statusCursor = -1;
            }

            switch (*statusCursor) {
            case 1:
                return routeIndex;
            case -1:
                *routeCursor = NULL;
                failedCount++;
                break;
            }
            routeCursor++;
            searchCursor += sizeof(PathSearch);
            statusCursor++;
        }

        switch (failedCount) {
        case 7:
            for (k = 0, routeCursor = routes; k < TRICKY_ROUTE_CANDIDATE_COUNT; k++) {
                if (*routeCursor != NULL) {
                    status[(int)k] = pathSearchStep(&state->pathSearches[(int)k], 0x1f4);
                    if (status[(int)k] == 1) {
                        return k;
                    }
                    return -1;
                }
                routeCursor++;
            }
        case 8:
            return -1;
        }
    }

    return -1;
}

void* trickySelectRouteEntry(TrickyState* state, u8* routeDef, u8 routeFlagValue) {
    void* entry;

    entry = NULL;

    if ((state->cachedRouteDef == routeDef) && (state->cachedWalkGroup == state->walkGroup) &&
        (state->cachedRouteFlags == (routeFlagValue & 0xffu))) {
        entry = skeetla_validateRouteEntry(state->validatedRouteEntry);
    }

    if (entry == NULL) {
        entry = trickyFindNearestLinkedRouteEntry(state, routeDef, state->walkGroup, routeFlagValue & 0xff);
        if (entry == NULL) {
            entry = trickyFindPathRouteEntry(state, (u32)routeDef, state->walkGroup);
        }

        if (entry == NULL) {
            if (state->savedWalkGroup != 0) {
                entry =
                    trickyFindNearestLinkedRouteEntry(state, routeDef, state->savedWalkGroup, routeFlagValue & 0xff);
                if (entry == NULL) {
                    entry = trickyFindPathRouteEntry(state, (u32)routeDef, state->savedWalkGroup);
                }
                if (entry != NULL) {
                    state->walkGroup = state->savedWalkGroup;
                }
            }

            if (entry == NULL) {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, 0, routeFlagValue & 0xff);
                state->walkGroup = 0;
            }
        }
    }

    state->cachedRouteDef = routeDef;
    state->validatedRouteEntry = entry;
    state->cachedWalkGroup = state->walkGroup;
    state->cachedRouteFlags = routeFlagValue;
    return entry;
}

void trickyRankLinkedRouteCandidates(GameObject* obj, u8* outRouteFlags, s16 linkSelector, RomCurveDef** outRoutes) {
    f32 bestDistances[TRICKY_ROUTE_CANDIDATE_COUNT];
    int i;
    RomCurveDef** curves;
    int linkCurveId;
    int count;
    RomCurveDef** cp;
    int curveIdx;
    RomCurveDef* linkedCurve;
    f32 curveX;
    f32 targetXDistanceSquared;
    f32 targetZDistanceSquared;
    f32 curveZ;
    f32* p;
    f32 score;
    f32 init;
    RomCurveDef* curve;
    u8 j;
    u8 routeFlags;
    u8 k;
    f32* bd;
    RomCurveDef** rp;
    TrickyState* state;

    state = obj->extra;
    curves = (*gRomCurveInterface)->getCurves(&count);

    init = gTrickyMaxDistance;
    bd = bestDistances;
    rp = outRoutes;
    for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++) {
        *bd++ = init;
        *rp++ = NULL;
    }

    if (linkSelector == 0) {
        return;
    }

    for (curveIdx = 0, cp = curves; curveIdx < count; cp++, curveIdx++) {
        curve = *cp;
        if ((curve->type != 0x24) || (curve->walkGroup != 0)) {
            continue;
        }
        if (((curve->requiredBit != -1) && (mainGetBit(curve->requiredBit) == 0)) ||
            ((curve->forbiddenBit != -1) && (mainGetBit(curve->forbiddenBit) != 0))) {
            continue;
        }

        curveZ = curve->z;
        p = state->targetPosPtr;
        {
            targetZDistanceSquared = (p[2] - curveZ) * (p[2] - curveZ);
            curveX = curve->x;
            targetXDistanceSquared = (p[0] - curveX) * (p[0] - curveX);
            {
                f32 objectXDistanceSquared = (obj->anim.worldPosX - curveX) * (obj->anim.worldPosX - curveX);
                f32 objectZDistanceSquared = (obj->anim.worldPosZ - curveZ) * (obj->anim.worldPosZ - curveZ);
                score = targetZDistanceSquared +
                        (targetXDistanceSquared + (objectXDistanceSquared + objectZDistanceSquared));
            }
        }
        if (score < bestDistances[7]) {
            for (j = 0; j < 4; j++) {
                linkCurveId = curve->linkIds[j];
                if ((linkCurveId > -1) && (curve->linkWalkGroups[j] == linkSelector)) {
                    if (curve->unk1A == 8) {
                        linkedCurve = (*gRomCurveInterface)->getById(linkCurveId);
                        if ((linkedCurve != NULL) && (linkedCurve->unk1A == 9)) {
                            continue;
                        }
                    }

                    routeFlags = (u8)(curve->blockedLinkMask >> j);
                    break;
                }
            }

            if (j == 4) {
                continue;
            }

            for (j = 0; j < TRICKY_ROUTE_CANDIDATE_COUNT; j++) {
                if (score < bestDistances[j]) {
                    for (k = 7; k > j; k--) {
                        outRouteFlags[k] = outRouteFlags[k - 1];
                        outRoutes[k] = outRoutes[k - 1];
                        bestDistances[k] = bestDistances[k - 1];
                    }

                    outRouteFlags[j] = (routeFlags & 1) ^ 1;
                    outRoutes[j] = curve;
                    bestDistances[j] = score;
                    break;
                }
            }
        }
    }
}

void skeetla_spawnLinkedSparks(GameObject* obj) {
    TrickyState* state;
    GameObject* linkedObj;
    SkeetlaParticleSpawnArgs args;

    state = obj->extra;
    linkedObj = state->followObj;

    args.x = state->sparkPos0X;
    args.y = state->sparkPos0Y;
    args.z = state->sparkPos0Z;
    args.objectId = obj->anim.rotX;
    if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ID_OBJ_A) {
        args.sourceId = (u8)((u32(*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ID_OBJ_B) {
        args.sourceId = (u8)((u32(*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else {
        args.sourceId = 0;
    }

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }

    args.x = state->sparkPos1X;
    args.y = state->sparkPos1Y;
    args.z = state->sparkPos1Z;
    args.objectId = obj->anim.rotX;

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
}

void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance,
                                 f32 moveDistance) {
    f32 projection[3];
    f32 dx;
    f32 centerToEnd;
    f32 minDistanceSq;
    f32 limitDistanceSq;
    f32 guardDistance;
    f32 startGuardDistance;
    f32 slope[1];
    f32 intercept;
    f32 perpSlope;
    f32 dz;
    f32 centerToStart;
    f32 length;
    int useBlendedDistance;

    useBlendedDistance = 0;
    centerToStart = getXZDistanceSquared(center, start);
    centerToEnd = getXZDistanceSquared(center, end);
    minDistanceSq = minDistance * minDistance;
    limitDistanceSq = moveDistance * moveDistance;

    if (centerToEnd > centerToStart) {
        return;
    }

    guardDistance = getXZDistanceSquared(guardPoint, center);
    if (guardDistance < minDistanceSq) {
        return;
    }

    startGuardDistance = getXZDistanceSquared(start, guardPoint);
    if (getXZDistanceSquared(start, center) > startGuardDistance) {
        return;
    }

    if (centerToStart < limitDistanceSq) {
        limitDistanceSq = centerToStart;
        useBlendedDistance = 1;
    }

    if (!(centerToEnd < limitDistanceSq)) {
        return;
    }

    slope[0] = (end[2] - start[2]) / (end[0] - start[0]);
    intercept = start[2] - (slope[0] * start[0]);
    perpSlope = (start[0] - end[0]) / (end[2] - start[2]);
    projection[0] = ((center[2] - (perpSlope * center[0])) - intercept) / (slope[0] - perpSlope);
    projection[2] = (slope[0] * projection[0]) + intercept;

    if (!(getXZDistanceSquared(center, projection) < minDistanceSq)) {
        return;
    }

    dx = end[0] - center[0];
    dz = end[2] - center[2];
    length = sqrtf((dx * dx) + (dz * dz));
    if (0.0f != length) {
        dx /= length;
        dz /= length;
    }

    if (useBlendedDistance != 0) {
        moveDistance = sqrtf(limitDistanceSq);
        {
            f32 blend = moveDistance - sqrtf(centerToEnd);
            moveDistance = moveDistance - (blend / 8.0f);
        }
    }

    end[0] = center[0] + (dx * moveDistance);
    end[2] = center[2] + (dz * moveDistance);
}

/* group owned by another DLL, queried here */

void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint) {
    int count;
    int startIndex;
    int objectCount;
    void** objects;
    GameObject* obj;
    SideRepelPlacement* repelPlacement;
    ObjDef* modelDef;
    ObjHitsPriorityState* hitState;
    u16 minRadius;
    void** op;
    f32 scale;
    int i;

    objects = (void**)objGetAllOfType(SIDEREPEL_OBJGROUP, &count);
    for (i = 0, op = objects, scale = 0.1f; i < count; i++) {
        obj = *op;
        repelPlacement = (SideRepelPlacement*)obj->anim.placementData;
        trickyAdjustStepAroundPoint(start, end, guardPoint, &obj->anim.worldPosX,
                                    scale * (f32)(u32)repelPlacement->minDistance,
                                    scale * (f32)(u32)repelPlacement->moveDistance);
        op++;
    }

    objects = (void**)ObjList_GetObjects(&startIndex, &objectCount);
    for (i = startIndex, op = objects + i; i < objectCount; i++) {
        obj = *op;
        modelDef = obj->anim.modelInstance;
        minRadius = modelDef->avoidRadiusX;
        if (minRadius != 0) {
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if ((hitState != NULL) && ((hitState->flags & 1) != 0)) {
                trickyAdjustStepAroundPoint(start, end, guardPoint, &obj->anim.worldPosX, 0.1f * (f32)(u32)minRadius,
                                            0.1f * (f32)(u32)modelDef->avoidRadiusZ);
            }
        }
        op++;
    }
}

/*
 * Tricky sidekick follow/path-walk movement. trickyUpdateMovementState is
 * the per-frame movement step that resolves the target's walk/patch group and
 * drives motion through a substate machine and RomCurveWalker route;
 * trickyUpdateApproachSpeed ramps the follow speed toward a target point. The
 * lbl_803E2xxx externs are this DLL's .sdata2 float constants.
 */

char sInWaterMessage[] = {
    0x69, 0x6E, 0x20, 0x77, 0x61, 0x74, 0x65, 0x72, 0x0A, 0x00,
};

char sTrickyDryLandDebugMessage[] = {
    0x6F, 0x75, 0x74, 0x20, 0x6F, 0x66, 0x20, 0x77, 0x61, 0x74, 0x65, 0x72, 0x0A, 0x00, 0x00, 0x00, 0x6D, 0x6F, 0x76,
    0x65, 0x54, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x3A, 0x20, 0x6F, 0x75, 0x74, 0x20, 0x6F, 0x66, 0x20, 0x77, 0x61, 0x74,
    0x65, 0x72, 0x0A, 0x00, 0x00, 0x00, 0x54, 0x75, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61,
    0x74, 0x65, 0x72, 0x0A, 0x00, 0x00, 0x00, 0x54, 0x75, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x6F, 0x75, 0x74, 0x20,
    0x6F, 0x66, 0x20, 0x77, 0x61, 0x74, 0x65, 0x72, 0x0A, 0x00, 0x00, 0x00, 0x74, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x20,
    0x77, 0x67, 0x20, 0x25, 0x64, 0x2D, 0x3E, 0x25, 0x64, 0x20, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x20, 0x77, 0x67,
    0x20, 0x25, 0x64, 0x2C, 0x20, 0x64, 0x65, 0x73, 0x74, 0x20, 0x77, 0x67, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x74,
    0x72, 0x69, 0x63, 0x6B, 0x79, 0x20, 0x6C, 0x61, 0x73, 0x74, 0x20, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x67, 0x72, 0x6F,
    0x75, 0x70, 0x20, 0x69, 0x73, 0x20, 0x7A, 0x65, 0x72, 0x6F, 0x2E, 0x20, 0x48, 0x61, 0x73, 0x20, 0x68, 0x65, 0x20,
    0x62, 0x65, 0x65, 0x6E, 0x20, 0x6C, 0x6F, 0x61, 0x64, 0x65, 0x64, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6E, 0x20,
    0x61, 0x20, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x3F, 0x20, 0x25, 0x66, 0x20, 0x25, 0x66,
    0x20, 0x25, 0x66, 0x0A, 0x00, 0x00, 0x00, 0x76, 0x65, 0x6C, 0x62, 0x65, 0x66, 0x6F, 0x72, 0x65, 0x20, 0x25, 0x66,
    0x2C, 0x20, 0x76, 0x65, 0x6C, 0x20, 0x6E, 0x6F, 0x77, 0x20, 0x25, 0x66, 0x0A, 0x00, 0x00, 0x00, 0x74, 0x61, 0x72,
    0x67, 0x65, 0x74, 0x20, 0x69, 0x73, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6E, 0x20, 0x61, 0x20, 0x77, 0x61, 0x6C,
    0x6B, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x6F, 0x72, 0x20, 0x69, 0x74, 0x73, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68,
    0x0A, 0x00, 0x00, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x74, 0x20, 0x77, 0x69,
    0x74, 0x68, 0x69, 0x6E, 0x20, 0x61, 0x20, 0x77, 0x61, 0x6C, 0x6B, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x6F, 0x72,
    0x20, 0x61, 0x6E, 0x79, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x65, 0x73, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x74, 0x61,
    0x72, 0x67, 0x65, 0x74, 0x20, 0x69, 0x73, 0x20, 0x77, 0x69, 0x74, 0x68, 0x69, 0x6E, 0x20, 0x70, 0x61, 0x74, 0x63,
    0x68, 0x20, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x50, 0x61, 0x74, 0x63,
    0x68, 0x20, 0x25, 0x64, 0x3A, 0x20, 0x4C, 0x61, 0x73, 0x74, 0x20, 0x78, 0x79, 0x7A, 0x20, 0x25, 0x66, 0x20, 0x25,
    0x66, 0x20, 0x25, 0x66, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x61, 0x73, 0x74, 0x20, 0x50, 0x61, 0x74, 0x63, 0x68,
    0x20, 0x50, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x25, 0x66, 0x20, 0x25, 0x66, 0x20, 0x25, 0x66, 0x0A, 0x00, 0x00, 0x54,
    0x72, 0x69, 0x63, 0x6B, 0x79, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x65, 0x69, 0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x6E,
    0x20, 0x61, 0x20, 0x77, 0x61, 0x6C, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x6F, 0x72, 0x20, 0x69, 0x6E, 0x20,
    0x61, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x0A, 0x00, 0x74, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x20, 0x65, 0x72, 0x72,
    0x6F, 0x72, 0x2C, 0x20, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x20, 0x25, 0x64,
    0x2C, 0x20, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x57, 0x61, 0x6C, 0x6B, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x25,
    0x64, 0x2C, 0x20, 0x74, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x57, 0x61, 0x6C, 0x6B, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x20,
    0x25, 0x64, 0x2C, 0x20, 0x74, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x20, 0x6C, 0x61, 0x73, 0x74, 0x20, 0x77, 0x61, 0x6C,
    0x6B, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x20, 0x25, 0x64, 0x2C, 0x20, 0x74, 0x72, 0x69, 0x63, 0x6B, 0x79, 0x20, 0x69,
    0x6E, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x74, 0x72, 0x69, 0x63,
    0x6B, 0x79, 0x20, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x32, 0x21, 0x21, 0x21, 0x21, 0x21, 0x0A, 0x00, 0x00, 0x00,
    0x00, 0x6D, 0x6F, 0x76, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x20, 0x69, 0x73, 0x20,
    0x25, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x77, 0x61, 0x69, 0x74, 0x0A, 0x00, 0x00, 0x77,
    0x61, 0x6C, 0x6B, 0x20, 0x66, 0x72, 0x65, 0x65, 0x0A, 0x00, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x73, 0x74, 0x61,
    0x72, 0x74, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x0A, 0x00, 0x00, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x70, 0x61,
    0x74, 0x63, 0x68, 0x20, 0x65, 0x78, 0x69, 0x74, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x65,
    0x6E, 0x64, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x0A, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x74, 0x6F, 0x20, 0x6E,
    0x6F, 0x64, 0x65, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x63, 0x75, 0x72, 0x76, 0x65, 0x20, 0x73, 0x65,
    0x74, 0x75, 0x70, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x77, 0x61, 0x6C, 0x6B, 0x20, 0x6E, 0x6F, 0x64, 0x65, 0x73, 0x0A,
    0x00, 0x4A, 0x75, 0x6D, 0x70, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x75, 0x70, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x75,
    0x6D, 0x70, 0x20, 0x70, 0x72, 0x65, 0x70, 0x0A, 0x00, 0x00, 0x4A, 0x75, 0x6D, 0x70, 0x69, 0x6E, 0x67, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x4A, 0x75, 0x6D, 0x70, 0x20, 0x75, 0x70, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x75, 0x70, 0x0A, 0x00,
    0x4A, 0x55, 0x4D, 0x50, 0x44, 0x4F, 0x57, 0x4E, 0x20, 0x6F, 0x72, 0x20, 0x4A, 0x55, 0x4D, 0x50, 0x55, 0x50, 0x0A,
    0x00, 0x4A, 0x55, 0x4D, 0x50, 0x44, 0x4F, 0x57, 0x4E, 0x5F, 0x52, 0x55, 0x4E, 0x55, 0x50, 0x0A, 0x00, 0x65, 0x6E,
    0x74, 0x65, 0x72, 0x65, 0x64, 0x20, 0x61, 0x20, 0x6E, 0x6F, 0x6E, 0x20, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x20, 0x6D,
    0x6F, 0x76, 0x65, 0x6D, 0x65, 0x6E, 0x74, 0x73, 0x74, 0x61, 0x74, 0x65, 0x0A, 0x00, 0x00,
};

#define TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed)                                                    \
    do {                                                                                                               \
        s16 previousYaw;                                                                                               \
        s16 routeYaw;                                                                                                  \
        s16 yawDelta;                                                                                                  \
                                                                                                                       \
        previousYaw =                                                                                                  \
            getAngle((state)->prevLocalPosX - (obj)->anim.localPosX, (state)->prevLocalPosZ - (obj)->anim.localPosZ);  \
        routeYaw =                                                                                                     \
            getAngle((state)->prevLocalPosX - (state)->route.posX, (state)->prevLocalPosZ - (state)->route.posZ);      \
        yawDelta = previousYaw - (u16)routeYaw;                                                                        \
        if (0x8000 < yawDelta) {                                                                                       \
            yawDelta = yawDelta - 0xffff;                                                                              \
        }                                                                                                              \
        if (yawDelta < -0x8000) {                                                                                      \
            yawDelta = yawDelta + 0xffff;                                                                              \
        }                                                                                                              \
        if (yawDelta > 0x4000) {                                                                                       \
            yawDelta -= 0x8000;                                                                                        \
        } else if (yawDelta < -0x4000) {                                                                               \
            yawDelta += 0x8000;                                                                                        \
        }                                                                                                              \
        if (0x1000 < ((yawDelta >= 0) ? yawDelta : -yawDelta)) {                                                       \
            (state)->speed = (previousSpeed);                                                                          \
            trickyUpdateApproachSpeed((obj), 2.5f, (state), &(state)->route.posX, 1);                                  \
        }                                                                                                              \
    } while (0)

#define TRICKY_ADVANCE_ROUTE_TO_END(state)                                                                             \
    do {                                                                                                               \
        if ((state)->route.reverse != 0) {                                                                             \
            while ((state)->route.atSegmentEnd != 0) {                                                                 \
                RomCurve_stepClamped(&(state)->route, TRICKY_ROUTE_REVERSE_STEP);                                      \
            }                                                                                                          \
        } else {                                                                                                       \
            while ((state)->route.atSegmentEnd == 0) {                                                                 \
                RomCurve_stepClamped(&(state)->route, 2.0f);                                                           \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define TRICKY_FOLLOW_MAX_SPEED                 3.0f
#define TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED   0.0135f
#define TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED   0.00975f
#define TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR   32.865f
#define TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED      0.0125f
#define TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR 33.114f
#define TRICKY_FOLLOW_ARC_SPEED                 2.3f
#define TRICKY_FOLLOW_ARC_HALF_PROGRESS         0.5f
#define TRICKY_FOLLOW_ARC_QUARTER_PROGRESS      0.25f
#define TRICKY_FOLLOW_ARC_COEFFICIENT           -0.017f

int trickyUpdateMovementState(GameObject* obj, f32 stoppingRadius, TrickyState* state) {
    int patchIdCursor;
    int patchTargetCursor;
    int targetPatchGroup;
    int patchInfoCursor;
    int patchIdWriteCursor;
    RomCurveDef* routeNode;
    f32* target;
    char* debugStrings = gTrickyDebugStringTable;
    int objectWalkGroup;
    int targetWalkGroup;
    u8 didMove = 1;
    RomCurveDef* prevNode;
    u32 patchGroupForCheck;
    s16 linkedWalkGroupId;
    u32 prod;
    int routeDirection;
    int patchTargetWriteCursor;
    int i;
    u8 patchSlot;
    f32* patchTarget;
    u16 walkGroupLink;
    u8 patchMaskBit;
    f32 previousSpeed;
    f32 dist;
    f32 len;
    f32 v;
    f32 k;
    f32 sqz;
    f32 sqx;
    u8 walkGroupPair[2];
    u8 routeFlags[8];
    struct {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } rot;
    f32 delta[3];
    ObjfsaWalkGroupPatchInfo patchInfo;
    RomCurveDef* routePtrs[9];

    if ((state->movementState < 5) && (isInWalkGroupOrPatch(&obj->anim.worldPosX) == 0)) {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
        obj->anim.localPosX = state->homePosX;
        obj->anim.localPosY = state->homePosY;
        obj->anim.localPosZ = state->homePosZ;
        obj->anim.worldPosX = state->homePosX;
        obj->anim.worldPosY = state->homePosY;
        obj->anim.worldPosZ = state->homePosZ;
        ObjHits_SyncObjectPosition(obj);
    }
    target = state->targetPosPtr;
    objectWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0);
    if ((objectWalkGroup != 0) && (state->activeWalkGroup != objectWalkGroup)) {
        state->activeWalkGroup = objectWalkGroup;
        {
            u32 mask;
            u32 f2 = state->stateFlags;
            mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
            state->stateFlags = f2 & mask;
        }
        state->patch[0] = 0;
        state->patch[1] = 0;
        state->patch[2] = 0;
        state->patch[3] = 0;
    }
    targetWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(target, &patchInfo);
    if (((objectWalkGroup != 0) && (targetWalkGroup == 0)) &&
        ((walkGroupLink = getPatchGroup(target, objectWalkGroup)) != 0)) {
        walkPath_writeU16LE(walkGroupLink, walkGroupPair);
        if (walkGroupPair[0] == objectWalkGroup) {
            targetWalkGroup = walkGroupPair[1];
        } else {
            targetWalkGroup = walkGroupPair[0];
        }
    }
    if ((targetWalkGroup != 0) && (targetWalkGroup != state->walkGroup)) {
        state->walkGroup = targetWalkGroup;
    }
    state->savedWalkGroup = state->walkGroup;
    trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_GROUP_STATUS, state->activeWalkGroup, objectWalkGroup,
                     targetWalkGroup, state->walkGroup);
    if (state->activeWalkGroup == 0) {
        trickyReportError(debugStrings + TRICKY_DBG_ZERO_ACTIVE_WALK_GROUP, obj->anim.worldPosX, obj->anim.worldPosY,
                          obj->anim.worldPosZ);
    }
    previousSpeed = state->speed;
    trickyUpdateApproachSpeed(obj, stoppingRadius, state, target, 0);
    trickyDebugPrint(debugStrings + TRICKY_DBG_SPEED_UPDATE, previousSpeed, state->speed);
    if (targetWalkGroup == state->activeWalkGroup) {

        state->stateFlags |= TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
        i = 0;
        patchMaskBit = 1;
        patchInfoCursor = (int)&patchInfo;
        patchIdWriteCursor = (int)state;
        patchTargetWriteCursor = (int)state;
        for (; i < 4;
             patchInfoCursor += 2, patchIdWriteCursor += 2, patchTargetWriteCursor += 12, i++, patchMaskBit <<= 1) {
            if (patchInfo.patchMask & patchMaskBit) {
                TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdWriteCursor) =
                    OBJFSA_PATCH_GROUP_ID_FROM_INFO_BASE(patchInfoCursor);
                TRICKY_PATCH_TARGET_X_FROM_STATE_BASE(patchTargetWriteCursor) = target[0];
                TRICKY_PATCH_TARGET_Y_FROM_STATE_BASE(patchTargetWriteCursor) = target[1];
                TRICKY_PATCH_TARGET_Z_FROM_STATE_BASE(patchTargetWriteCursor) = target[2];
            }
        }
    }
    if ((targetWalkGroup != 0) && (targetWalkGroup == state->activeWalkGroup)) {
        state->linkedWalkGroup = 0;
    } else {
        u32 wgProd;

        wgProd = targetWalkGroup * state->activeWalkGroup & 0xffff;
        if (wgProd != 0) {
            u16* ids = patchInfo.patchGroupIds;

            for (i = 0, linkedWalkGroupId = wgProd; i < 4; ids++, i++) {
                if ((wgProd == *ids) && (((1 << i) & patchInfo.patchMask) != 0)) {
                    state->linkedWalkGroup = linkedWalkGroupId;
                    state->linkedPatchPos.x = target[0];
                    state->linkedPatchPos.y = target[1];
                    state->linkedPatchPos.z = target[2];
                }
            }
        }
    }
    if (isInWalkGroupOrPatch(target) != 0) {
        trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_IN_WALKGROUP_OR_PATCH);
    } else {
        trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_OUTSIDE_WALKGROUP_AND_PATCHES);
    }
    trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_PATCH_GROUP, getPatchGroup(target, state->activeWalkGroup));
    if ((state->stateFlags & TRICKY_STATE_FLAG_PATH_PATCHES_VALID) != 0) {
        int slotIdx;

        slotIdx = 0;
        patchIdCursor = (int)state;
        patchTargetCursor = (int)state;
        for (; slotIdx < 4; patchIdCursor += 2, patchTargetCursor += 12, slotIdx++) {
            if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) != 0) {
                trickyDebugPrint(debugStrings + TRICKY_DBG_PATCH_LAST_XYZ, slotIdx,
                                 TRICKY_PATCH_TARGET_X_FROM_STATE_BASE(patchTargetCursor),
                                 TRICKY_PATCH_TARGET_Y_FROM_STATE_BASE(patchTargetCursor),
                                 TRICKY_PATCH_TARGET_Z_FROM_STATE_BASE(patchTargetCursor));
            }
        }
    }
    if (state->linkedWalkGroup != 0) {
        trickyDebugPrint(debugStrings + TRICKY_DBG_LAST_PATCH_POINT, state->linkedPatchPos.x, state->linkedPatchPos.y,
                         state->linkedPatchPos.z);
    }
    {
        int trickyPatch;

        targetPatchGroup = getPatchGroup(target, state->activeWalkGroup) & 0xffff;
        trickyPatch = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff;
        if ((targetWalkGroup != 0) && (objectWalkGroup == targetWalkGroup)) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
        } else {
            walkGroupLink = Objfsa_GetWalkGroupIndexForMove(&obj->anim.worldPosX, target, state->activeWalkGroup);
            if (walkGroupLink != 0) {
                state->movementState = TRICKY_MOVE_WALK_FREE;
                if (walkGroupLink != state->activeWalkGroup) {
                    state->activeWalkGroup = walkGroupLink;
                    {
                        u32 mask;
                        u32 f2 = state->stateFlags;
                        mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        state->stateFlags = f2 & mask;
                    }
                    state->patch[0] = 0;
                    state->patch[1] = 0;
                    state->patch[2] = 0;
                    state->patch[3] = 0;
                }
            } else if (state->movementState < 5) {
                int i;

                if ((u32)targetPatchGroup != 0) {
                    if (targetWalkGroup == 0) {
                        if (objectWalkGroup != 0) {
                            for (i = 0, patchIdCursor = (int)state; i < 4; patchIdCursor += 2, i++) {
                                if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == 4) {
                                if (targetPatchGroup & (state->cachedWalkGroup == 0xff)) {
                                    state->walkGroup = (int)(targetPatchGroup & 0xff00) >> 8;
                                } else {
                                    state->walkGroup = targetPatchGroup & 0xff;
                                }
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if ((u32)trickyPatch != 0) {
                                for (i = 0, patchIdCursor = (int)state; i < 4; patchIdCursor += 2, i++) {
                                    if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) == trickyPatch) {
                                        trickyPatch = i & 0xffff;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if (i == 4) {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, trickyPatch);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError(debugStrings + TRICKY_DBG_NOT_IN_WALKGROUP_OR_PATCH);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    } else {
                        if (objectWalkGroup != 0) {
                            for (i = 0, patchIdCursor = (int)state; i < 4; patchIdCursor += 2, i++) {
                                if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == 4) {
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if (objectWalkGroup == 0 &&
                                (u32)(targetPatchGroup =
                                          getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff) != 0) {
                                if (state->linkedWalkGroup == targetPatchGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, (u16)targetPatchGroup);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                patchGroupForCheck = targetPatchGroup & 0xffff;
                                i = isPointWithinPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup,
                                                            patchGroupForCheck);
                                trickyReportError(debugStrings + TRICKY_DBG_PATCH_ROUTE_ERROR, patchGroupForCheck,
                                                  targetWalkGroup, objectWalkGroup, state->activeWalkGroup, i);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    }
                } else {
                    if (targetWalkGroup == 0) {
                        if (objectWalkGroup != 0) {
                            u16 pid = Objfsa_GetPatchGroupIdAtPoint(target);
                            if (pid == 0) {
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            } else {
                                state->walkGroup = pid & 0xff;
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            state->movementState = TRICKY_MOVE_WALK_WAIT;
                        }
                    } else {
                        if (objectWalkGroup != 0) {
                            if (isPointWithinPatchGroup(
                                    &obj->anim.worldPosX, state->activeWalkGroup,
                                    (targetWalkGroup = targetWalkGroup * objectWalkGroup & 0xffff)) != 0) {
                                if (state->linkedWalkGroup == targetWalkGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            } else {
                                for (i = 0, patchIdCursor = (int)state; i < 4; patchIdCursor += 2, i++) {
                                    if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) == targetWalkGroup) {
                                        patchSlot = i;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if ((i == 4) || (targetWalkGroup != state->linkedWalkGroup)) {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            }
                        } else {
                            u16 p = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup);
                            if (p != 0) {
                                if (targetWalkGroup == state->activeWalkGroup) {
                                    for (i = 0, patchIdCursor = (int)state; i < 4; patchIdCursor += 2, i++) {
                                        if (TRICKY_PATCH_ID_FROM_STATE_BASE(patchIdCursor) == p) {
                                            patchSlot = i;
                                            state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                            break;
                                        }
                                    }
                                    if (i == 4) {
                                        Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                        state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                    }
                                } else if (state->linkedWalkGroup == p) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError(debugStrings + TRICKY_DBG_PATCH_ROUTE_ERROR_2);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    }
                }
            }
        }
    }
    if (state->movementState < 5) {
        state->stateFlags &= ~0x2000LL;
    }
    trickyDebugPrint(debugStrings + TRICKY_DBG_MOVEMENT_STATE, state->movementState);
    switch (state->movementState) {
        char routeNodeType;
        RomCurveDef* node;
    case TRICKY_MOVE_WALK_WAIT:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_WAIT);
        v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
        state->speed = (v < 0.0f) ? 0.0f : v;
        if (0.0f == state->speed) {
            didMove = 0;
        } else {
            didMove = moveTricky(obj, target);
        }
        break;
    case TRICKY_MOVE_WALK_FREE:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_FREE);
        didMove = moveTricky(obj, target);
        break;
    case TRICKY_MOVE_WALK_START_PATCH:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_START_PATCH);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, 0.0f, state, patchTarget = &state->patchTargets[patchSlot].x, 1);
        didMove = moveTricky(obj, patchTarget);
        break;
    case TRICKY_MOVE_WALK_PATCH_EXIT:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_PATCH_EXIT);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, 5.0f, state, &state->patchExitPos.x, 1);
        didMove = moveTricky(obj, &state->patchExitPos.x);
        break;
    case TRICKY_MOVE_WALK_END_PATCH:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_END_PATCH);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, 5.0f, state, &state->linkedPatchPos.x, 1);
        didMove = moveTricky(obj, &state->linkedPatchPos.x);
        break;
    case TRICKY_MOVE_WALK_TO_NODE:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_TO_NODE, 10,
                         (int)getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX));
        dist = getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX);
        if (10.0f > dist) {
            state->route.reverse = state->routeSeedDir;
            prevNode = state->routeSeedNode;
            node = trickySelectRouteEntry(state, (u8*)prevNode, state->routeSeedDir);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                u8* nextNode = trickySelectRouteEntry(state, (u8*)node, state->routeSeedDir);
                if (nextNode == 0) {
                    state->movementState = TRICKY_MOVE_WALK_WAIT;
                } else {
                    RomCurve_setupHermiteSegment(&state->route, (u8*)prevNode, node, nextNode);
                    RomCurve_stepClamped(&state->route, 0.1f);
                    TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
                    trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
                    didMove = moveTricky(obj, &state->route.posX);
                    switch (prevNode->unk1A) {
                    case 1:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        state->speed = TRICKY_FOLLOW_MAX_SPEED;
                        trickyRequestMove(obj, 0x15, TRICKY_TINY_MOVE_BLEND_SPEED,
                                          TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                        state->movementState = TRICKY_MOVE_JUMP_PREP;
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case 5:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        if ((int)randomGetRange(0, 1) != 0) {
                            trickyRequestMove(obj, 0x17, TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED,
                                              TRICKY_MOVE_FLAG_JUMP_ARC);
                        } else {
                            trickyRequestMove(obj, 0x18, TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED,
                                              TRICKY_MOVE_FLAG_JUMP_ARC);
                        }
                        state->verticalDelta = (((RomCurveDef*)state->route.nodeA0)->y - obj->anim.worldPosY) /
                                               TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR;
                        state->movementState = TRICKY_MOVE_JUMPUP;
                        TRICKY_ADVANCE_ROUTE_TO_END(state);
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case 6:
                        node = state->route.nodeA0;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (0.0f != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        trickyRequestMove(obj, 0x19, TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                        state->verticalDelta = (obj->anim.worldPosY - ((RomCurveDef*)state->route.nodeA0)->y) /
                                               TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR;
                        state->movementState = TRICKY_MOVE_JUMPDOWN;
                        TRICKY_ADVANCE_ROUTE_TO_END(state);
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case 2:
                    case 7:
                        state->stateFlags = state->stateFlags | 0x2000;
                    default:
                        state->movementState = TRICKY_MOVE_WALK_NODES;
                    }
                }
            }
        } else {
            prevNode = state->routeSeedNode;
            if (prevNode == NULL) {
                node = NULL;
            } else if (((prevNode->requiredBit == -1) || (mainGetBit(prevNode->requiredBit) != 0)) &&
                       ((prevNode->forbiddenBit == -1) || (mainGetBit(prevNode->forbiddenBit) == 0))) {
                node = prevNode;
            } else {
                node = NULL;
            }
            if ((node != 0) || (objectWalkGroup == 0)) {
                state->speed = previousSpeed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->routeSeedNode->x, 1);
                didMove = moveTricky(obj, &state->routeSeedNode->x);
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            }
        }
        break;
    case TRICKY_MOVE_CURVE_SETUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_CURVE_SETUP);
        trickyRankLinkedRouteCandidates(obj, routeFlags, (s16)objectWalkGroup, routePtrs);
        i = trickyFindReachableRouteIndex(state, routePtrs, routeFlags, state->walkGroup);
        if (i == -1) {
            state->speed = previousSpeed;
            return 2;
        }
        state->routeSeedDir = routeFlags[i];
        state->routeSeedNode = routePtrs[i];
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, 5.0f, state, &state->routeSeedNode->x, 1);
        didMove = moveTricky(obj, &state->routeSeedNode->x);
        state->movementState = TRICKY_MOVE_WALK_TO_NODE;
        break;
    case TRICKY_MOVE_WALK_NODES:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_NODES);
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        routeNode = state->route.nodeA0;
        if ((((RomCurveDef*)state->route.node9C)->unk1A != 9) && (routeNode->unk1A != 9)) {
            int i;
            u8 step;
            char found;
            f32* tpos = state->targetPosPtr;
            delta[0] = tpos[0] - obj->anim.worldPosX;
            delta[1] = tpos[1] - obj->anim.worldPosY;
            delta[2] = tpos[2] - obj->anim.worldPosZ;
            rot.angle = -obj->anim.rotX;
            rot._pad0 = 0;
            rot._pad1 = 0;
            vecRotateZXY(&rot.angle, delta);
            if ((delta[2] > 0.0f) && (0.0f != state->speed)) {
                for (step = 0; step < 4; step++) {
                    u8 grp = routeNode->linkWalkGroups[step];
                    if (grp == state->walkGroup) {
                        break;
                    }
                }
                if (step == 4) {
                    pathSearchBegin(&state->pathSearches[0], (RomCurveDef*)state->route.nodeA4, state->targetPosPtr,
                                    state->walkGroup, state->route.reverse);
                    pathSearchBegin(&state->pathSearches[1], (RomCurveDef*)state->route.node9C, state->targetPosPtr,
                                    state->walkGroup, state->route.reverse ^ 1);
                    found = 0;
                    for (i = 0; (u8)(i = i + 1) < 100 && (found != 1);) {
                        found = pathSearchStep(&state->pathSearches[0], 1);
                        if (found != 1) {
                            found = pathSearchStep(&state->pathSearches[1], 1);
                            switch (found) {
                            case 0:
                                break;
                            case 1:
                                prod = (state->route.reverse ^ 1) & 0xff;
                                if (prod == 0) {
                                    RomCurve_stepClamped(&state->route, 2.0f);
                                } else {
                                    RomCurve_stepClamped(&state->route, TRICKY_ROUTE_REVERSE_STEP);
                                }
                                state->route.reverse = prod;
                                RomCurve_swapEndpointNodes(&state->route);
                                break;
                            case -1:
                                found = 1;
                                break;
                            }
                        }
                    }
                }
            }
        }
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            node = trickySelectRouteEntry(state, state->route.nodeA4, routeDirection & 0xff);
            if (node != 0) {
                RomCurve_advanceToNextSegment(&state->route, node);
                routeNodeType = ((RomCurveDef*)state->route.node9C)->unk1A;
                switch (routeNodeType) {
                case 2:
                case 7:
                    prod = state->stateFlags;
                    if ((prod & 0x2000) != 0) {
                        state->stateFlags = prod & ~0x2000LL;
                    } else {
                        state->stateFlags = prod | 0x2000;
                    }
                    break;
                }
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
        } else {
            node = trickySelectRouteEntry(state, state->route.nodeA0, routeDirection & 0xff);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
            if (node != state->route.nodeA4) {
                RomCurve_setSegmentEndNode(&state->route, node);
            }
        }
        if ((state->savedWalkGroup == 0) || (objectWalkGroup != state->savedWalkGroup)) {
            TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        didMove = moveTricky(obj, &state->route.posX);
        routeNodeType = ((RomCurveDef*)state->route.nodeA0)->unk1A;
        switch (routeNodeType) {
        case 1:
            state->movementState = TRICKY_MOVE_JUMP_RUNUP;
            break;
        case 5:
            state->movementState = TRICKY_MOVE_JUMPUP_RUNUP;
            break;
        case 6:
            state->movementState = TRICKY_MOVE_JUMPDOWN_RUNUP;
            break;
        }
        break;
    case TRICKY_MOVE_JUMP_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_RUN_UP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            u8* nextRouteNode = trickySelectRouteEntry(state, state->route.nodeA4, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                state->speed = TRICKY_FOLLOW_MAX_SPEED;
                trickyRequestMove(obj, 0x15, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                state->movementState = TRICKY_MOVE_JUMP_PREP;
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    case TRICKY_MOVE_JUMP_PREP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_PREP);
        if ((u8)(state->stateFlags & TRICKY_STATE_FLAG_TURNING_U32)) {
            v = -0.01f * timeDelta + previousSpeed;
            if (v < 0.0f) {
                v = 0.0f;
            }
        } else if (previousSpeed > (v = TRICKY_FOLLOW_ARC_SPEED)) {
            k = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            v = (k < v) ? v : k;
        } else {
            k = gTrickySmallSpeedStep * timeDelta + previousSpeed;
            v = (k > v) ? v : k;
        }
        state->speed = v;
        {
            f32 dz;
            f32 dx;
            f32 sqz;
            f32 sqx;

            dx = ((TrickyState*)obj->extra)->dirX;
            sqx = dx;
            sqx = sqx * sqx;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqz = dz;
            sqz = sqz * sqz;
            if (sqx + sqz > 0.01f) {
                trickyTurnTowardYaw(obj, (s16)getAngle(-dx, -dz));
            }
        }
        if (obj->anim.currentMoveProgress < TRICKY_FOLLOW_ARC_HALF_PROGRESS) {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed, &state->moveProgress);
            obj->anim.localPosX = timeDelta * (state->dirX * state->speed) + obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->dirZ * state->speed) + obj->anim.localPosZ;
        } else {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed / 4.0f, &state->moveProgress);
            obj->anim.localPosX =
                timeDelta * (state->dirX * (state->speed * (k = TRICKY_FOLLOW_ARC_QUARTER_PROGRESS))) +
                obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->dirZ * (state->speed * k)) + obj->anim.localPosZ;
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            f32 dx;
            TrickyJumpArc* arc = &state->jumpArc;
            RomCurveDef* landNode = state->route.nodeA0;
            dx = landNode->x - obj->anim.worldPosX;
            sqx = dx * dx;
            dx = landNode->z - obj->anim.worldPosZ;
            dx = dx * dx;
            len = sqrtf(sqx + dx);
            arc->duration = len / TRICKY_FOLLOW_ARC_SPEED;
            arc->time = (v = 0.0f);
            arc->baseX = obj->anim.worldPosX;
            arc->baseY = obj->anim.worldPosY;
            arc->baseZ = obj->anim.worldPosZ;
            arc->landX = landNode->x;
            arc->landZ = landNode->z;
            k = arc->duration;
            arc->riseCoeff = -(TRICKY_FOLLOW_ARC_COEFFICIENT * k * k - (landNode->y - obj->anim.worldPosY)) / k;
            trickyRequestMove(obj, 0x16, v, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->arcMoveProgress = arc->time / arc->duration;
            state->speed = TRICKY_FOLLOW_ARC_SPEED;
            state->movementState = TRICKY_MOVE_JUMPING;
            TRICKY_ADVANCE_ROUTE_TO_END(state);
        }
        break;
    case TRICKY_MOVE_JUMPING: {
        TrickyJumpArc* arc = &state->jumpArc;
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMPING);
        arc->time = arc->time + timeDelta;
        if (arc->time >= arc->duration) {
            obj->anim.localPosY = ((RomCurveDef*)state->route.nodeA0)->y;
            state->arcMoveProgress = 1.0f;
            state->movementState = TRICKY_MOVE_WALK_NODES;
        } else {
            f32 baseX = arc->baseX;
            f32 baseZ;
            obj->anim.localPosX = (arc->landX - baseX) * (arc->time / arc->duration) + baseX;
            k = arc->time;
            obj->anim.localPosY = TRICKY_FOLLOW_ARC_COEFFICIENT * k * k + (arc->riseCoeff * k + arc->baseY);
            baseZ = arc->baseZ;
            obj->anim.localPosZ = (arc->landZ - baseZ) * (arc->time / arc->duration) + baseZ;
            v = arc->duration;
            if (v <= 24.0f) {
                state->arcMoveProgress = arc->time / v;
            } else {
                k = arc->time;
                if (k <= 6.0f) {
                    state->arcMoveProgress = k / 24.0f;
                } else if (k >= v - 6.0f) {
                    f32 adj;
                    adj = 24.0f - v;
                    state->arcMoveProgress = (adj + k) / 24.0f;
                } else {
                    k = (k - 6.0f) / (v - 12.0f);
                    state->arcMoveProgress = k / 2.0f + TRICKY_FOLLOW_ARC_QUARTER_PROGRESS;
                }
            }
            Obj_SetParent(obj, NULL, 0);
            state->heightUpdateActive = 0;
        }
        break;
    }
    case TRICKY_MOVE_JUMPUP_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_UP_RUN_UP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            u8* nextRouteNode = trickySelectRouteEntry(state, state->route.nodeA4, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                if ((int)randomGetRange(0, 1) != 0) {
                    trickyRequestMove(obj, 0x17, TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                } else {
                    trickyRequestMove(obj, 0x18, TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                }
                state->verticalDelta = (((RomCurveDef*)state->route.nodeA0)->y - obj->anim.worldPosY) /
                                       TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR;
                state->movementState = TRICKY_MOVE_JUMPUP;
                TRICKY_ADVANCE_ROUTE_TO_END(state);
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    case TRICKY_MOVE_JUMPUP:
    case TRICKY_MOVE_JUMPDOWN:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_DOWN_OR_UP);
        state->heightUpdateActive = 0;
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        {
            f32 dz;
            f32 dx;
            dx = ((TrickyState*)obj->extra)->dirX;
            sqz = dx;
            sqz = sqz * sqz;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqx = dz;
            sqx = sqx * sqx;
            if (sqz + sqx > 0.01f) {
                trickyTurnTowardYaw(obj, (s16)getAngle(-dx, -dz));
            }
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            state->speed = 0.75f;
            moveTricky(obj, &state->route.posX);
            state->movementState = TRICKY_MOVE_WALK_NODES;
        }
        break;
    case TRICKY_MOVE_JUMPDOWN_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMPDOWN_RUNUP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < 0.0f) ? 0.0f : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            u8* nextRouteNode = trickySelectRouteEntry(state, state->route.nodeA4, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.nodeA0;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (0.0f != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                trickyRequestMove(obj, 0x19, TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                state->verticalDelta = (obj->anim.worldPosY - ((RomCurveDef*)state->route.nodeA0)->y) /
                                       TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR;
                state->movementState = TRICKY_MOVE_JUMPDOWN;
                TRICKY_ADVANCE_ROUTE_TO_END(state);
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    default:
        trickyDebugPrint(debugStrings + TRICKY_DBG_INVALID_MOVEMENT_STATE);
    }
    if (state->movementState < 5) {
        if (isInWalkGroupOrPatch(&obj->anim.worldPosX) != 0) {
            state->homePosX = obj->anim.worldPosX;
            state->homePosY = obj->anim.worldPosY;
            state->homePosZ = obj->anim.worldPosZ;
        } else {
            (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
            obj->anim.localPosX = state->homePosX;
            obj->anim.localPosY = state->homePosY;
            obj->anim.localPosZ = state->homePosZ;
            obj->anim.worldPosX = state->homePosX;
            obj->anim.worldPosY = state->homePosY;
            obj->anim.worldPosZ = state->homePosZ;
            ObjHits_SyncObjectPosition(obj);
        }
    }
    {
        u8 movementState = state->movementState;

        if (((((movementState == TRICKY_MOVE_WALK_WAIT) || (movementState == TRICKY_MOVE_WALK_START_PATCH)) ||
              (movementState == TRICKY_MOVE_WALK_PATCH_EXIT)) ||
             (movementState == TRICKY_MOVE_WALK_END_PATCH)) &&
            (0.0f == state->speed)) {
            return 2;
        }
    }
    if (didMove != 0) {
        return 1;
    }
    return 0;
}

void trickyUpdateApproachSpeed(GameObject* obj, f32 stoppingRadius, TrickyState* state, f32* targetPos,
                               u8 slowWhenFacingAway) {
    struct {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } rotation;
    f32 targetDelta[3];
    f32 deceleration;
    f32 deltaTime;
    f32 projectedSpeed;
    f32 stoppingDistance;
    f32 stoppingRadiusSq;
    f32 totalStoppingRadius;
    f32 targetDistanceSq;
    f32 dx;
    f32 dz;
    f32 previousPathSpeed;
    f32 candidateSpeed;
    f32* currentPathPoint;
    TrickyState* objectState;

    stoppingDistance = gTrickySmallSpeedStep;
    projectedSpeed = state->speed;
    deltaTime = timeDelta;
    deceleration = gTrickySpeedDecayStep * deltaTime;
    while (projectedSpeed > 0.0f) {
        stoppingDistance = projectedSpeed * deltaTime + stoppingDistance;
        projectedSpeed = projectedSpeed + deceleration;
    }
    totalStoppingRadius = stoppingRadius + stoppingDistance;
    stoppingRadiusSq = totalStoppingRadius;
    stoppingRadiusSq = stoppingRadiusSq * totalStoppingRadius;
    targetDistanceSq = getXZDistanceSquared(targetPos, &obj->anim.worldPosX);
    if (targetDistanceSq < stoppingRadiusSq) {
        candidateSpeed = state->speed;
        candidateSpeed = candidateSpeed + gTrickySpeedDecayStep * timeDelta;
        state->speed = (candidateSpeed < 0.0f) ? 0.0f : candidateSpeed;
        return;
    }
    if (slowWhenFacingAway != 0) {
        targetDelta[0] = targetPos[0] - obj->anim.worldPosX;
        targetDelta[1] = targetPos[1] - obj->anim.worldPosY;
        targetDelta[2] = targetPos[2] - obj->anim.worldPosZ;
        rotation.angle = -obj->anim.rotX;
        rotation._pad0 = 0;
        rotation._pad1 = 0;
        vecRotateZXY(&rotation.angle, targetDelta);
        if (targetDelta[2] > 0.0f) {
            candidateSpeed = state->speed;
            candidateSpeed = candidateSpeed + gTrickySpeedDecayStep * timeDelta;
            state->speed = (candidateSpeed < 0.0f) ? 0.0f : candidateSpeed;
            return;
        }
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_TURNING_U32) != 0) {
        state->speed = -0.01f * timeDelta + state->speed;
        if (state->speed < 0.0f) {
            state->speed = 0.0f;
        }
        return;
    }
    {
        f32 deltaSpeed = 5.0f + totalStoppingRadius;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        objectState = obj->extra;
        currentPathPoint = objectState->targetPosPtr;
        if (currentPathPoint == objectState->previousPathPoint) {
            dx = objectState->previousPathX - obj->anim.worldPosX;
            dz = objectState->previousPathZ - obj->anim.worldPosZ;
            previousPathSpeed = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = currentPathPoint[0] - obj->anim.worldPosX;
            dz = currentPathPoint[2] - obj->anim.worldPosZ;
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidateSpeed = distOther - previousPathSpeed;
            }
        } else {
            candidateSpeed = 0.0f;
        }
        if (targetDistanceSq < deltaSpeedSq) {
            if (candidateSpeed > 0.0f) {
                f32 curSpeed = state->speed;
                if (candidateSpeed < curSpeed) {
                    f32 step = gTrickySpeedDecayStep * timeDelta + curSpeed;
                    state->speed = (step < candidateSpeed) ? candidateSpeed : step;
                    return;
                } else {
                    f32 step;
                    if (candidateSpeed > TRICKY_FOLLOW_MAX_SPEED) {
                        step = gTrickySmallSpeedStep * timeDelta + curSpeed;
                        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
                        return;
                    }
                    step = gTrickySmallSpeedStep * timeDelta + curSpeed;
                    state->speed = (step > candidateSpeed) ? candidateSpeed : step;
                    return;
                }
            }
        }
    }
    if ((state->stateFlags & 0x00100000) != 0) {
        state->speed = TRICKY_FAST_MOVE_BLEND_SPEED * timeDelta + state->speed;
        if (state->speed > TRICKY_FOLLOW_MAX_SPEED) {
            state->speed = TRICKY_FOLLOW_MAX_SPEED;
        }
        return;
    }
    {
        f32 step = state->speed;
        step = step + gTrickySmallSpeedStep * timeDelta;
        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
    }
}

#define TRICKYWARP_OBJ_GROUP 0x4b /* DLL 0x100 trickywarp */

void tricky_stateGoToWarpPoint(GameObject* self, TrickyState* state) {
    GameObject* nearest;
    f32 rejectDist;
    f32 minDist;
    f32 dist;
    f32 z;
    GameObject** objs;
    GameObject** objsList;
    int count;
    int i;
    int inWater;
    GameObject* best;

    nearest = NULL;
    best = NULL;
    minDist = gTrickyMaxDistance;

    if (trickyShouldGoToWarpPoint(self, state) == 0) {
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        z = 0.0f;
        state->cooldownA = z;
        state->cooldownB.f = z;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
        state->commandPhase = -1;
        return;
    }

    objsList = (GameObject**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &count);
    i = 0;
    objs = objsList;
    rejectDist = 2500.0f;
    for (; i < count; i++) {
        dist = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &(*objs)->anim.worldPosX);
        if (dist > rejectDist) {
            dist = getXZDistanceSquared(&self->anim.worldPosX, &(*objs)->anim.worldPosX);
            if (dist < minDist) {
                best = *objs;
                minDist = dist;
            }
        }
        objs++;
    }

    nearest = best;
    if (nearest != NULL) {
        state->followObj = nearest;
        if (state->targetPosPtr != &nearest->anim.worldPosX) {
            state->targetPosPtr = &nearest->anim.worldPosX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~0x400;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        if (trickyUpdateMovementState(self, 15.0f, state) == 1) {
            return;
        }
    }

    if (0.0f == state->waterLevel) {
        inWater = 0;
    } else if (gTrickyEventTimeSentinel == state->eventTime) {
        inWater = 1;
    } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
        inWater = 1;
    } else {
        inWater = 0;
    }

    if (inWater != 0) {
        trickyRequestMove(self, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
        state->particleTimer = 0.0f;
        trickyDebugPrint(sInWaterMessage);
    } else {
        trickyRequestMove(self, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyDebugPrint(sTrickyDryLandDebugMessage);
    }
}

/*
 * Should Tricky head for a trickywarp point?
 *
 * Queried with Tricky (arg1) and his own TrickyState extra block (arg2). It returns:
 *   0 - no,
 *   1 - yes,
 *   2 - yes, and the player is still right next to him (the enter condition).
 *
 * The answer is no outright while another object of group 0x53 is nearby.
 * Otherwise, while no command is mid-dispatch (commandPhase != 3) and the
 * owning player carries the parent-slack flag, map cell 0x38 gates the answer
 * behind the TrickyFood game bits and any other cell arms the cooldown packed
 * into statusFlags and answers yes. The final range test promotes a "1" to a
 * "2" when the player sits within 2500.0f squared units of Tricky.
 */

#define MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK 0x1000
#define PRESSURESWITCHFB_REMOVE_GROUP_ID    0x53 /* DLL 0xFB pressureswitchfb (self-registers) */

int trickyShouldGoToWarpPoint(GameObject* tricky, TrickyState* state) {
    int result = 0;
    f32 dist = 40.0f;
    TrickyState* st = state;

    if (st->warpCooldown != 0) {
        st->warpCooldown--;
        result = 1;
    }

    if (objGetNearestTypeTo(PRESSURESWITCHFB_REMOVE_GROUP_ID, tricky, &dist) != NULL) {
        return 0;
    }

    if (st->commandPhase != 3) {
        GameObject* playerObj = st->playerObj;

        if ((playerObj->objectFlags & MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK) != 0) {
            if (coordsToMapCell(tricky->anim.localPosX, tricky->anim.localPosZ) == 0x38) {
                if ((mainGetBit(0x385) == 0) && (mainGetBit(0x384) != 0)) {
                    if ((mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) ||
                        (mainGetBit(GAMEBIT_ITEM_TrickyFood_GrabInProgress) != 0)) {
                        result = 1;
                    }
                }
            } else {
                st->warpCooldown = 0x1F;
                result = 1;
            }
        }
    }

    if (result == 1) {
        GameObject* playerObj = state->playerObj;

        if (vec3f_distanceSquared(&playerObj->anim.worldPosX, &tricky->anim.worldPosX) < 2500.0f) {
            return 2;
        }
    }
    return result;
}

/*
 * Tricky "growl/dig" action handler.
 *
 * trickyGrowl drives a four-step substate machine for the Tricky sidekick:
 *   0  growl windup  - barks (sfx 0x299), kicks off anim move 0x33
 *   1  face target   - turns toward the followed object (extra+0x28), with a
 *                      random chance to bark again, until anim flag + timer hit
 *   2  dig start     - if loading isn't locked, spawns seven child objects
 *                      (Obj_AllocObjectSetup/objSetupObject into scratch700..),
 *                      plays/loops the dig sfx (0x3db/0x3dc) and runs anim 0x34
 *   3  dig end       - on move progress >= threshold, resets child anim speed,
 *                      stops the dig loop, barks (sfx 0x29d) and clears the
 *                      action's state flags, returning to substate 0
 *
 * Barks are gated on bit 6 of TrickyState.statusFlags, the current anim move
 * being outside [0x29,0x30), and no sfx already playing on channel 0x10.
 */

#define CHILD_OBJECT_COUNT          7
#define TRICKY_CHILD_OBJ_FLAMEBLAST 0x4f0 /* "flameblast" (DLL 0xF3) */

enum {
    TRICKYGROWL_WINDUP = 0,
    TRICKYGROWL_FACE_TARGET = 1,
    TRICKYGROWL_DIG_START = 2,
    TRICKYGROWL_DIG_END = 3
};

char sTrickyGrowlAtDebugTextBlock[] = {
    0x47, 0x52, 0x4F, 0x57, 0x4C, 0x41, 0x54, 0x5F, 0x47, 0x4F, 0x54, 0x4F, 0x0A, 0x00, 0x00, 0x00, 0x47, 0x52,
    0x4F, 0x57, 0x4C, 0x41, 0x54, 0x5F, 0x47, 0x52, 0x4F, 0x57, 0x4C, 0x49, 0x4E, 0x47, 0x0A, 0x00, 0x00, 0x00,
    0x47, 0x52, 0x4F, 0x57, 0x4C, 0x41, 0x54, 0x5F, 0x47, 0x4F, 0x54, 0x4F, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x0A,
    0x00, 0x00, 0x47, 0x52, 0x4F, 0x57, 0x4C, 0x41, 0x54, 0x5F, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x0A, 0x00, 0x00,
    0x42, 0x41, 0x44, 0x44, 0x49, 0x45, 0x41, 0x4C, 0x45, 0x52, 0x54, 0x5F, 0x47, 0x4F, 0x54, 0x4F, 0x0A, 0x00,
    0x00, 0x00, 0x42, 0x41, 0x44, 0x44, 0x49, 0x45, 0x41, 0x4C, 0x45, 0x52, 0x54, 0x5F, 0x42, 0x41, 0x52, 0x4B,
    0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x0A, 0x00, 0x42, 0x41, 0x44, 0x44, 0x49, 0x45, 0x41, 0x4C, 0x4C, 0x45,
    0x52, 0x54, 0x5F, 0x47, 0x4F, 0x54, 0x4F, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x0A, 0x00, 0x42, 0x41, 0x44, 0x44,
    0x49, 0x45, 0x41, 0x4C, 0x4C, 0x45, 0x52, 0x54, 0x5F, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x0A, 0x00,
};

void trickyGrowl(GameObject* obj, TrickyState* trickyState) {
    TrickyState* barkState;
    int i;
    int j;
    TrickyState* finishSoundState;
    void** slot;
    FlameblastPlacement* setup;
    void** slot2;
    char* strBase = gTrickyDebugStringTable;

    switch (trickyState->substate) {
    case TRICKYGROWL_WINDUP:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GOTO);
        if (trickyUpdateMovementState(obj, 30.0f, trickyState) == 0) {
            barkState = obj->extra;
            if (barkState->soundSuppressed == 0u) {
                s16 move = obj->anim.currentMove;
                if (move >= 0x30 || move < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &barkState->soundState, 0x299, 0x100, -1, 0);
                    }
                }
            }
            trickyState->substate = TRICKYGROWL_FACE_TARGET;
            trickyRequestMove(obj, 0x33, TRICKY_LAND_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->stateWord728 = 0;
        }
        break;
    case TRICKYGROWL_FACE_TARGET:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GROWLING);
        if (*trickyState->progressPtr != 0 && trickyState->stateWord728 != 0) {
            trickyState->substate = TRICKYGROWL_DIG_START;
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0) {
                barkState = obj->extra;
                if (barkState->soundSuppressed == 0u) {
                    s16 move = obj->anim.currentMove;
                    if (move >= 0x30 || move < 0x29) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            objSoundStartTimed(obj, &barkState->soundState, 0x299, 0x100, -1, 0);
                        }
                    }
                }
            }
        }
        break;
    case TRICKYGROWL_DIG_START:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GOTOFLAME);
        if (trickyUpdateMovementState(obj, 25.0f, trickyState) == 0) {
            if ((u8)Obj_IsLoadingLocked() != 0) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (i = 0, slot = (void**)trickyState; i < CHILD_OBJECT_COUNT; slot++, i++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_CHILD_OBJ_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = i;
                    TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot) =
                        objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
            (*trickyState->progressPtr)--;
            trickyRequestMove(obj, 0x34, TRICKY_LAND_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKYGROWL_DIG_END;
            trickyState->stateWord728 = 0;
        }
        break;
    case TRICKYGROWL_DIG_END:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_FLAME);
        if (obj->anim.currentMoveProgress >= 0.95f) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (j = 0, slot2 = (void**)trickyState; j < CHILD_OBJECT_COUNT; slot2++, j++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot2));
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            finishSoundState = obj->extra;
            if (finishSoundState->soundSuppressed == 0u) {
                s16 move = obj->anim.currentMove;
                if (move >= 0x30 || move < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &finishSoundState->soundState, 0x29d, 0, -1, 0);
                    }
                }
            }
            trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            trickyState->substate = TRICKYGROWL_WINDUP;
            {
                f32 resetValue = 0.0f;
                trickyState->cooldownA = resetValue;
                trickyState->cooldownB.f = resetValue;
            }
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm = -1;
                trickyState->commandPhase = mm;
            }
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    }
}

/*
 * Tricky companion "circle the enemy" combat behaviour (part of the
 * tricky AI module; operates on TrickyState, the per-object scratch at
 * GameObject.extra).
 *
 * trickyFindCirclingTarget       - picks the object Tricky should circle:
 *                                   the current follow target if it is the
 *                                   special romDefNo 0x6a3 actor, else the
 *                                   player's lock-on target, validated
 *                                   against ObjGroup 3 by a triangle-
 *                                   inequality distance test.
 * trickyUpdateCirclingTargetPosition
 *                                - orbits Tricky around followObj: picks a
 *                                   random spin direction once, advances the
 *                                   orbit angle while it stays near the seed
 *                                   heading, and writes the desired
 *                                   x/y/z onto the state; trickyUpdateMovementState
 *                                   then steers toward it.
 * trickyUpdateCircling                    - the circling state machine, dispatched on
 *                                   substate t->substate (0 acquire, 1 approach,
 *                                   2/3/4 the special charge/spawn/finish
 *                                   path, 5 orbit-and-pick-best). It spawns
 *                                   helper objects (ids 0x17b, 0x4f0),
 *                                   plays/loops bark and effect sounds, and
 *                                   drives the shared TRICKY_* state macros.
 */

/* group owned by another DLL, queried here */
#define ANIMOBJD2_OBJFLAG_FREED 0x40
/* Objects spawned by the trickyUpdateCircling state machine (retail OBJECTS.bin names
   "TrickyFood" and "flameblast"). */
#define ANIMOBJD2_TRICKY_FOOD_OBJ_ID 0x17b
#define ANIMOBJD2_FLAMEBLAST_OBJ_ID  0x4f0
/* romDefNo of the special actor Tricky circles when it is the current follow target (docblock: "the special romDefNo 0x6a3 actor") */
#define ANIMOBJD2_CIRCLE_TARGET_SEQID 0x6a3

/* trickyUpdateCircling circling substate machine (TrickyState.substate; this object's
 * own values, not a globally shared TrickyState enum). */
enum AnimObjD2Substate {
    ANIMOBJD2_SUBSTATE_ACQUIRE = 0,  /* find/lock onto a target        */
    ANIMOBJD2_SUBSTATE_APPROACH = 1, /* close on the seed heading      */
    ANIMOBJD2_SUBSTATE_CHARGE = 2,   /* retarget + start charge anim   */
    ANIMOBJD2_SUBSTATE_SPAWN = 3,    /* spawn the 7 drip helper objects*/
    ANIMOBJD2_SUBSTATE_FINISH = 4,   /* speed up helpers, bark, reset  */
    ANIMOBJD2_SUBSTATE_ORBIT = 5     /* orbit and pick the best target */
};

/* Spawn-setup buffer seeded in the substate-3 drip burst (defNo 0x4f0).
 * Reuses ObjPlacement's color head and adds a signed stream index at 0x1a. */
typedef struct AnimObjD2DripSetup {
    ObjPlacement head; /* 0x00: color[0..1] written */
    u8 pad18[0x1a - 0x18];
    s16 index; /* 0x1a */
} AnimObjD2DripSetup;

void* trickyFindCirclingTarget(GameObject* obj, void* state);

#define TRICKY_STATE_FLAG_4            0x4
#define TRICKY_STATE_FLAG_800          0x800
#define TRICKY_STATE_FLAG_1000         0x1000
#define TRICKY_STATE_FLAG_8000000      0x8000000
#define TRICKY_STATE_TARGET_DIRTY_FLAG 0x00000400LL
#define TRICKY_STATE_RESET_FLAG_10     TRICKY_STATE_FLAG_COMMAND_ACTIVE
#define TRICKY_STATE_RESET_FLAG_10000  TRICKY_STATE_FLAG_RECALL_REQUEST
#define TRICKY_STATE_RESET_FLAG_20000  TRICKY_STATE_FLAG_HEEL_REQUEST
#define TRICKY_STATE_RESET_FLAG_40000  TRICKY_STATE_FLAG_GUARD_REQUEST

#define TRICKY_RETARGET(st, X)                                                                                         \
    {                                                                                                                  \
        f32* px = &((GameObject*)(X))->anim.worldPosX;                                                                 \
        if (((TrickyState*)(st))->targetPosPtr != px) {                                                                \
            ((TrickyState*)(st))->targetPosPtr = px;                                                                   \
            {                                                                                                          \
                u32 m;                                                                                                 \
                u32 flags = ((TrickyState*)(st))->stateFlags;                                                          \
                m = ~TRICKY_STATE_TARGET_DIRTY_FLAG;                                                                   \
                ((TrickyState*)(st))->stateFlags = flags & m;                                                          \
            }                                                                                                          \
            ((TrickyState*)(st))->linkedWalkGroup = 0;                                                                 \
        }                                                                                                              \
    }

#define TRICKY_RESET_TAIL(st)                                                                                          \
    {                                                                                                                  \
        f32 z = 0.0f;                                                                                                  \
        ((TrickyState*)(st))->cooldownA = z;                                                                           \
        ((TrickyState*)(st))->cooldownB.f = z;                                                                         \
        ((TrickyState*)(st))->stateFlags &= 0xFFFFFFEFLL;                                                              \
        ((TrickyState*)(st))->stateFlags &= 0xFFFEFFFFLL;                                                              \
        ((TrickyState*)(st))->stateFlags &= 0xFFFDFFFFLL;                                                              \
        ((TrickyState*)(st))->stateFlags &= 0xFFFBFFFFLL;                                                              \
        ((TrickyState*)(st))->commandPhase = 0xFF;                                                                     \
    }
#define TRICKY_RESET(st)                                                                                               \
    ((TrickyState*)(st))->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;                                                     \
    ((TrickyState*)(st))->substate = 0;                                                                                \
    TRICKY_RESET_TAIL(st)

static inline int trickyAcquireCirclingTarget(TrickyState* state) {
    int hasTarget;

    if ((state->followObj = trickyFindNearestUsableBaddie(state->playerObj, 150.0f, 0)) != NULL) {
        f32* targetPos = &state->followObj->anim.worldPosX;

        if (state->targetPosPtr != targetPos) {
            state->targetPosPtr = targetPos;
            {
                u32 flags;
                u32 mask;

                flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        hasTarget = 1;
    } else {
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        hasTarget = 0;
        state->substate = hasTarget;
        TRICKY_RESET_TAIL((u8*)state)
    }

    return hasTarget;
}

#define TRICKY_BARK(obj, snd, p4, cfg)                                                                                 \
    {                                                                                                                  \
        cfg = (u8*)((GameObject*)(obj))->extra;                                                                        \
        if (!((TrickyState*)cfg)->soundSuppressed) {                                                                   \
            s16 a0 = ((GameObject*)(obj))->anim.currentMove;                                                           \
            if (a0 >= 0x30 || a0 < 0x29) {                                                                             \
                if (Sfx_IsPlayingFromObjectChannel((GameObject*)(obj), 0x10) == 0) {                                   \
                    objSoundStartTimed((GameObject*)(obj), &((TrickyState*)cfg)->soundState, snd, p4, -1, 0);          \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

void trickyUpdateCircling(GameObject* obj, TrickyState* state) {
    char* str = gTrickyDebugStringTable;
    u8 ok;
    int hasTarget;
    GameObject* bestWarp = NULL;
    f32 bestDetourSavings = 0.0f;
    int warpCount;
    u8* approachCfg;
    u8* orbitCfg;
    u8* finishCfg;

    switch (state->substate) {
    case ANIMOBJD2_SUBSTATE_ACQUIRE: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_GOTO);
        ok = trickyUpdateMovementState(obj, 50.0f, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0) {
            if (state->stateWord728 == 0) {
                {
                    void* ct = trickyFindCirclingTarget((GameObject*)(obj), state);
                    state->cooldownB.ptr = ct;
                    if (ct != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (ok == 2) {
                TRICKY_RESET((u8*)state);
                break;
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) < 3600.0f) {
                int b;
                f32 z;
                state->substate = ANIMOBJD2_SUBSTATE_APPROACH;
                z = 0.0f;
                state->cooldownA = z;
                b = skeetla_isInWater(state);
                if (b != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                    trickyDebugPrint(str + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(str + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_APPROACH: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_BARK, *state->progressPtr, state->stateWord728);
        ok = trickyUpdateMovementState(obj, 50.0f, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0) {
            if (state->stateWord728 == 0) {
                {
                    void* ct = trickyFindCirclingTarget((GameObject*)(obj), state);
                    state->cooldownB.ptr = ct;
                    if (ct != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (ok == 2) {
                TRICKY_RESET((u8*)state);
                break;
            }
            if (ok == 0) {
                trickyRequestMove(obj, 0x33, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
            }
            if (state->stateWord728 != 0) {
                if (*state->progressPtr < 2) {
                    state->stateWord728 = 0;
                    if (Obj_IsLoadingLocked() != 0) {
                        state->stateFlags |= TRICKY_STATE_FLAG_4;
                        TRICKY_RESET((u8*)state);
                        if (state->child == NULL) {
                            AnimObjD2DripSetup* setup =
                                (AnimObjD2DripSetup*)Obj_AllocObjectSetup(0x20, ANIMOBJD2_TRICKY_FOOD_OBJ_ID);
                            s8 slots[4];
                            int free_;
                            slots[0] = -1;
                            slots[1] = -1;
                            slots[2] = -1;
                            if (state->childA != NULL) {
                                slots[state->packedSlots.promptASlot] = 1;
                            }
                            if (state->childB != NULL) {
                                slots[state->packedSlots.promptBSlot] = 1;
                            }
                            if (state->child != NULL) {
                                slots[state->packedSlots.zzzSlot] = 1;
                            }
                            if (slots[0] == -1) {
                                free_ = 0;
                            } else if (slots[1] == -1) {
                                free_ = 1;
                            } else if (slots[2] == -1) {
                                free_ = 2;
                            } else if (slots[3] == -1) {
                                free_ = 3;
                            } else {
                                free_ = -1;
                            }
                            state->packedSlots.zzzSlot = free_;
                            state->child = (void*)objSetupObject((ObjPlacement*)setup, 4, -1, -1, obj->anim.parent);
                            ObjLink_AttachChild(obj, state->child, state->packedSlots.zzzSlot);
                            {
                                f32 z3 = 0.0f;
                                state->childPhaseTimer0 = z3;
                                state->childPhaseTimer1 = z3;
                                state->childPhaseTimer2 = z3;
                            }
                        }
                    }
                } else {
                    state->substate = ANIMOBJD2_SUBSTATE_CHARGE;
                    break;
                }
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) > 5625.0f) {
                state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                break;
            }
            state->cooldownA -= timeDelta;
            if (state->cooldownA < 0.0f) {
                f32 rv;
                rv = (s32)randomGetRange(0xc8, 0x258);
                state->cooldownA = rv / 2.0f;
                TRICKY_BARK((int*)obj, 0x29b, 0x1000, approachCfg);
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_CHARGE: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_GOTOFLAME);
        ok = trickyUpdateMovementState(obj, 55.0f, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0 && ok != 1) {
            trickyRequestMove(obj, 0x34, TRICKY_LAND_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
            state->substate = ANIMOBJD2_SUBSTATE_SPAWN;
            state->stateWord728 = 0;
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_SPAWN:
        if (obj->anim.currentMove != 0x34) {
            break;
        }
        if (obj->anim.currentMoveProgress > 0.3f) {
            if (Obj_IsLoadingLocked() != 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_800;
                {
                    int i = 0;
                    u8* p = (u8*)state;
                    for (; i < 7; i++) {
                        AnimObjD2DripSetup* setup =
                            (AnimObjD2DripSetup*)Obj_AllocObjectSetup(0x24, ANIMOBJD2_FLAMEBLAST_OBJ_ID);
                        setup->head.color[0] = 2;
                        setup->head.color[1] = 1;
                        setup->index = i;
                        ((TrickyState*)p)->flameChildren[0] =
                            objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        p += 4;
                    }
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
            *state->progressPtr -= 2;
            state->substate = ANIMOBJD2_SUBSTATE_FINISH;
        }
        break;
    case ANIMOBJD2_SUBSTATE_FINISH: {
        u32 fl;
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_FLAME);
        fl = state->stateFlags;
        if (fl & TRICKY_STATE_FLAG_8000000) {
            state->stateFlags = fl & ~(u64)TRICKY_STATE_FLAG_800;
            state->stateFlags |= TRICKY_STATE_FLAG_1000;
            {
                u8* p;
                int i = 0;
                p = (u8*)state;
                for (; i < 7; i++) {
                    objSetAnimSpeedTo1(((TrickyState*)p)->flameChildren[0]);
                    p += 4;
                }
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            TRICKY_BARK((int*)obj, 0x29d, 0, finishCfg);
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_RESET_FLAG_10;
                state->stateFlags = flags & mask;
            }
            state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_ORBIT: {
        void** warpCursor;
        GameObject* target;
        GameObject* nearestBaddie = trickyFindNearestUsableBaddie(state->playerObj, 150.0f, 0);
        if (nearestBaddie != NULL && nearestBaddie->anim.romDefNo == ANIMOBJD2_CIRCLE_TARGET_SEQID) {
            target = nearestBaddie;
        } else {
            target = (GameObject*)Player_GetTargetObject((int)state->playerObj);
        }
        if (target != state->cooldownB.obj || state->stateWord728 != 0) {
            TRICKY_RETARGET((u8*)state, state->followObj);
            state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
        } else {
            void** warpList = (void**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
            int i = 0;
            warpCursor = warpList;
            for (; i < warpCount; i++) {
                f32 warpToTarget =
                    Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &target->anim.worldPosX);
                f32 warpToPlayer =
                    Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &state->playerObj->anim.worldPosX);
                f32 targetToPlayer = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if (warpToTarget + warpToPlayer > 2.0f * targetToPlayer) {
                    f32 warpToTricky =
                        Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &obj->anim.worldPosX);
                    if (warpToPlayer - warpToTricky > bestDetourSavings) {
                        bestDetourSavings = warpToPlayer - warpToTricky;
                        bestWarp = warpCursor[0];
                    }
                }
                warpCursor++;
            }
            {
                GameObject* circlingWarpDetour = state->circlingWarpDetour;
                if (circlingWarpDetour != NULL && (circlingWarpDetour->objectFlags & ANIMOBJD2_OBJFLAG_FREED)) {
                    state->circlingWarpDetour = NULL;
                    TRICKY_RETARGET((u8*)state, state->playerObj);
                }
            }
            if (bestWarp != NULL) {
                if (state->circlingWarpDetour == NULL) {
                    TRICKY_BARK((int*)obj, 0x35b, 0x500, orbitCfg);
                }
                if (state->circlingWarpDetour == NULL || state->circlingWarpDetour != bestWarp) {
                    state->circlingWarpDetour = bestWarp;
                    TRICKY_RETARGET((u8*)state, state->circlingWarpDetour);
                }
            }
        }
        {
            u8 orbitMovementStatus;
            if (state->circlingWarpDetour != NULL) {
                orbitMovementStatus = trickyUpdateMovementState(obj, 5.0f, state);
            } else {
                orbitMovementStatus = trickyUpdateMovementState(obj, gTrickyMaxDistance, state);
            }
            if (orbitMovementStatus != 1) {
                int useSwimMove;
                if (0.0f == state->waterLevel) {
                    useSwimMove = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    useSwimMove = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    useSwimMove = 1;
                } else {
                    useSwimMove = 0;
                }
                if (useSwimMove != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                    trickyDebugPrint(str + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(str + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    }
}

void* trickyFindCirclingTarget(GameObject* obj, void* state) {
    GameObject* target;
    void** list;
    int count;
    int i;
    f32 d1, d2, d3;

    target = (GameObject*)((TrickyState*)state)->followObj;
    if (target->anim.romDefNo == ANIMOBJD2_CIRCLE_TARGET_SEQID) {
        return target;
    }

    target = (GameObject*)playerGetTargetObject(((TrickyState*)state)->playerObj);
    if (target != NULL) {
        list = (void**)objGetAllOfType(3, &count);
        for (i = 0; i < count; i++) {
            if ((GameObject*)*list == target) {
                d1 = Vec_xzDistance(&obj->anim.worldPosX, &target->anim.worldPosX);
                d2 = Vec_xzDistance(&obj->anim.worldPosX, &((TrickyState*)state)->playerObj->anim.worldPosX);
                d3 = Vec_xzDistance(&target->anim.worldPosX, &((TrickyState*)state)->playerObj->anim.worldPosX);
                if ((d1 + d2) < 2.0f * d3) {
                    return target;
                }
                break;
            }
            list++;
        }
    }
    return NULL;
}

void trickyUpdateCirclingTargetPosition(void* objPtr, void* state) {
    GameObject* obj = (GameObject*)objPtr;
    GameObject* target = ((TrickyState*)state)->followObj;
    f32 dx = target->anim.worldPosX - obj->anim.worldPosX;
    f32 dz = target->anim.worldPosZ - obj->anim.worldPosZ;
    int angle = atan2Angle16(dx, dz);
    s32 delta;
    s32 absDelta;

    if (((TrickyState*)state)->substate == ANIMOBJD2_SUBSTATE_ACQUIRE) {
        ((TrickyState*)state)->scratch700.i = randomGetRange(0, 1);
        if (((TrickyState*)state)->scratch700.i == 0) {
            ((TrickyState*)state)->scratch700.i = -1;
        }
        ((TrickyState*)state)->scratch704.i = angle;
        ((TrickyState*)state)->substate = ANIMOBJD2_SUBSTATE_APPROACH;
    }

    delta = angle - (s32)(u16)((TrickyState*)state)->scratch704.u;
    if (delta > 0x8000) {
        delta -= 0xFFFF;
    }
    if (delta < -0x8000) {
        delta += 0xFFFF;
    }

    if (delta >= 0) {
        absDelta = delta;
    } else {
        absDelta = -delta;
    }
    if (absDelta < 0x2000) {
        ((TrickyState*)state)->scratch704.i =
            ((TrickyState*)state)->scratch704.i + (((TrickyState*)state)->scratch700.i << 11);
    }

    ((TrickyState*)state)->scratch708.f = ((TrickyState*)state)->followObj->anim.worldPosX -
                                          50.0f * fsin16Precise((u16)((TrickyState*)state)->scratch704.i);
    ((TrickyState*)state)->scratch70C.f = ((TrickyState*)state)->followObj->anim.worldPosY;
    ((TrickyState*)state)->scratch710.f = ((TrickyState*)state)->followObj->anim.worldPosZ -
                                          50.0f * fcos16Precise((u16)((TrickyState*)state)->scratch704.i);

    if (trickyUpdateMovementState(objPtr, 5.0f, state) == 0) {
        trickyReportError(sTrickyShouldNeverStopCirclingError);
    }
}

const char sTrickyShouldNeverStopCirclingError[] = "error tricky should never stop when circling\n";

/*
 * Tricky companion-AI substate handlers (TrickyState::substate machines).
 *
 * Each entry point is one behavior tick dispatched off TrickyState->substate:
 *   tricky_fetchBall - fetch/carry-ball behavior (grab a thrown ball via
 *                      sidekickBall_* entry points, swim or walk to it, return it).
 *   tricky_idleAndEat - idle/eat ambient state (random bark cues, eating anim).
 *   tricky_trackTumbleweed - track a TumbleweedBush target and steer Tricky toward it,
 *                 gated by game bit 0x48b.
 *   tricky_moveToFollowTarget - simple swim-or-walk move toward the follow target.
 *
 * Common to all: water is detected by comparing waterLevel / eventTime /
 * currentTime to pick a swim anim vs a ground anim. tricky_fetchBall and tricky_idleAndEat play a
 * localized bark sfx unless one is already on object channel 16. Debug strings
 * are emitted via
 * trickyDebugPrint. tricky_state.h owns the TrickyState layout; the lbl_803E*
 * floats are pooled .sdata2 tuning constants shared throughout this DLL.
 *
 * tricky_fetchBall's case numbering/fallthrough (0 into 1, 4 into 5 via the label
 * inside the if) is ground truth from the retail jump table at 0x8031D910 --
 * do not renumber or "un-nest" case 5.
 */

#define TRICKY_CLEAR_RESET_FLAGS(st)                                                                                   \
    {                                                                                                                  \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;                                          \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10000;                                       \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_20000;                                       \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_40000;                                       \
        {                                                                                                              \
            s8 mm;                                                                                                     \
            mm = -1;                                                                                                   \
            ((TrickyState*)(st))->commandPhase = mm;                                                                   \
        }                                                                                                              \
    }

void tricky_fetchBall(GameObject* obj, TrickyState* state) {
    int status;
    TrickyState* extra;
    int useSwimAnim;
    s16 move;
    f32 bob;
    f32 resetTimer;
    f32* targetPos;

    switch (state->substate) {
    case 0:
        state->scratch700.ptr = state->followObj;
        state->scratch704.f = 180.0f;
        state->substate = 1;
        state->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
        /* fall through */
    case 1:
        if (sidekickBall_isHeldOrMoving(state->scratch700.obj) != 0) {
            status = trickyUpdateMovementState(obj, 13.0f, state);
            if (status == 0) {
                if (0.0f == state->waterLevel) {
                    useSwimAnim = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    useSwimAnim = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    useSwimAnim = 1;
                } else {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, 28, 0.03f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, 17, 0.03f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
                state->substate = 3;
                sidekickBall_setIdle(state->scratch700.obj, obj);
            } else if (status == 2) {
                extra = obj->extra;
                if (extra->soundSuppressed == 0) {
                    move = (obj)->anim.currentMove;
                    if (move >= 48 || move < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objSoundStartTimed(obj, &extra->soundState, 861, 1280, -1, 0);
                        }
                    }
                }
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                resetTimer = 0.0f;
                state->cooldownA = resetTimer;
                state->cooldownB.f = resetTimer;
                TRICKY_CLEAR_RESET_FLAGS(state);
            }
        } else {
            status = trickyUpdateMovementState(obj, 20.0f, state);
            if (status == 0) {
                if (state->scratch704.f > 0.0f) {
                    if (0.0f == state->waterLevel) {
                        useSwimAnim = 0;
                    } else if (gTrickyEventTimeSentinel == state->eventTime) {
                        useSwimAnim = 1;
                    } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                        useSwimAnim = 1;
                    } else {
                        useSwimAnim = 0;
                    }
                    if (useSwimAnim != 0) {
                        trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = 0.0f;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    state->scratch704.f -= timeDelta;
                    if (state->scratch704.f <= 0.0f) {
                        if (0.0f == state->waterLevel) {
                            useSwimAnim = 0;
                        } else if (gTrickyEventTimeSentinel == state->eventTime) {
                            useSwimAnim = 1;
                        } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                            useSwimAnim = 1;
                        } else {
                            useSwimAnim = 0;
                        }
                        if (useSwimAnim != 0) {
                            state->scratch704.f = 180.0f;
                        } else {
                            state->scratch708.f = 60.0f;
                        }
                    }
                } else {
                    trickyRequestMove(obj, 16, TRICKY_FAST_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                    state->scratch708.f -= timeDelta;
                    if (state->scratch708.f <= 0.0f) {
                        state->scratch704.f = 180.0f;
                    }
                }
            } else if (status == 1) {
                state->sfxIntervalTimer -= timeDelta;
                if (state->sfxIntervalTimer <= 0.0f) {
                    state->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
                    extra = obj->extra;
                    if (extra->soundSuppressed != 0) {
                        break;
                    }
                    move = (obj)->anim.currentMove;
                    if (move < 48) {
                        if (move >= 41) {
                            break;
                        }
                    }
                    if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                        objSoundStartTimed(obj, &extra->soundState, 865, 1280, -1, 0);
                    }
                }
            } else {
                if (0.0f == state->waterLevel) {
                    useSwimAnim = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    useSwimAnim = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    useSwimAnim = 1;
                } else {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
            }
        }
        break;
    case 6:
        if ((obj)->anim.currentMoveProgress >= 0.65f) {
            status = state->scratch700.i;
            ((GameObject*)status)->anim.localPosY += 5.0f;
            bob = -mathCosf(TRICKY_PI * (f32)(s32) * (short*)obj / TRICKY_ANGLE_HALF_TURN_UNITS);
            sidekickBall_launch(state->scratch700.obj, obj,
                                -mathSinf(TRICKY_PI * (f32)(s32) * (short*)obj / TRICKY_ANGLE_HALF_TURN_UNITS), 1.0f,
                                bob);
            state->substate = 2;
        }
        break;
    case 2:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            state->variantFadeTimer = 20.0f;
            if (state->progressPtr[2] >= 0xef) {
                state->progressPtr[2] = 0;
            } else {
                state->progressPtr[2]++;
            }
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_RESET_FLAG_10;
                state->stateFlags = flags & mask;
            }
            state->substate = 7;
            targetPos = &state->followObj->anim.worldPosX;
            if (state->targetPosPtr != targetPos) {
                state->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
        }
        break;
    case 7:
        status = trickyUpdateMovementState(obj, 20.0f, state);
        if (status != 1) {
            if (0.0f == state->waterLevel) {
                useSwimAnim = 0;
            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                useSwimAnim = 1;
            } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                useSwimAnim = 1;
            } else {
                useSwimAnim = 0;
            }
            if (useSwimAnim != 0) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            return;
        }
        if (sidekickBall_isIdle(state->followObj) != 0) {
            state->scratch704.f = 180.0f;
            state->substate = 1;
        }
        break;
    case 3:
        if ((obj)->anim.currentMoveProgress >= 0.5f) {
            state->substate = 4;
        }
        break;
    case 4:
        if ((obj)->anim.currentMoveProgress >= 0.95f) {
            targetPos = &state->playerObj->anim.worldPosX;
            if (state->targetPosPtr != targetPos) {
                state->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            state->substate = 5;
        case 5:
            if (trickyUpdateMovementState(obj, 30.0f, state) == 0) {
                if (0.0f == state->waterLevel) {
                    useSwimAnim = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    useSwimAnim = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    useSwimAnim = 1;
                } else {
                    useSwimAnim = 0;
                }
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, 29, 0.03f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, 19, 0.03f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->substate = 6;
            }
        }
        break;
    }
    if (((state->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) &&
        ViewFrustum_IsSphereVisible(&(obj)->anim.localPosX, 19.0f) == 0) {
        Obj_FreeObject(state->followObj);
    } else {
        sidekickBall_keepAlive(state->scratch700.obj);
    }
}

void tricky_idleAndEat(GameObject* obj, TrickyState* state) {
    TrickyState* extra;
    int inWater;
    s16 move;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        if (trickyUpdateMovementState(obj, 5.0f, state) == 0) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= 0.0f) {
                state->idleSfxTimer = (f32)(s32)randomGetRange(500, 750);
                extra = obj->extra;
                if (extra->soundSuppressed == 0) {
                    move = obj->anim.currentMove;
                    if (move >= 48 || move < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objSoundStartTimed(obj, &extra->soundState, 864, 1280, -1, 0);
                        }
                    }
                }
            }
            if (0.0f == state->waterLevel) {
                inWater = 0;
            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                inWater = 1;
            } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                inWater = 1;
            } else {
                inWater = 0;
            }
            if (inWater != 0) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch (obj->anim.currentMove) {
                case 13:
                    if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
                        trickyRequestMove(obj, 49, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    }
                    break;
                case 49:
                    break;
                default:
                    trickyRequestMove(obj, 13, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    break;
                }
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
        }
    }
}

void tricky_trackTumbleweed(GameObject* obj, TrickyState* state) {
    int inWater;
    float dx;
    float dz;
    float distance;
    f32 resetTimer;
    float* targetPos;
    GameObject* trackedObj;
    u32 currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (state->substate) {
    case 0:
        newBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        state->scratch700.nib.hi = newBit;
        state->scratch710.ptr = NULL;
        state->substate = 1;
    case 1:
        currentBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        bitIndex = state->scratch700.nib.hi;
        if (bitIndex != currentBit) {
            state->scratch700.nib.hi++;
            **(u8**)state -= 2;
        }
        targetPos = NW_mammoth_getSpawnPosition(state->followObj);
        trackedObj = tumbleweedbush_findNearestActive(targetPos);
        if (trackedObj != 0 && **(u8**)state != 0) {
            if (trackedObj != state->scratch710.obj && (u8*)state->targetPosPtr != (u8*)&state->scratch704) {
                state->targetPosPtr = &state->scratch704.f;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            dx = *targetPos - obj->anim.worldPosX;
            dz = targetPos[2] - obj->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (0.0f != distance) {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = 50.0f;
            state->scratch704.f = -(distance * dx - trackedObj->anim.worldPosX);
            state->scratch708.f = trackedObj->anim.worldPosY;
            state->scratch70C.f = -(distance * dz - trackedObj->anim.worldPosZ);
            if (trickyUpdateMovementState(obj, 5.0f, state) == 0) {
                if (0.0f == state->waterLevel) {
                    inWater = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    inWater = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    inWater = 1;
                } else {
                    inWater = 0;
                }
                if (inWater != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
            }
        } else {
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            resetTimer = 0.0f;
            state->cooldownA = resetTimer;
            state->cooldownB.f = resetTimer;
            TRICKY_CLEAR_RESET_FLAGS(state);
        }
        break;
    }
}

void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state) {
    int inWater;
    int result;

    result = trickyUpdateMovementState(obj, 15.0f, state);
    if (result == 0) {
        if (0.0f == state->waterLevel) {
            inWater = 0;
        } else if (gTrickyEventTimeSentinel == state->eventTime) {
            inWater = 1;
        } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
            inWater = 1;
        } else {
            inWater = 0;
        }
        if (inWater != 0) {
            trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
            state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
            state->particleTimer = 0.0f;
            trickyDebugPrint(sInWaterMessage);
        } else {
            trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
            trickyDebugPrint(sTrickyDryLandDebugMessage);
        }
    }
}

/* Tricky flame/guard AI. Spawns Tricky's flameblast (def 0x4F0) for the
 * fire-breath/guard behaviour. */

#define TRICKY_STATE_HELPERS_ACTIVE_FLAG   0x00000800
#define TRICKY_STATE_HELPERS_FINISHED_FLAG 0x00001000
#define TRICKY_GUARD_HELPER_COUNT          7
#define TRICKY_GUARD_APPROACH_GROUP        3
#define TRICKY_GUARD_HELPER_SETUP_SIZE     0x24
#define TRICKY_GUARD_HELPER_DEF_ID         0x04F0

#define TRICKY_STATE(st) ((TrickyState*)(st))

#define TRICKY_CLEAR_FLAG(st, flag)                                                                                    \
    {                                                                                                                  \
        u32 m;                                                                                                         \
        u32 f2 = TRICKY_STATE(st)->stateFlags;                                                                         \
        m = ~(flag);                                                                                                   \
        TRICKY_STATE(st)->stateFlags = f2 & m;                                                                         \
    }

#define TRICKY_CLEAR_TARGET_DIRTY(st) TRICKY_CLEAR_FLAG(st, TRICKY_STATE_TARGET_DIRTY_FLAG)

#define TRICKY_MARK_HELPERS_FINISHED(st)                                                                               \
    {                                                                                                                  \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_HELPERS_ACTIVE_FLAG);                                                       \
        TRICKY_STATE(st)->stateFlags |= TRICKY_STATE_HELPERS_FINISHED_FLAG;                                            \
    }

#define TRICKY_STATE_CLEAR_RESET_FLAGS(st)                                                                             \
    {                                                                                                                  \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_RESET_FLAG_10);                                                             \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_RESET_FLAG_10000);                                                          \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_RESET_FLAG_20000);                                                          \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_RESET_FLAG_40000);                                                          \
        TRICKY_STATE(st)->commandPhase = -1;                                                                           \
    }

int trickyGuardFindBaddieTarget(TrickyState* state);

static inline int trickyGuardIsBaddieTargetValid(TrickyState* state) {
    GameObject* target = state->guardTarget;
    int count;
    GameObject** objects;
    s16 i;

    objects = (GameObject**)objGetAllOfType(TRICKY_GUARD_APPROACH_GROUP, &count);
    for (i = 0; i < count; i++) {
        if (*objects == target) {
            return 1;
        }
        objects++;
    }
    return 0;
}

static inline void trickyPlayVoice(GameObject* obj, TrickyState* state, u16 sfxId, int volume) {
    s16 move;

    if (state->soundSuppressed) {
        return;
    }
    move = obj->anim.currentMove;
    if (move >= 0x30 || move < 0x29) {
        if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
            objSoundStartTimed(obj, &state->soundState, sfxId, volume, -1, 0);
        }
    }
}

static inline void trickyStopFlameChildren(GameObject* obj, TrickyState* state) {
    state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    {
        int childIndex = 0;
        u8* childState = (u8*)state;

        for (; childIndex < CHILD_OBJECT_COUNT; childState += sizeof(GameObject*), childIndex++) {
            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(childState));
        }
    }
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
    trickyPlayVoice(obj, obj->extra, 0x29d, 0);
}

static inline void trickySpawnFlameChildren(GameObject* obj, TrickyState* state) {
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    {
        int childIndex = 0;
        u8* childState = (u8*)state;

        for (; childIndex < CHILD_OBJECT_COUNT; childState += sizeof(GameObject*), childIndex++) {
            FlameblastPlacement* setup =
                (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_CHILD_OBJ_FLAMEBLAST);

            setup->base.color[0] = 2;
            setup->base.color[1] = 1;
            setup->streamIndex = childIndex;
            TRICKY_FLAME_CHILD_FROM_STATE_BASE(childState) =
                objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        }
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
    Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
}

typedef enum TrickyGuardState {
    TRICKY_GUARD_INIT = 0,
    TRICKY_GUARD_FINDING = 1,
    TRICKY_GUARD_TO_SPOT = 2,
    TRICKY_GUARD_TO_FRONT = 3,
    TRICKY_GUARD_TO_BADDIE = 4,
    TRICKY_GUARD_FLAME = 5,
    TRICKY_GUARD_DOWN_TO_GROWL = 6,
    TRICKY_GUARD_GROWL = 7,
    TRICKY_GUARD_UP_FROM_GROWL = 8,
} TrickyGuardState;

char sTrickyGuardDebugTextBlock[] = {
    0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x49, 0x4E, 0x49, 0x54, 0x0A, 0x00, 0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x46,
    0x49, 0x4E, 0x44, 0x49, 0x4E, 0x47, 0x0A, 0x00, 0x00, 0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x54, 0x4F, 0x53, 0x50,
    0x4F, 0x54, 0x0A, 0x00, 0x00, 0x00, 0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x54, 0x4F, 0x46, 0x52, 0x4F, 0x4E, 0x54,
    0x0A, 0x00, 0x00, 0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x54, 0x4F, 0x42, 0x41, 0x44, 0x44, 0x49, 0x45, 0x0A, 0x00,
    0x47, 0x55, 0x41, 0x52, 0x44, 0x5F, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x47, 0x55, 0x41,
    0x52, 0x44, 0x5F, 0x44, 0x4F, 0x57, 0x4E, 0x54, 0x4F, 0x47, 0x52, 0x4F, 0x57, 0x4C, 0x0A, 0x00, 0x00, 0x47, 0x55,
    0x41, 0x52, 0x44, 0x5F, 0x47, 0x52, 0x4F, 0x57, 0x4C, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x47, 0x55, 0x41, 0x52, 0x44,
    0x5F, 0x55, 0x50, 0x46, 0x52, 0x4F, 0x4D, 0x47, 0x52, 0x4F, 0x57, 0x4C, 0x0A, 0x00, 0x00,
};

void trickyGuard(GameObject* obj, TrickyState* trickyState) {
    char* strBase = gTrickyDebugStringTable;
    int i;
    TrickyState* flameSoundState;
    TrickyState* growlSoundState;
    TrickyState* randomSoundState;
    void** slot;
    void** slot2;
    int i2;
    FlameblastPlacement* setup;
    f32* newTarget;

    switch (trickyState->substate) {
    case TRICKY_GUARD_INIT:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_INIT);
        trickyState->guardWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosPtr, 0x0);
        trickyState->guardPoint[0] =
            (f32)(trickyState->followObj->anim.worldPosX -
                  15.0f * mathSinf((TRICKY_PI * trickyState->followObj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS));
        trickyState->guardPoint[1] = trickyState->followObj->anim.worldPosY;
        trickyState->guardPoint[2] =
            (f32)(trickyState->followObj->anim.worldPosZ -
                  15.0f * mathCosf((TRICKY_PI * trickyState->followObj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS));
        trickyState->guardCanSpawnHelpers = 0;
        trickyState->substate = TRICKY_GUARD_FINDING;
        break;
    case TRICKY_GUARD_FINDING:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_FINDING);
        trickyUpdateMovementState(obj, 5.0f, trickyState);
        if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0x0)) {
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
        }
        break;
    case TRICKY_GUARD_TO_SPOT:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_TOSPOT);
        if (trickyUpdateMovementState(obj, 5.0f, trickyState) == 0) {
            if (trickyState->targetPosPtr != trickyState->guardPoint) {
                trickyState->targetPosPtr = trickyState->guardPoint;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                trickyState->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_GUARD_TO_FRONT;
        } else {
            trickyGuardFindBaddieTarget(trickyState);
            break;
        }
    case TRICKY_GUARD_TO_FRONT:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_TOFRONT);
        if (trickyUpdateMovementState(obj, 5.0f, trickyState) == 0) {
            if (skeetla_isInWater(trickyState) != 0) {
                trickyRequestMove(obj, 0x8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                (trickyState)->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                (trickyState)->particleTimer = 0.0f;
                trickyDebugPrint(strBase + TRICKY_DBG_IN_WATER);
            } else {
                trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(strBase + TRICKY_DBG_OUT_OF_WATER);
            }
        }
        trickyGuardFindBaddieTarget(trickyState);
        break;
    case TRICKY_GUARD_TO_BADDIE:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_TOBADDIE);
        if (trickyUpdateMovementState(obj, 15.0f, trickyState) == 0) {
            trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_RESET_FLAG_10;
            if (*trickyState->progressPtr != 0 && trickyState->guardCanSpawnHelpers != 0) {
                if ((u8)Obj_IsLoadingLocked() != 0) {
                    trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                    for (i = 0, slot = (void**)trickyState; i < TRICKY_GUARD_HELPER_COUNT; i++) {
                        setup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                           TRICKY_GUARD_HELPER_DEF_ID);
                        setup->base.color[0] = 2;
                        setup->base.color[1] = 1;
                        setup->streamIndex = i;
                        TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot) =
                            (void*)objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        slot++;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                    Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                }
                (*trickyState->progressPtr)--;
                trickyRequestMove(obj, 0x34, TRICKY_LAND_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                trickyState->substate = TRICKY_GUARD_FLAME;
            } else {
                trickyRequestMove(obj, 0x32, 0.01f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                trickyState->substate = TRICKY_GUARD_DOWN_TO_GROWL;
            }
        } else {
            if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosPtr, 0x0)) {
                break;
            }
            newTarget = &trickyState->followObj->anim.worldPosX;
            if (trickyState->targetPosPtr != newTarget) {
                trickyState->targetPosPtr = newTarget;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                trickyState->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
            break;
        }
    case TRICKY_GUARD_FLAME:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_FLAME);
        if (obj->anim.currentMoveProgress >= 0.95f) {
            TRICKY_MARK_HELPERS_FINISHED(trickyState);
            for (i2 = 0, slot2 = (void**)trickyState; i2 < TRICKY_GUARD_HELPER_COUNT; i2++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot2));
                slot2++;
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            flameSoundState = obj->extra;
            if (!flameSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= 0x30 || move < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &flameSoundState->soundState, 0x29d, 0, -1, 0);
                    }
                }
            }
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                newTarget = &trickyState->followObj->anim.worldPosX;
                if (trickyState->targetPosPtr != newTarget) {
                    trickyState->targetPosPtr = newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                    trickyState->linkedWalkGroup = 0;
                }
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        } else if (trickyGuardIsBaddieTargetValid(trickyState) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_DOWN_TO_GROWL:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_DOWNTOGROWL);
        if (obj->anim.currentMoveProgress >= 0.95f) {
            trickyRequestMove(obj, 0x33, TRICKY_LAND_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->guardTimer = 0.0f;
            growlSoundState = obj->extra;
            if (!growlSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= 0x30 || move < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &growlSoundState->soundState, 0x299, 0x100, -1, 0);
                    }
                }
            }
            trickyState->substate = TRICKY_GUARD_GROWL;
        } else if (trickyGuardIsBaddieTargetValid(trickyState) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_GROWL:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_GROWL);
        if (randomGetRange(0, 10) == 0) {
            randomSoundState = obj->extra;
            if (!randomSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= 0x30 || move < 0x29) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &randomSoundState->soundState, 0x299, 0x100, -1, 0);
                    }
                }
            }
        }
        trickyState->guardTimer = trickyState->guardTimer + timeDelta;
        if ((trickyState->guardTimer >= 150.0f &&
             getXZDistanceSquared(trickyState->targetPosPtr, &obj->anim.worldPosX) >= 2500.0f) ||
            trickyGuardIsBaddieTargetValid(trickyState) == 0) {
            trickyRequestMove(obj, 0x32, -0.01f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->substate = TRICKY_GUARD_UP_FROM_GROWL;
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_UP_FROM_GROWL:
        trickyDebugPrint(strBase + TRICKY_DBG_GUARD_UPFROMGROWL);
        if (obj->anim.currentMoveProgress <= gTrickySmallSpeedStep) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_RESET_FLAG_10;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                newTarget = &trickyState->followObj->anim.worldPosX;
                if (trickyState->targetPosPtr != newTarget) {
                    trickyState->targetPosPtr = newTarget;
                    TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                    trickyState->linkedWalkGroup = 0;
                }
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        }
        break;
    }
}

int trickyGuardFindBaddieTarget(TrickyState* trickyState) {
    int count;
    f32 d;
    f32 bestDist;
    GameObject** objectCursor;
    s16 i;
    GameObject** groupObjects;
    GameObject* best = NULL;

    groupObjects = (GameObject**)objGetAllOfType(TRICKY_GUARD_APPROACH_GROUP, &count);
    i = 0;
    objectCursor = groupObjects;
    for (; i < count; i++) {
        d = getXZDistanceSquared(&(*objectCursor)->anim.worldPosX, trickyState->guardPoint);
        if (best == NULL) {
            if (trickyState->guardWalkGroup ==
                Objfsa_GetWalkGroupIndexAtPoint(&(*objectCursor)->anim.worldPosX, NULL)) {
                bestDist = d;
                best = *objectCursor;
            }
        } else if (d < bestDist) {
            if (trickyState->guardWalkGroup ==
                Objfsa_GetWalkGroupIndexAtPoint(&(*objectCursor)->anim.worldPosX, NULL)) {
                bestDist = d;
                best = *objectCursor;
            }
        }
        objectCursor++;
    }
    if (best != NULL) {
        trickyState->guardTarget = best;
        if (trickyState->targetPosPtr != &best->anim.worldPosX) {
            trickyState->targetPosPtr = &best->anim.worldPosX;
            TRICKY_CLEAR_TARGET_DIRTY(trickyState);
            trickyState->linkedWalkGroup = 0;
        }
        trickyState->substate = 4;
        return 1;
    }
    return 0;
}

typedef enum TrickyFlameState {
    TRICKY_FLAME_NONE = 0,
    TRICKY_FLAME_FINDING_IN = 1,
    TRICKY_FLAME_TURNING_IN = 2,
    TRICKY_FLAME_FINDING_OUT = 3,
    TRICKY_FLAME_GOING_TO_EDGE = 4,
    TRICKY_FLAME_TO_START = 5,
    TRICKY_FLAME_IN = 6,
    TRICKY_FLAME_OUT = 7,
    TRICKY_FLAME_TO_END = 8,
} TrickyFlameState;

char sTrickyFlameDebugTextBlock[] = {
    0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x4E, 0x4F, 0x4E, 0x45, 0x0A, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x46,
    0x49, 0x4E, 0x44, 0x49, 0x4E, 0x47, 0x5F, 0x4F, 0x55, 0x54, 0x0A, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F,
    0x47, 0x4F, 0x49, 0x4E, 0x47, 0x54, 0x4F, 0x45, 0x44, 0x47, 0x45, 0x0A, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45,
    0x5F, 0x54, 0x4F, 0x53, 0x54, 0x41, 0x52, 0x54, 0x0A, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x4F, 0x55,
    0x54, 0x0A, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x46, 0x49, 0x4E, 0x44, 0x49, 0x4E, 0x47, 0x5F, 0x49,
    0x4E, 0x0A, 0x00, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x54, 0x55, 0x52, 0x4E, 0x49, 0x4E, 0x47, 0x5F,
    0x49, 0x4E, 0x0A, 0x00, 0x00, 0x00, 0x46, 0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x49, 0x4E, 0x0A, 0x00, 0x00, 0x00, 0x46,
    0x4C, 0x41, 0x4D, 0x45, 0x5F, 0x54, 0x4F, 0x45, 0x4E, 0x44, 0x0A, 0x00, 0x00, 0x00, 0x00,
};

void trickyFlame(GameObject* obj, TrickyState* trickyState) {
    char* strBase = gTrickyDebugStringTable;
    void** slot;
    int i;
    void** slot2;
    int i2;
    FlameblastPlacement* setup;
    int dieFlag;
    f32* target;
    f32 fz;

    switch (trickyState->substate) {
    case TRICKY_FLAME_NONE:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_NONE);
        trickyState->flameNode0 = Objfsa_FindNearestCurveType24(&trickyState->followObj->anim.worldPosX, -1, 4);
        if (trickyState->flameNode0->walkGroup != 0) {
            target = &trickyState->flameNode0->x;
            if (trickyState->targetPosPtr != target) {
                trickyState->targetPosPtr = target;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                (trickyState)->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_FLAME_FINDING_IN;
        } else {
            trickyState->flameNode1 = (*gRomCurveInterface)->getById(trickyState->flameNode0->linkIds[0]);
            target = &trickyState->flameNode1->x;
            if (trickyState->targetPosPtr != target) {
                trickyState->targetPosPtr = target;
                TRICKY_CLEAR_TARGET_DIRTY(trickyState);
                (trickyState)->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_FLAME_FINDING_OUT;
        }
        trickyUpdateMovementState(obj, 5.0f, trickyState);
        break;
    case TRICKY_FLAME_FINDING_OUT:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_FINDING_OUT);
        trickyUpdateMovementState(obj, 5.0f, trickyState);
        if ((u8)trickyState->flameNode1->walkGroup == Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL)) {
            trickyState->movementState = TRICKY_MOVE_WALK_FREE;
            trickyState->substate = TRICKY_FLAME_GOING_TO_EDGE;
        }
        break;
    case TRICKY_FLAME_GOING_TO_EDGE:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_GOINGTOEDGE);
        target = &trickyState->flameNode0->x;
        trickyUpdateApproachSpeed(obj, 5.0f, trickyState, target, 1);
        moveTricky(obj, target);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
            trickyState->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
            trickyState->substate = TRICKY_FLAME_TO_START;
        }
        break;
    case TRICKY_FLAME_TO_START:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_TOSTART);
        target = &trickyState->flameNode0->x;
        trickyUpdateApproachSpeed(obj, 5.0f, trickyState, target, 1);
        if (moveTricky(obj, target) != 0) {
            break;
        }
        trickyRequestMove(obj, 0x1a, 0.004f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        trickyState->substate = TRICKY_FLAME_OUT;
        *trickyState->progressPtr -= 4;
        /* fall through */
    case TRICKY_FLAME_OUT:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_OUT);
        {
            s16 srcAng = (s16)(trickyState->flameNode0->yaw << 8);
            s16 delta = (s16)(srcAng - (u16) * (s16*)obj);
            int absDelta;
            if (delta > 0x8000) {
                delta = (s16)(delta - 0xFFFF);
            }
            if (delta < -0x8000) {
                delta = (s16)(delta + 0xFFFF);
            }
            absDelta = delta;
            absDelta = (absDelta >= 0) ? absDelta : -absDelta;
            if (absDelta >= 0x4000) {
                srcAng = (s16)(srcAng + 0x8000);
            }
            trickyTurnTowardYaw(obj, srcAng);
        }
        do {
            if (obj->anim.currentMoveProgress > 0.25f) {
                if ((trickyState->stateFlags & TRICKY_STATE_HELPERS_ACTIVE_FLAG) == 0) {
                    if ((u8)Obj_IsLoadingLocked() != 0) {
                        trickyState->stateFlags |= TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                        for (i = 0, slot = (void**)trickyState; i < TRICKY_GUARD_HELPER_COUNT; i++) {
                            setup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                               TRICKY_GUARD_HELPER_DEF_ID);
                            setup->base.color[0] = 2;
                            setup->base.color[1] = 1;
                            setup->streamIndex = i;
                            TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot) =
                                (void*)objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            slot++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > 0.8f) {
                        TRICKY_MARK_HELPERS_FINISHED(trickyState);
                        for (i = 0, slot = (void**)trickyState; i < TRICKY_GUARD_HELPER_COUNT; i++) {
                            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot));
                            slot++;
                        }
                        Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                        i = (int)obj->extra;
                        if (((TrickyState*)i)->soundSuppressed == 0) {
                            s16 a0 = obj->anim.currentMove;
                            if (a0 >= 0x30 || a0 < 0x29) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)i)->soundState, 0x29d, 0, -1, 0);
                                }
                            }
                        }
                        dieFlag = 0;
                        break;
                    }
                }
            }
            dieFlag = 1;
        } while (0);
        if (dieFlag == 0) {
            trickyState->substate = TRICKY_FLAME_TO_END;
            (trickyState)->guardTimer = 60.0f;
        }
        break;
    case TRICKY_FLAME_FINDING_IN:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_FINDING_IN);
        {
            int r = trickyUpdateMovementState(obj, 5.0f, trickyState);
            if (r == 0) {
                trickyState->stateFlags |= TRICKY_STATE_RESET_FLAG_10;
                trickyState->substate = TRICKY_FLAME_TURNING_IN;
            } else if (r == 2) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                fz = 0.0f;
                trickyState->guardPoint[0] = fz;
                trickyState->guardPoint[1] = fz;
                TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
            }
        }
        break;
    case TRICKY_FLAME_TURNING_IN:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_TURNING_IN);
        target = &trickyState->followObj->anim.worldPosX;
        trickyUpdateApproachSpeed(obj, gTrickyMaxDistance, trickyState, target, 1);
        if (moveTricky(obj, target) == 0) {
            trickyRequestMove(obj, 0x1a, 0.004f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->substate = TRICKY_FLAME_IN;
            *trickyState->progressPtr -= 4;
        }
        break;
    case TRICKY_FLAME_IN:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_IN);
        do {
            if (obj->anim.currentMoveProgress > 0.25f) {
                if ((trickyState->stateFlags & TRICKY_STATE_HELPERS_ACTIVE_FLAG) == 0) {
                    if ((u8)Obj_IsLoadingLocked() != 0) {
                        trickyState->stateFlags |= TRICKY_STATE_HELPERS_ACTIVE_FLAG;
                        for (i = 0, slot = (void**)trickyState; i < TRICKY_GUARD_HELPER_COUNT; i++) {
                            setup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                               TRICKY_GUARD_HELPER_DEF_ID);
                            setup->base.color[0] = 2;
                            setup->base.color[1] = 1;
                            setup->streamIndex = i;
                            TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot) =
                                (void*)objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            slot++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > 0.8f) {
                        TRICKY_MARK_HELPERS_FINISHED(trickyState);
                        for (i2 = 0, slot2 = (void**)trickyState; i2 < TRICKY_GUARD_HELPER_COUNT; i2++) {
                            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(slot2));
                            slot2++;
                        }
                        Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                        slot = (void**)obj->extra;
                        if (((TrickyState*)slot)->soundSuppressed == 0) {
                            s16 a0 = obj->anim.currentMove;
                            if (a0 >= 0x30 || a0 < 0x29) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)slot)->soundState, 0x29d, 0, -1, 0);
                                }
                            }
                        }
                        dieFlag = 0;
                        break;
                    }
                }
            }
            dieFlag = 1;
        } while (0);
        if (dieFlag == 0) {
            trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            trickyState->substate = TRICKY_FLAME_NONE;
            fz = 0.0f;
            trickyState->guardPoint[0] = fz;
            trickyState->guardPoint[1] = fz;
            TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
        }
        break;
    case TRICKY_FLAME_TO_END:
        trickyDebugPrint(strBase + TRICKY_DBG_FLAME_TOEND);
        trickyState->guardTimer -= timeDelta;
        if (trickyState->guardTimer <= 0.0f) {
            target = &trickyState->flameNode1->x;
            trickyUpdateApproachSpeed(obj, 5.0f, trickyState, target, 1);
            moveTricky(obj, target);
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                fz = 0.0f;
                trickyState->guardPoint[0] = fz;
                trickyState->guardPoint[1] = fz;
                TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
            }
        }
        break;
    }
}
void tricky_state06_nop(void) {
}

/*
 * Tricky rom-curve route walker. tricky_updateBallRoll is the per-frame
 * update that rolls the object along its rom-curve route.
 *
 * Before init (init-done byte 0x0a == 0): the ball homes onto its curve
 * (CANNONBALL_CURVE). Once the owner and the ball share a walk group it
 * picks the route direction by comparing owner-to-endpoint distances,
 * binds the route walker to the chosen segment, steps it, seeds the sfx
 * timer and marks init done.
 *
 * After init: at each segment end it gathers the valid branch nodes
 * (gated by the node-set's per-branch mask byte), picks the nearest to
 * the current owner, retargets the walker, then accelerates/decays the
 * roll speed toward CANNONBALL_SFX_TIMER limits, advances and moves the
 * ball. Off the walk grid it sets CANNONBALL_HIDE_FLAG. The sfx timer
 * periodically plays the rolling sound (0x29b) on object channel 0x10
 * when the current move is outside the 0x29..0x2f window.
 */

/* The "ball" is the Tricky cannonball's TrickyState extra block: substate is
 * the init-done byte, speed the roll speed, stateFlags the flag word, route the
 * embedded RomCurveWalker, followObj/playerObj the owner links, scratch700 the
 * curve link and scratch708 the rolling-sfx countdown. */
#define CANNONBALL_HIDE_FLAG        0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000

/* lbl_803E2*: this DLL's f32 route/speed constants. */

void tricky_updateBallRoll(GameObject* obj, TrickyState* ball) {
    RomCurveDef* toNode;
    u8 nodeCount = 0;
    int node;
    RomCurveDef* nodeSet;
    s32* link;
    u32 mask;
    int bit;
    int i;
    RomCurveDef* curve;
    RomCurveDef* fromNode;
    s32 nodeIds[4];
    RomCurveDef* curveArg;
    RomCurveDef* candidateNode;
    RomCurveDef* targetNode;
    int walkGroup;
    f32 speed;
    f64 distance;
    f64 bestDistance;

    if (ball->substate != 0) {
        if (ball->route.reverse == 0) {
            if (ball->route.atSegmentEnd != 0) {
                nodeSet = (RomCurveDef*)ball->route.nodeA4;
                mask = 1;
                link = nodeSet->linkIds;
                for (bit = 0; bit < 4; bit++) {
                    node = *link++;
                    if (node > -1 && ((nodeSet->blockedLinkMask & mask) == 0)) {
                        nodeIds[nodeCount++] = node;
                    }
                    mask <<= 1;
                }
            }
        } else if (ball->route.atSegmentEnd == 0) {
            int node2;
            RomCurveDef* nodeSet2;
            s32* link2;
            u32 mask2;
            nodeSet2 = (RomCurveDef*)ball->route.nodeA4;
            mask2 = 1;
            link2 = nodeSet2->linkIds;
            for (bit = 0; bit < 4; bit++) {
                node2 = *link2++;
                if (node2 > -1 && ((nodeSet2->blockedLinkMask & mask2) != 0)) {
                    nodeIds[nodeCount++] = node2;
                }
                mask2 <<= 1;
            }
        }

        if (nodeCount != 0) {
            targetNode = (*gRomCurveInterface)->getById(nodeIds[0]);
            bestDistance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &targetNode->x);

            for (i = 1, link = &nodeIds[1]; i < nodeCount; i++) {
                candidateNode = (*gRomCurveInterface)->getById(*link);
                distance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &candidateNode->x);
                if (distance < bestDistance) {
                    targetNode = candidateNode;
                    bestDistance = distance;
                }
                link++;
            }

            RomCurve_advanceToNextSegment(&ball->route, targetNode);
        }

        speed = ball->speed;
        if ((u8)(ball->stateFlags & CANNONBALL_SPEED_DECAY_FLAG) != 0) {
            speed += -0.01f * timeDelta;
            if (speed < 0.0f) {
                speed = 0.0f;
            }
        } else if (speed > 1.2f) {
            speed += gTrickySpeedDecayStep * timeDelta;
            if (speed < 1.2f) {
                speed = 1.2f;
            }
        } else {
            speed += gTrickySmallSpeedStep * timeDelta;
            if (speed > 1.2f) {
                speed = 1.2f;
            }
        }

        ball->speed = speed;
        trickyAdvanceRouteTargetAhead(obj, &ball->route, ball->speed);
        moveTricky(obj, &ball->route.posX);

        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
            ball->stateFlags &= ~(u64)CANNONBALL_HIDE_FLAG;
        } else {
            ball->stateFlags |= CANNONBALL_HIDE_FLAG;
        }

        ball->scratch708.f -= timeDelta;
        if (ball->scratch708.f < 0.0f) {
            ball->scratch708.f = (f32)(int)randomGetRange(200, 600);
            trickyPlayVoice(obj, obj->extra, 0x29b, 0x1000);
        }
    } else {
        trickyUpdateMovementState(obj, 5.0f, ball);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) ==
            (walkGroup = Objfsa_GetWalkGroupIndexAtPoint(&ball->scratch700.curve->x, NULL))) {
            curve = ball->scratch700.curve;

            fromNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(curve, 0));
            toNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(curve, 0));

            bestDistance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &fromNode->x);
            distance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &toNode->x);

            curveArg = curve;
            if (bestDistance > distance) {
                targetNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(fromNode, 0));
                ball->route.reverse = 0;
            } else {
                fromNode = toNode;
                targetNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(toNode, 0));
                ball->route.reverse = 1;
            }

            RomCurve_setupHermiteSegment(&ball->route, curveArg, fromNode, targetNode);
            if (ball->route.reverse != 0) {
                RomCurve_stepClamped(&ball->route, -10.0f);
            } else {
                RomCurve_stepClamped(&ball->route, 10.0f);
            }

            ball->scratch708.f = 0.0f;
            ball->substate = 1;
        }
    }
}

void tricky_state04_nop(void) {
}

/*
 * Tricky companion behaviour states (part of the tricky DLL, 0x00C4).
 *
 * Each function here is one entry of Tricky's per-frame substate machine,
 * dispatched off TrickyState::substate either directly or through the
 * function-pointer table walked in tricky_stateFollowPlayer. They drive Tricky along ROM
 * curve paths (rom_curve_interface), follow/feed the player, run the dig
 * and flame-breath sequences, pick random idle moves and emit the matching
 * object sounds (audio/sfx). tricky_handleFeedOrTalk handles the shared
 * feeding/Y-button-item interaction and is called as a guard at the top of
 * most states. Water-vs-land animation selection (the repeated
 * waterLevel/unk2B0/unk2B4 ladder) chooses swim vs walk anims throughout.
 */

/* GameCube controller button mask */
#define PAD_BUTTON_A 0x100

/* child objects spawned by this TU (retail OBJECTS.bin names) */
#define TRICKY_CHILD_OBJ_FOOD 0x17b /* "TrickyFood" */

/*
 * A ROM/FSA walk-curve node as Tricky's tunnel/follow states see it (via the
 * rom_curve_interface getById() / Objfsa_*Curve* lookups). Byte-compatible with
 * the shared RomCurveDef, but with the walk-group id at +3 that those states
 * key off (which RomCurveDef leaves in its pad).
 */
void tricky_handlePlayerContact(GameObject* obj, TrickyState* state);
const TrickyItemIdList gTrickyCmdQueryInit = {{0, 1, 3, 4, 5}};
const TrickyItemIdList gTrickyFoodItemIds = {{0, 1, 3, 4, 5}};

static inline void trickyPlayWhineSfx(u32 id, GameObject* obj) {
    TrickyState* sfxState = obj->extra;
    if (sfxState->soundSuppressed == 0 && (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
        Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
        objSoundStartTimed(obj, &sfxState->soundState, id, 0x500, -1, 0);
    }
}

static inline void trickyAdvanceNode(TrickyState* state) {
    int idx;
    u8* linkNode;
    int linkId;
    int off;
    int k;
    idx = 0;
    off = 0;
    for (k = 4; k != 0; k--) {
        linkNode = state->scratch704.ptr;
        linkId = TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(linkNode, off);
        if (linkId > -1 && linkId != ((RomCurveDef*)state->scratch700.ptr)->id) {
            state->scratch700.ptr = linkNode;
            state->scratch704.ptr =
                (u8*)(*gRomCurveInterface)->getById(TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(state->scratch704.ptr, idx));
            break;
        }
        off += 4;
        idx++;
    }
}

char sTrickyDigTunnelDebugTextBlock[] = {
    0x44, 0x49, 0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45, 0x4C, 0x5F, 0x46, 0x49, 0x4E, 0x44, 0x49, 0x4E, 0x47, 0x0A,
    0x00, 0x00, 0x44, 0x49, 0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45, 0x4C, 0x5F, 0x47, 0x4F, 0x49, 0x4E, 0x47, 0x54,
    0x4F, 0x53, 0x54, 0x41, 0x52, 0x54, 0x0A, 0x00, 0x44, 0x49, 0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45, 0x4C, 0x5F,
    0x44, 0x49, 0x47, 0x47, 0x49, 0x4E, 0x47, 0x0A, 0x00, 0x00, 0x44, 0x49, 0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45,
    0x4C, 0x5F, 0x54, 0x4F, 0x45, 0x4E, 0x44, 0x31, 0x20, 0x25, 0x66, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x44, 0x49,
    0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45, 0x4C, 0x5F, 0x54, 0x4F, 0x45, 0x4E, 0x44, 0x32, 0x0A, 0x00, 0x00, 0x00,
    0x44, 0x49, 0x47, 0x54, 0x55, 0x4E, 0x4E, 0x45, 0x4C, 0x5F, 0x57, 0x41, 0x49, 0x54, 0x0A, 0x00,
};

void trickyDigTunnel(GameObject* obj, TrickyState* state) {
    u32 sfxTable;
    u8* base;
    RomCurveDef* pc;
    u8* pos;
    u8* ptr;
    int gidx;
    int inWater;
    u16 id;
    f32 vz, vx, spd, z, vxx;

    base = (u8*)gTrickyDebugStringTable;
    sfxTable = *(u32*)gTrickySubstateSfxIdPairB;
    switch (state->substate) {
    case 0:
        pc = Objfsa_FindNearestCurveType24(state->targetPosPtr, -1, 2);
        state->scratch708.ptr = (u8*)(*gRomCurveInterface)->getById(pc->linkIds[0]);
        state->scratch700.ptr = pc;
        state->scratch704.ptr = (u8*)(*gRomCurveInterface)->getById(pc->linkIds[1]);
        if (((RomCurveDef*)state->scratch704.ptr)->walkGroup != 0) {
            *(u32*)&state->scratch704.ptr = state->scratch704.u ^ state->scratch708.u;
            state->scratch708.u = state->scratch708.u ^ state->scratch704.u;
            *(u32*)&state->scratch704.ptr = state->scratch704.u ^ state->scratch708.u;
        }
        ptr = (u8*)&((RomCurveDef*)state->scratch708.ptr)->x;
        if (state->targetPosPtr != (f32*)ptr) {
            state->targetPosPtr = (f32*)ptr;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~0x400;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 1;
    case 1:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_FINDING));
        trickyUpdateMovementState(obj, 5.0f, state);
        gidx = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
        if (((RomCurveDef*)state->scratch708.ptr)->walkGroup == gidx) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
            state->substate = 2;
        }
        break;
    case 2:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_GOINGTOSTART));
        pos = (u8*)&((RomCurveDef*)state->scratch700.ptr)->x;
        trickyUpdateApproachSpeed(obj, 5.0f, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            state->stateFlags |= 0x2010;
            state->substate = 3;
        } else {
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
                state->stateFlags |= 0x2010;
            }
        }
        break;
    case 3:
        trickyRequestMove(obj, 0xe, 0.033f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        state->dirX = ((RomCurveDef*)state->scratch704.ptr)->x - ((RomCurveDef*)state->scratch700.ptr)->x;
        state->dirZ = ((RomCurveDef*)state->scratch704.ptr)->z - ((RomCurveDef*)state->scratch700.ptr)->z;
        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
        state->scratch70C.f = (f32)(int)randomGetRange(0x14, 0xb4);
        state->substate = 4;
    case 4:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_DIGGING));
        state->scratch70C.f -= timeDelta;
        if (state->scratch70C.f <= 0.0f) {
            state->scratch70C.f = (f32)(int)randomGetRange(0x14, 0xb4);
            state->scratch70C.f *= 100.0f;
            ptr = obj->extra;
            if (((TrickyState*)ptr)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)ptr)->soundState, 0x360, 0x500, -1, 0);
            }
        }
        spd = GROUND_ANIMATOR_INTERFACE(state->followObj)->applyPress(state->followObj, obj);
        obj->anim.localPosX = state->dirX * spd + ((RomCurveDef*)state->scratch700.ptr)->x;
        obj->anim.localPosZ = state->dirZ * spd + ((RomCurveDef*)state->scratch700.ptr)->z;
        vx = ((TrickyState*)obj->extra)->dirX;
        vxx = vx * vx;
        vz = ((TrickyState*)obj->extra)->dirZ;
        spd = vz * vz;
        if (vxx + spd > 0.01f) {
            trickyTurnTowardYaw(obj, getAngle(-vx, -vz));
        }
        if (GROUND_ANIMATOR_INTERFACE(state->followObj)->isFullySunk(state->followObj) != 0) {
            {
                int off;
                int linkId;
                u8* linkNode;
                int idx;
                int k;

                idx = 0;
                off = 0;
                for (k = 4; k != 0; k--) {
                    linkNode = state->scratch704.ptr;
                    linkId = TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(linkNode, off);
                    if (linkId > -1 && linkId != ((RomCurveDef*)state->scratch700.ptr)->id) {
                        state->scratch700.ptr = linkNode;
                        state->scratch704.ptr =
                            (u8*)(*gRomCurveInterface)
                                ->getById(TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(state->scratch704.ptr, idx));
                        break;
                    }
                    off += 4;
                    idx++;
                }
            }
            **(u8**)state -= 4;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->substate = 5;
            id = *(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2);
            ptr = obj->extra;
            if (((TrickyState*)ptr)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)ptr)->soundState, id, 0x500, -1, 0);
            }
        }
        break;
    case 5:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_TOEND1),
                         Vec_xzDistance(&obj->anim.worldPosX, &((RomCurveDef*)state->scratch704.ptr)->x));
        pos = (u8*)&((RomCurveDef*)state->scratch704.ptr)->x;
        trickyUpdateApproachSpeed(obj, 5.0f, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            trickyAdvanceNode(state);
            state->substate = 6;
        }
        break;
    case 6:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_TOEND2));
        pos = (u8*)&((RomCurveDef*)state->scratch704.ptr)->x;
        trickyUpdateApproachSpeed(obj, 5.0f, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            if (0.0f == state->waterLevel) {
                inWater = 0;
            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                inWater = 1;
            } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                inWater = 1;
            } else {
                inWater = 0;
            }
            if (inWater != 0) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint((char*)(base + TRICKY_DBG_IN_WATER));
            } else {
                trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint((char*)(base + TRICKY_DBG_OUT_OF_WATER));
            }
            state->stateFlags &= ~0x2010;
            state->substate = 7;
        }
        break;
    case 7:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_WAIT));
        gidx = Objfsa_GetWalkGroupIndexAtPoint(&state->playerObj->anim.worldPosX, NULL);
        {
            int currentGroup;

            currentGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
            if (currentGroup == gidx) {
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                z = 0.0f;
                state->cooldownA = z;
                state->cooldownB.f = z;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                {
                    s8 mm;
                    mm = -1;
                    state->commandPhase = mm;
                }
            }
        }
        break;
    }
}

void tricky_stateFindSecretDig(GameObject* obj, TrickyState* state) {
    u32 sfxTable;
    u8* ptr;
    GameObject* pc;
    int ret;
    f32 spd;
    f32 dist;
    f32 z;

    sfxTable = *(u32*)gTrickySubstateSfxIdPairA;
    pc = state->followObj;
    switch (state->substate) {
    case 0:
        state->scratch70C.ptr = Objfsa_FindNearestEnabledCurveType24(&state->followObj->anim.worldPosX, -1, 2);
        if (state->scratch70C.ptr != NULL &&
            getXZDistanceSquared(&state->followObj->anim.worldPosX, &((RomCurveDef*)state->scratch70C.ptr)->x) >
                10000.0f) {
            state->scratch70C.ptr = NULL;
        }
        state->substate = 1;
    case 1:
        ret = trickyUpdateMovementState(obj, 5.0f, state);
        if (ret == 0) {
            if (state->scratch70C.ptr != NULL) {
                state->substate = 2;
                ptr = (u8*)&((RomCurveDef*)state->scratch70C.ptr)->x;
                if (state->targetPosPtr != (f32*)ptr) {
                    state->targetPosPtr = (f32*)ptr;
                    {
                        u32 mask;
                        u32 flags = state->stateFlags;
                        mask = ~0x400;
                        state->stateFlags = flags & mask;
                    }
                    state->linkedWalkGroup = 0;
                }
            } else {
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->substate = 3;
                state->scratch700.f = 0.0f;
                state->scratch710.f = (f32)(int)randomGetRange(0x28, 0x50);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
                trickyRequestMove(obj, 0xe, 0.033f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            }
        } else if (ret == 2) {
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            z = 0.0f;
            state->cooldownA = z;
            state->cooldownB.f = z;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm;
                mm = -1;
                state->commandPhase = mm;
            }
        }
        break;
    case 2:
        if (trickyUpdateMovementState(obj, gTrickyMaxDistance, state) == 0) {
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = 3;
            state->scratch700.f = 0.0f;
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
            trickyRequestMove(obj, 0xe, 0.033f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        }
        break;
    case 3:
        state->scratch700.f += timeDelta;
        state->scratch710.f -= timeDelta;
        if (state->scratch700.f >= 60.0f) {
            state->substate = 4;
            state->scratch704.f = obj->anim.worldPosX;
            state->scratch708.f = obj->anim.worldPosZ;
            ptr = state->scratch70C.ptr;
            if (ptr != NULL) {
                pc = state->followObj;
                state->dirX = ((RomCurveDef*)ptr)->x - pc->anim.worldPosX;
                state->dirZ = ((RomCurveDef*)ptr)->z - pc->anim.worldPosZ;
                dist = sqrtf(state->dirX * state->dirX + state->dirZ * state->dirZ);
                if (0.0f != dist) {
                    state->dirX = state->dirX / dist;
                    state->dirZ = state->dirZ / dist;
                }
            }
        }
        break;
    case 4:
        state->scratch710.f -= timeDelta;
        if (state->scratch710.f <= 0.0f) {
            state->scratch710.f = (f32)(int)randomGetRange(0x28, 0x50);
            state->scratch710.f *= 100.0f;
            trickyPlayWhineSfx(0x360, obj);
        }
        spd = GROUND_ANIMATOR_INTERFACE(pc)->applyPress((GameObject*)pc, obj);
        obj->anim.localPosX = state->scratch704.f - state->dirX * spd;
        obj->anim.localPosZ = state->scratch708.f - state->dirZ * spd;
        if (GROUND_ANIMATOR_INTERFACE(pc)->isFullySunk((GameObject*)pc) != 0) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            **(u8**)state -= 4;
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            z = 0.0f;
            state->cooldownA = z;
            state->cooldownB.f = z;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm;
                mm = -1;
                state->commandPhase = mm;
            }
            trickyPlayWhineSfx(*(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2), obj);
        }
        break;
    }
}

typedef struct TrickyFnRow {
    u8 pad[0x6c];
    int (*fn)(u8*, u8*);
} TrickyFnRow;

void tricky_stateFollowPlayer(GameObject* obj, TrickyState* state) {
    u8* base;
    GameObject* found;
    TrickyState* other;
    GameObject* target;
    TrickyState* sfxState;
    int inWater;
    f32 z;

    base = (u8*)gTrickyDebugStringTable;
    found = NULL;
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if (state->pendingFollowRequest != 0) {
            switch ((int)state->pendingFollowRequest) {
            case 1: {
                target = state->pendingFollowObj;
                other = obj->extra;
                if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    if ((other->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                        other->followObj = target;
                        if (other->targetPosPtr != &target->anim.worldPosX) {
                            other->targetPosPtr = &target->anim.worldPosX;
                            {
                                u32 mask;
                                u32 flags = other->stateFlags;
                                mask = ~0x400;
                                other->stateFlags = flags & mask;
                            }
                            other->linkedWalkGroup = 0;
                        }
                        other->substate = 0;
                        other->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                    } else {
                        other->pendingFollowRequest = 1;
                        other->pendingFollowObj = target;
                        other->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                    }
                }
                if (tricky_handleFeedOrTalk(obj, state) == 0 && trickyUpdateMovementState(obj, 5.0f, state) == 0) {
                    state->idleSfxTimer -= timeDelta;
                    if (state->idleSfxTimer <= 0.0f) {
                        state->idleSfxTimer = (f32)(int)randomGetRange(500, 0x2ee);
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, 0x360, 0x500, -1, 0);
                        }
                    }
                    if (0.0f == state->waterLevel) {
                        inWater = 0;
                    } else if (gTrickyEventTimeSentinel == state->eventTime) {
                        inWater = 1;
                    } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                        inWater = 1;
                    } else {
                        inWater = 0;
                    }
                    if (inWater != 0) {
                        trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = 0.0f;
                        trickyDebugPrint((char*)(base + TRICKY_DBG_IN_WATER));
                    } else {
                        switch (obj->anim.currentMove) {
                        case 0xd:
                            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
                                trickyRequestMove(obj, 0x31, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                            }
                            break;
                        default:
                            trickyRequestMove(obj, 0xd, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        case 0x31:
                            break;
                        }
                        trickyDebugPrint((char*)(base + TRICKY_DBG_OUT_OF_WATER));
                    }
                }
            } break;
            default:
                break;
            }
            state->pendingFollowRequest = 0;
            return;
        }
        found = Tricky_findNearestGroup4BObject(obj, state);
    }
    if (found != NULL) {
        state->groundSnapCounter = 2;
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        z = 0.0f;
        state->cooldownA = z;
        state->cooldownB.f = z;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
        {
            s8 mm;
            mm = -1;
            state->commandPhase = mm;
        }
        obj->anim.localPosX = found->anim.localPosX;
        obj->anim.localPosY = found->anim.localPosY;
        obj->anim.localPosZ = found->anim.localPosZ;
        obj->anim.worldPosX = found->anim.worldPosX;
        obj->anim.worldPosY = found->anim.worldPosY;
        obj->anim.worldPosZ = found->anim.worldPosZ;
        ObjHits_SyncObjectPosition(obj);
        obj->anim.rotX = found->anim.rotX;
        state->movementState = TRICKY_MOVE_WALK_WAIT;
        z = 0.0f;
        state->prevSpeed = z;
        state->speed = z;
        state->homePosX = found->anim.worldPosX;
        state->homePosY = found->anim.worldPosY;
        state->homePosZ = found->anim.worldPosZ;
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_WARP_RETURNED;
        state->stateFlags &= ~0x2000LL;
    } else {
        state->cooldownA -= timeDelta;
        if (state->cooldownA < 0.0f) {
            state->cooldownA = 0.0f;
        }
        tricky_handlePlayerContact(obj, state);
        {
            if (((int (**)(GameObject*, TrickyState*))(base + TRICKY_SUBSTATE_HANDLER_TABLE_OFFSET))[state->substate](
                    obj, state) == 0) {
                if (0.0f == state->waterLevel) {
                    inWater = 0;
                } else if (gTrickyEventTimeSentinel == state->eventTime) {
                    inWater = 1;
                } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                    inWater = 1;
                } else {
                    inWater = 0;
                }
                if (inWater != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                } else {
                    trickyRequestMove(obj, 0x25, 0.0025f, 0);
                }
            }
        }
    }
}

int tricky_substateApproachThorntail(GameObject* obj, TrickyState* state) {
    TrickyState* tex;
    short move;
    u16 sfxId;
    float pos[3];

    objGetJointWorldPosition(state->followObj, 0, pos);
    if (getXZDistanceSquared(pos, &state->wanderTargetX) > 100.0f) {
        state->wanderTargetX = pos[0];
        state->wanderTargetY = pos[1];
        state->wanderTargetZ = pos[2];
    }
    if (state->flag728Bit5 != 0) {
        if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) {
            return 0;
        }
        tricky_startRandomIdleMove((GameObject*)(obj), state);
    } else if ((u8)trickyUpdateMovementState(obj, 30.0f, state) != 1) {
        state->flag728Bit5 = 1;
        sfxId = randomGetRange(862, 863);
        tex = obj->extra;
        if (tex->soundSuppressed == 0) {
            move = obj->anim.currentMove;
            if (move >= 48 || move < 41) {
                if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                    objSoundStartTimed(obj, &tex->soundState, sfxId, 1280, -1, 0);
                }
            }
        }
        return 0;
    }
    return 1;
}

int tricky_substateFlameBreath(GameObject* obj, TrickyState* state) {
    int i;
    int j;
    TrickyState* sfxState;
    u8* p;
    u8* q;
    FlameblastPlacement* setup;

    switch (obj->anim.currentMove) {
    case 0x1a:
        if (obj->anim.currentMoveProgress > 0.25f && (state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
            if (Obj_IsLoadingLocked() != 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (i = 0, p = (u8*)state; i < 7; p += 4, i++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(0x24, TRICKY_CHILD_OBJ_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = i;
                    ((TrickyState*)p)->flameChildren[0] =
                        objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
        } else {
            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (j = 0, q = (u8*)state; j < 7; q += 4, j++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(q));
                }
                Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                sfxState = obj->extra;
                if (sfxState->soundSuppressed == 0 && (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                    Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                    objSoundStartTimed(obj, &sfxState->soundState, 0x29d, 0, -1, 0);
                }
                state->substate = 10;
            }
        }
        break;
    default:
        trickyRequestMove(obj, 0x1a, 0.004f, 0);
    }
    return 1;
}

int tricky_substateBegForFood(GameObject* obj, TrickyState* state) {
    TrickyState* tex;
    int result;
    short move;
    TrickyItemIdList buf;

    buf = gTrickyFoodItemIds;
    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->cooldownB.f = 0.0f;
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~0x10;
            state->stateFlags = flags & mask;
        }
        state->substate = 0;
        return 1;
    }
    result = (*gGameUIInterface)->isOneOfItemsBeingUsed(buf.ids, TRICKY_ITEM_ID_COUNT);
    switch (result) {
    case 0:
    case 1:
    case 3:
    case 4:
    case 5:
        tex = obj->extra;
        if (tex->soundSuppressed == 0u) {
            move = (obj)->anim.currentMove;
            if (move >= 48 || move < 41) {
                if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                    objSoundStartTimed(obj, &tex->soundState, 861, 1280, -1, 0);
                }
            }
        }
        break;
    }
    if (0.0f == state->cooldownB.f) {
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~0x10;
            state->stateFlags = flags & mask;
        }
        state->substate = 0;
    }
    if ((u8)trickyUpdateMovementState(obj, 20.0f, state) == 1) {
        return 1;
    }
    return 0;
}

int tricky_substateDigForFood(GameObject* obj, TrickyState* state) {
    short move;
    int b;
    PartFxSpawnParams spawnBuf;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case 44:
    case 45:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, 46, 0.0125f, 0);
        }
        break;
    case 46: {
        if (((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) &&
            (((state->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0 || randomGetRange(0, 2) == 0) ||
             state->cooldownB.f > 0.0f)) {
            trickyRequestMove(obj, 47, 0.01f, 0);
        }
        spawnBuf.posX = (obj)->anim.worldPosX;
        spawnBuf.posY = (obj)->anim.worldPosY;
        spawnBuf.posZ = (obj)->anim.worldPosZ;
        spawnBuf.scale = 0.7f;
        (*gPartfxInterface)->spawnObject((void*)obj, 2022, &spawnBuf, 0x200001, -1, NULL);
        break;
    }
    case 47:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            if (0.0f == state->waterLevel) {
                b = 0;
            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                b = 1;
            } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                b = 1;
            } else {
                b = 0;
            }
            if (b != 0) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~0x10;
                state->stateFlags = flags & mask;
            }
            state->substate = 0;
        }
        break;
    }
    return 1;
}

int tricky_substateIdlePick(GameObject* obj, TrickyState* state) {
    TrickyState* sfxState;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    if ((u8)trickyUpdateMovementState(obj, gTrickyMaxDistance, state) != 1) {
        if (state->childB != NULL) {
            sfxState = obj->extra;
            if (sfxState->soundSuppressed == 0 && (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &sfxState->soundState, 0x357, 0, -1, 0);
            }
            trickyRequestMove(obj, 0x26, 0.0075f, 0);
            state->substate = 5;
        } else {
            switch (randomGetRange(0, 6)) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                tricky_startRandomIdleMove(obj, state);
                break;
            default:
                tricky_pickAmbientActivity(obj, state);
                break;
            }
        }
    }
    return 1;
}

u32 tricky_substateFidgetA(GameObject* obj, TrickyState* trickyState) {
    short move;
    int foodResult;

    foodResult = tricky_handleFeedOrTalk(obj, trickyState);
    if (foodResult != 0) {
        return 1;
    }
    move = (obj)->anim.currentMove;
    switch (move) {
    case 0x23:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, 0x24, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        }
        break;
    case 0x24:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

u32 tricky_substateFidgetB(GameObject* obj, TrickyState* trickyState) {
    short move;
    int foodResult;

    foodResult = tricky_handleFeedOrTalk(obj, trickyState);
    if (foodResult != 0) {
        return 1;
    }
    move = (obj)->anim.currentMove;
    switch (move) {
    case 0x21:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, 0x22, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        }
        break;
    case 0x22:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

u32 tricky_substateWaitMoveEnd(GameObject* obj, TrickyState* trickyState) {
    TrickyState* ref;
    int val;
    int idx;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    for (val = 0; val < trickyState->animEvents.triggerCount; val++) {
        idx = val + offsetof(TrickyState, animEvents.triggeredIds);
        if (*((s8*)trickyState + idx) != 0) {
            continue;
        }
        ref = obj->extra;
        if (ref->soundSuppressed != 0U) {
            continue;
        }
        if ((int)(obj)->anim.currentMove >= 0x30 || (int)(obj)->anim.currentMove < 0x29) {
            if (((int (*)(GameObject*, int))Sfx_IsPlayingFromObjectChannel)(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &ref->soundState, 0x357, 0, 0xffffffff, 0);
            }
        }
    }
    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = 0;
        }
    }
    return 1;
}

int tricky_substateHowlCall(GameObject* obj, TrickyState* trickyState) {
    char bval;
    short move;
    float fval;
    int b[1];
    int val;
    PartFxSpawnParams fxBuf;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case 0x29:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, 0x2a, 0.003f, 0);
        }
        break;
    case 0x2a:
        trickyState->moveHoldTimer = trickyState->moveHoldTimer - timeDelta;
        if (trickyState->moveHoldTimer <= 0.0f) {
            if (((trickyState->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) ||
                (trickyState->cooldownB.f > 0.0f)) {
                trickyRequestMove(obj, 0x2b, 0.01f, 0);
            } else {
                val = (*gSkyInterface)->getSunPosition(0);
                if (val == 0) {
                    trickyRequestMove(obj, 0x2c, 0.0075f, 0);
                    trickyState->substate = 9;
                }
            }
        }
        for (val = 0; val < trickyState->animEvents.triggerCount; val++) {
            b[0] = val + offsetof(TrickyState, animEvents.triggeredIds);
            bval = *((char*)trickyState + b[0]);
            if (bval == '\0') {
                objSoundStartTimed(obj, &trickyState->soundState, 0x390, 0x500, -1, 0);
            } else if (bval == '\a') {
                objSoundStartTimed(obj, &trickyState->soundState, 0x391, 0x100, -1, 0);
            }
        }
        fval = trickyState->sparkleFxTimer - timeDelta;
        trickyState->sparkleFxTimer = fval;
        if (fval <= 0.0f) {
            if (((obj)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                fxBuf.posX = trickyState->renderPosX;
                fxBuf.posY = 2.0f + trickyState->renderPosY;
                fxBuf.posZ = trickyState->renderPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7f0, &fxBuf, 0x200001, -1, NULL);
            }
            trickyState->sparkleFxTimer = 30.0f;
        }
        break;
    case 0x2b:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            if (0.0f == trickyState->waterLevel) {
                b[0] = 0;
            } else if (gTrickyEventTimeSentinel == trickyState->eventTime) {
                b[0] = 1;
            } else if (trickyState->currentTime - trickyState->eventTime > gTrickyEventStaleSeconds) {
                b[0] = 1;
            } else {
                b[0] = 0;
            }
            if (b[0] != 0) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                trickyState->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                trickyState->particleTimer = 0.0f;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~0x10;
                trickyState->stateFlags = flags & mask;
            }
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

int tricky_substateSleep(GameObject* obj, TrickyState* state) {
    s8 slots[4];
    TrickyState* sfxState;
    u8* e;
    int idx;
    f32 z;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->substate = 0;
        return 1;
    }
    if (cMenuGetSelectedItem() == 0xc1) {
        state->substate = 0;
        return 1;
    }
    state->sfxRepeatTimer -= timeDelta;
    if (state->sfxRepeatTimer < 0.0f) {
        sfxState = (obj)->extra;
        if (sfxState->soundSuppressed == 0 && ((obj)->anim.currentMove >= 0x30 || (obj)->anim.currentMove < 0x29) &&
            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, 0x29a, 0x100, -1, 0);
        }
        state->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
    }
    if (state->child == NULL && Obj_IsLoadingLocked() != 0) {
        e = (u8*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_FOOD);
        slots[0] = -1;
        slots[1] = -1;
        slots[2] = -1;
        if (state->childA != NULL) {
            slots[state->packedSlots.promptASlot] = 1;
        }
        if (state->childB != NULL) {
            slots[state->packedSlots.promptBSlot] = 1;
        }
        if (state->child != NULL) {
            slots[state->packedSlots.zzzSlot] = 1;
        }
        if (slots[0] == -1) {
            idx = 0;
        } else if (slots[1] == -1) {
            idx = 1;
        } else if (slots[2] == -1) {
            idx = 2;
        } else if (slots[3] == -1) {
            idx = 3;
        } else {
            idx = -1;
        }
        state->packedSlots.zzzSlot = idx;
        state->child = objSetupObject((ObjPlacement*)e, 4, -1, -1, (obj)->anim.parent);
        ObjLink_AttachChild(obj, state->child, state->packedSlots.zzzSlot);
        z = 0.0f;
        state->childPhaseTimer0 = z;
        state->childPhaseTimer1 = z;
        state->childPhaseTimer2 = z;
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0 && state->cooldownA <= 0.0f &&
        mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
        trickyRequestMove(obj, 0x29, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        sfxState = (obj)->extra;
        if (sfxState->soundSuppressed == 0 && ((obj)->anim.currentMove >= 0x30 || (obj)->anim.currentMove < 0x29) &&
            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, 0x354, 0x1000, -1, 0);
        }
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 4;
        state->moveHoldTimer = (f32)(int)randomGetRange(0x78, 0xf0);
    }
    return 1;
}

u32 tricky_substateWaitQueuedMove(GameObject* obj, TrickyState* trickyState) {
    int val;

    val = tricky_handleFeedOrTalk(obj, trickyState);
    if (val != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = 0;
        }
    }
    return 1;
}

u32 tricky_substateReturnToHeel(GameObject* obj, TrickyState* trickyState) {
    int val;

    val = tricky_handleFeedOrTalk(obj, trickyState);
    if (val != 0) {
        return 1;
    }
    val = trickyUpdateMovementState(obj, 20.0f, (TrickyState*)trickyState);
    if (val == 1) {
        if (0.0f == trickyState->cooldownA) {
            trickyState->substate = 0;
        }
        return 1;
    }
    trickyState->substate = 0;
    return 0;
}

int tricky_substateFollowIdle(GameObject* obj, TrickyState* state) {
    TrickyState* tex;
    short move;
    u8 result;
    f32* followBase;
    int inWater;
    float threshold;

    state->followObj = state->playerObj;
    followBase = &state->followObj->anim.worldPosX;
    if (state->targetPosPtr != followBase) {
        state->targetPosPtr = followBase;
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~0x400;
            state->stateFlags = flags & mask;
        }
        state->linkedWalkGroup = 0;
    }
    if (0.0f == state->cooldownA) {
        {
            s8 mm;
            mm = -1;
            state->commandPhase = mm;
        }
        threshold = 30.0f;
    } else {
        if ((state->stateFlags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
            state->commandPhase = 0;
            state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
        }
        threshold = 20.0f;
    }
    result = trickyUpdateMovementState(obj, threshold, state);
    if (result != 1) {
        if (result == 2) {
            if ((state->stateFlags & 2) != 0) {
                tex = obj->extra;
                if (tex->soundSuppressed == 0u) {
                    move = (obj)->anim.currentMove;
                    if (move >= 48 || move < 41) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0) {
                            objSoundStartTimed(obj, &tex->soundState, 861, 1280, -1, 0);
                        }
                    }
                }
            }
        }
        if (0.0f == state->waterLevel) {
            inWater = 0;
        } else if (gTrickyEventTimeSentinel == state->eventTime) {
            inWater = 1;
        } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
            inWater = 1;
        } else {
            inWater = 0;
        }
        if (inWater != 0) {
            return 0;
        }
        return tricky_updateIdleBehavior(obj, state);
    }
    state->flag728Bit7 = 1;
    return 1;
}

u32 tricky_updateIdleBehavior(GameObject* obj, TrickyState* trickyState) {
    int done;
    TrickyState* extra;
    u32 bitVal;

    done = tricky_handleFeedOrTalk((GameObject*)(obj), trickyState);
    if (done != 0) {
        return 1;
    }
    if (trickyState->cooldownC > 0.0f) {
        trickyRequestMove(obj, 0x1b, 0.01f, 0);
        trickyState->substate = 2;
        trickyState->cooldownC = 0.0f;
        return 1;
    }
    if (trickyState->flag728Bit7 != 0U) {
        trickyState->idleTimer = 200.0f;
        trickyState->flag728Bit7 = 0;
        trickyState->flag728Bit6 = 1;
    }
    if (trickyState->flag728Bit6 != 0U) {
        trickyState->idleTimer -= timeDelta;
        if (trickyState->idleTimer <= 0.0f) {
            trickyState->cooldownA = 300.0f;
            bitVal = randomGetRange(200, 500);
            trickyState->idleTimer = (f32)(s32)bitVal;
            trickyState->flag728Bit6 = 0;
            trickyState->substate = 1;
        }
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10)) {
        return 1;
    }
    done = (*gSkyInterface)->getSunPosition(0);
    if (done == 0) {
        trickyState->stateFlags = trickyState->stateFlags & ~TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
    }
    done = (*gSkyInterface)->getSunPosition(0);
    if ((done != 0) && ((trickyState->stateFlags & TRICKY_STATE_FLAG_SUN_VOICE_PLAYED_U32) == 0)) {
        trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
        done = (int)obj->extra;
        if ((((TrickyState*)done)->soundSuppressed == 0U) &&
            ((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
             !Sfx_IsPlayingFromObjectChannel(obj, 0x10))) {
            objSoundStartTimed(obj, &((TrickyState*)done)->soundState, 0x353, 0x500, 0xffffffff, 0);
        }
        return 0;
    }
    if (*trickyState->progressPtr <= 3) {
        trickyRequestMove(obj, 0x14, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 3;
        trickyState->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
        return 1;
    }
    trickyState->idleTimer -= timeDelta;
    if (trickyState->idleTimer <= 0.0f) {
        bitVal = randomGetRange(200, 500);
        trickyState->idleTimer = (f32)(s32)bitVal;
        if (*trickyState->progressPtr <= 7) {
            trickyRequestMove(obj, 0x14, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
            trickyState->substate = 3;
            trickyState->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
            return 1;
        }
        if (trickyState->cooldownA > 0.0f) {
            tricky_startRandomIdleMove((GameObject*)(obj), trickyState);
        } else {
            if (trickyState->childB != NULL) {
                extra = obj->extra;
                if (((extra->soundSuppressed == 0U) &&
                     (obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
                     !Sfx_IsPlayingFromObjectChannel(obj, 0x10))) {
                    objSoundStartTimed(obj, &extra->soundState, 0x357, 0, 0xffffffff, 0);
                }
                trickyRequestMove(obj, 0x26, 0.0075f, 0);
                trickyState->substate = 5;
            } else {
                bitVal = randomGetRange(0, 6);
                switch ((int)bitVal) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                    tricky_startRandomIdleMove(obj, trickyState);
                    break;
                default:
                    tricky_pickAmbientActivity(obj, (TrickyState*)trickyState);
                    break;
                }
            }
        }
        return 1;
    }
    return 0;
}

void tricky_pickAmbientActivity(GameObject* obj, TrickyState* state) {
    f32 arr[2];
    TrickyState* sfxState;
    u8 lo;
    u8 hi;
    GameObject* found;
    int sv;
    f32 ang;

    lo = 1;
    hi = 3;
    arr[0] = 200.0f;
    found = objGetNearestTypeTo(SHTHORNTAIL_OBJECT_GROUP, obj, arr);
    if (found != NULL && ((found)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        lo = 0;
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0 || mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
        hi = 2;
    }
    switch (randomGetRange(lo, hi)) {
    case 0:
        state->followObj = found;
        objGetJointWorldPosition(found, 0, &state->wanderTargetX);
        if ((u8*)state->targetPosPtr != (u8*)&state->wanderTargetX) {
            state->targetPosPtr = &state->wanderTargetX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~0x400;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->flag728Bit5 = 0;
        state->substate = 0xc;
        break;
    case 1:
        sv = randomGetRange(0x20, 0xff);
        sv = (s16)((obj->anim.rotX + sv) * 0x100);
        ang = TRICKY_PI * (f32)sv / TRICKY_ANGLE_HALF_TURN_UNITS;
        state->wanderTargetX = (f32)(0.1 * -mathSinf(ang) + obj->anim.localPosX);
        state->wanderTargetY = obj->anim.localPosY;
        state->wanderTargetZ = (f32)(0.1f * -mathCosf(ang) + obj->anim.localPosZ);
        if ((u8*)state->targetPosPtr != (u8*)&state->wanderTargetX) {
            state->targetPosPtr = &state->wanderTargetX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~0x400;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 8;
        break;
    case 2:
        trickyRequestMove(obj, 0x2d, 0.015f, 0);
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 9;
        break;
    case 3:
        trickyRequestMove(obj, 0x29, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        sfxState = obj->extra;
        if (sfxState->soundSuppressed == 0 && (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, 0x354, 0x1000, -1, 0);
        }
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 4;
        state->moveHoldTimer = (f32)(int)randomGetRange(0x78, 0xf0);
        break;
    }
}

void tricky_startRandomIdleMove(GameObject* obj, TrickyState* trickyState) {
    int val;
    TrickyState* state;

    val = randomGetRange(0, 4);
    switch (val) {
    case 0:
        trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 2;
        break;
    case 1:
        state = obj->extra;
        if (state->soundSuppressed == 0U) {
            if ((obj)->anim.currentMove >= 0x30 || (obj)->anim.currentMove < 0x29) {
                if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                    objSoundStartTimed(obj, &state->soundState, 0x357, 0, 0xffffffff, 0);
                }
            }
        }
        trickyRequestMove(obj, 0x26, 0.0075f, 0);
        trickyState->substate = 5;
        break;
    case 2:
        trickyRequestMove(obj, 0x21, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 6;
        break;
    case 3:
        trickyRequestMove(obj, 0x23, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 7;
        break;
    case 4:
        trickyRequestMove(obj, 0x25, 0.0025f, 0);
        trickyState->substate = 2;
        break;
    }
}

int tricky_handleFeedOrTalk(GameObject* obj, TrickyState* state) {
    TrickyState* b;
    u8 gu;
    int g;
    u8 flag;
    u8 a;
    u8 c;
    u8 d;
    u8 n;
    u8 cnt;
    int inWater;
    s16 item[4];

    flag = 0;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    n = mainGetBit(GAMEBIT_ITEM_TrickyFood_Count);
    if (n != 0) {
        getYButtonItem(item);
        if (item[0] == 0xc1) {
            flag = 1;
        }
        if (cMenuGetSelectedItem() == 0xc1) {
            flag = 1;
        }
    }
    if (flag != 0) {
        if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
            if ((*gGameUIInterface)->isItemBeingUsed(0xc1) != 0) {
                a = *state->progressPtr;
                c = state->progressPtr[1];
                if (a == c) {
                    b = obj->extra;
                    b->stateFlags |= 0x4000;
                    b->stateFlags |= 1;
                    if (0.0f == b->waterLevel) {
                        inWater = 0;
                    } else if (gTrickyEventTimeSentinel == b->eventTime) {
                        inWater = 1;
                    } else if (b->currentTime - b->eventTime > gTrickyEventStaleSeconds) {
                        inWater = 1;
                    } else {
                        inWater = 0;
                    }
                    if (inWater != 0) {
                        trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        b->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        b->particleTimer = 0.0f;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
                    b->flag82EBit5 = 1;
                } else {
                    d = c - a;
                    cnt = (u32)d >> 2;
                    if (d % 4) {
                        cnt += 1;
                    }
                    if (cnt > n) {
                        state->progressValue = a + (n << 2);
                        mainSetBits(GAMEBIT_ITEM_TrickyFood_Count, 0);
                    } else {
                        state->progressValue = a + (cnt << 2);
                        mainSetBits(GAMEBIT_ITEM_TrickyFood_Count, n - cnt);
                    }
                    if (state->progressValue > state->progressPtr[1]) {
                        state->progressValue = state->progressPtr[1];
                    }
                    b = obj->extra;
                    b->stateFlags |= 0x4000;
                    if (0.0f == b->waterLevel) {
                        inWater = 0;
                    } else if (gTrickyEventTimeSentinel == b->eventTime) {
                        inWater = 1;
                    } else if (b->currentTime - b->eventTime > gTrickyEventStaleSeconds) {
                        inWater = 1;
                    } else {
                        inWater = 0;
                    }
                    if (inWater != 0) {
                        trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        b->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        b->particleTimer = 0.0f;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                    b->flag82EBit5 = 1;
                    state->stateFlags |= TRICKY_STATE_FLAG_FEED_VOICE_PENDING;
                }
                buttonDisable(0, PAD_BUTTON_A);
                return 1;
            }
        } else {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        }
    } else {
        gu = mainGetBit(GAMEBIT_TrickyTalk);
        if (gu != 0xff && cMenuGetSelectedItem() == -1) {
            if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                mainSetBits(GAMEBIT_TrickyTalk, 0xff);
                b = obj->extra;
                g = gu;
                b->stateFlags |= 0x4000;
                if (g != 2) {
                    b->stateFlags |= 1;
                }
                if (0.0f == b->waterLevel) {
                    inWater = 0;
                } else if (gTrickyEventTimeSentinel == b->eventTime) {
                    inWater = 1;
                } else if (b->currentTime - b->eventTime > gTrickyEventStaleSeconds) {
                    inWater = 1;
                } else {
                    inWater = 0;
                }
                if (inWater != 0) {
                    trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    b->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    b->particleTimer = 0.0f;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
                (*gObjectTriggerInterface)->runSequence(g, (void*)obj, -1);
                b->flag82EBit5 = 1;
                buttonDisable(0, PAD_BUTTON_A);
                return 1;
            }
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        }
    }
    return 0;
}

void tricky_handlePlayerContact(GameObject* obj, TrickyState* state) {
    GameObject* hit[1];
    TrickyState* sfxState;
    f32 fv;
    int inWater;

    state->cooldownB.f -= timeDelta;
    if (state->cooldownB.f < 0.0f) {
        state->cooldownB.f = 0.0f;
    }
    if (ObjHits_GetPriorityHit(obj, hit, 0, 0) != 0 && hit[0]->ownerObj != NULL &&
        ((GameObject*)hit[0]->ownerObj)->anim.classId == 1) {
        fv = state->cooldownB.f;
        if (fv <= 0.0f) {
            state->cooldownB.f += 180.0f;
            sfxState = obj->extra;
            if (sfxState->soundSuppressed == 0 && (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &sfxState->soundState, 0x34f, 0x500, -1, 0);
            }
        } else {
            state->cooldownB.f += TRICKY_TIMER_600_FRAMES;
            if (state->substate != 0xb) {
                if (state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) {
                    if (state->cooldownB.f > 3000.0f) {
                        state->cooldownB.f *= 0.5f;
                        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
                            if (0.0f == state->waterLevel) {
                                inWater = 0;
                            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                                inWater = 1;
                            } else if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
                                inWater = 1;
                            } else {
                                inWater = 0;
                            }
                            if (inWater == 0) {
                                state->substate = 0xb;
                                return;
                            }
                        }
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, 0x350, 0x500, -1, 0);
                        }
                    } else {
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                            Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, 0x350, 0x500, -1, 0);
                        }
                    }
                } else {
                    sfxState = obj->extra;
                    if (sfxState->soundSuppressed == 0 &&
                        (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                        Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                        objSoundStartTimed(obj, &sfxState->soundState, 0x350, 0x500, -1, 0);
                    }
                    state->substate = 10;
                    state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                }
            }
        }
    }
}

typedef void (*TrickyHandlerFn)(void* obj, void* state);

/* group owned by another DLL, queried here */

/* child/reward objects spawned by this DLL (retail OBJECTS.bin names) */
#define TRICKY_CHILD_OBJ_BADGE_A       0x244 /* "TrickyBadge" */
#define TRICKY_CHILD_OBJ_BADGE_B       0x254 /* "TrickyBadge" */
#define TRICKY_CHILD_OBJ_QUEST         0x17c /* "TrickyQuest..." */
#define TRICKY_CHILD_OBJ_EXCLAMATION   0x175 /* "TrickyExcla..." */
#define TRICKY_CHILD_OBJ_SIDEKICK_BALL 0x112 /* "SidekickBal..." (DLL 0xF5 sidekickball) */
#define TRICKY_OBJ_BLUE_MUSHROOM       0x6a  /* "BlueMushroo..." (DLL 0x1A7) */

/* GameObject.objectFlags bit (distinct field from stateFlags above). */
#define TRICKY_OBJFLAG_PARENT_SLACK            0x1000
#define TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID 0x46406
#define TRICKY_OBJGROUP                        1
#define TRICKY_BBOX_HIT_SCRATCH_SIZE           84

typedef enum TrickySequenceEvent {
    TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN = 1,
    TRICKY_SEQUENCE_EVENT_SPAWN_BADGE = 2,
    TRICKY_SEQUENCE_EVENT_STORE_PROGRESS = 3,
    TRICKY_SEQUENCE_EVENT_HIDE_SHADOW = 0x2B,
    TRICKY_SEQUENCE_EVENT_SHOW_SHADOW = 0x2C,
} TrickySequenceEvent;

int lbl_803DDA4C;
u32 gTrickyHelperObject;

GameObject* Tricky_findNearestGroup4BObject(GameObject* obj, TrickyState* state) {
    GameObject** objs;
    int count[1];
    GameObject* result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = objGetAllOfType(TRICKYWARP_OBJ_GROUP, count);
    d = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &obj->anim.worldPosX);
    if ((d >= 360000.0f) || (state->cooldownA > 0.0f)) {
        if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX, 19.0f) == 0) {
            bestD = gTrickyMaxDistance;
            for (i = 0; i < count[0]; i++) {
                f32 cd = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &(*objs)->anim.worldPosX);
                if (cd < d && cd < bestD) {
                    bestD = cd;
                    result = *objs;
                }
                objs++;
            }
        }
    }
    return result;
}

void tricky_stateIdleWander(GameObject* obj, TrickyState* state) {
    TrickyState* sfxState;
    int isInWater;
    u32 sfxDisabled;
    u32 transitionFlag;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        state->wanderTargetX =
            (obj)->anim.worldPosX - mathSinf((TRICKY_PI * (f32) * (s16*)obj) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->wanderTargetY = (obj)->anim.worldPosY;
        state->wanderTargetZ =
            (obj)->anim.worldPosZ - mathCosf((TRICKY_PI * (f32) * (s16*)obj) / TRICKY_ANGLE_HALF_TURN_UNITS);

        if (trickyUpdateMovementState(obj, 15.0f, state) != 1) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= 0.0f) {
                state->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
                sfxState = obj->extra;
                sfxDisabled = sfxState->soundSuppressed;
                if ((sfxDisabled == 0) && (((obj)->anim.currentMove >= 0x30) || ((obj)->anim.currentMove < 0x29)) &&
                    (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)) {
                    objSoundStartTimed(obj, &sfxState->soundState, 0x360, 0x500, -1, 0);
                }
            }

            if (0.0f == state->waterLevel) {
                isInWater = 0;
            } else if (gTrickyEventTimeSentinel == state->eventTime) {
                isInWater = 1;
            } else if ((state->currentTime - state->eventTime) > gTrickyEventStaleSeconds) {
                isInWater = 1;
            } else {
                isInWater = 0;
            }

            if (isInWater) {
                trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch ((obj)->anim.currentMove) {
                case 0x31:
                    break;
                case 0xd:
                    transitionFlag = state->stateFlags & 0x08000000;
                    if (transitionFlag != 0) {
                        trickyRequestMove(obj, 0x31, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    }
                    break;
                default:
                    trickyRequestMove(obj, 0xd, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    break;
                }
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
        }
    }
}

void tricky_attachToWalkGroup(GameObject* obj, TrickyState* state) {
    u8 pathBytes[16];
    u32 pathByte = (u8)Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);

    pathBytes[0] = pathByte;
    if (pathByte == 0) {
        int pathId = Objfsa_GetPatchGroupIdAtPoint(&obj->anim.worldPosX);
        if (pathId != 0) {
            walkPath_writeU16LE(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0) {
        f32 resetTimer;

        state->walkGroup = pathBytes[0];
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        resetTimer = 0.0f;
        state->cooldownA = resetTimer;
        state->cooldownB.f = resetTimer;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
        state->commandPhase = -1;
    }
    if (gTrickyHelperObject == 0) {
        int setup = (int)Obj_AllocObjectSetup(0x18, 0x25);
        gTrickyHelperObject = (int)objSetupObject((ObjPlacement*)setup, 4, -1, -1, obj->anim.parent);
    }
    state->statusFlag7 = 1;
}

static inline int trickyGetState(GameObject* obj) {
    return (int)obj->extra;
}

int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int state;
    int i;
    ObjSeqState* sequence = animUpdate;
    u8* childSlot;
    int secondChildIndex;
    int childIndex;
    u8* spawnSlot;
    ObjPlacement* setup;
    u8 blockFlags[120];

    state = trickyGetState(obj);
    if ((((TrickyState*)state)->stateFlags & 0x200) == 0) {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, 0x7f);
        if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
            ((TrickyState*)state)->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (childIndex = 0, childSlot = (u8*)state; childIndex < CHILD_OBJECT_COUNT;
                 childSlot += sizeof(GameObject*), childIndex++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(childSlot));
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            childSlot = obj->extra;
            if (((TrickyState*)childSlot)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, 0x29d, 0, -1, 0);
            }
        }
        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        ((TrickyState*)state)->stateFlags |= 0x200;
        if ((sequence->flags & 3) == 0) {
            ((TrickyState*)state)->stateFlags |= 0x4000;
        }
        if (((TrickyState*)state)->flag82EBit5 == 0) {
            ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
            ((TrickyState*)state)->blendActive = 0;
        }
    }

    for (i = 0; i < sequence->eventCount; i++) {
        switch (sequence->eventIds[i]) {
        case TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN:
            if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                ((TrickyState*)state)->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (secondChildIndex = 0, childSlot = (u8*)state; secondChildIndex < CHILD_OBJECT_COUNT;
                     childSlot += sizeof(GameObject*), secondChildIndex++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_FROM_STATE_BASE(childSlot));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                childSlot = obj->extra;
                if (((TrickyState*)childSlot)->soundSuppressed == 0 &&
                    (obj->anim.currentMove >= 0x30 || obj->anim.currentMove < 0x29) &&
                    Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
                    objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, 0x29d, 0, -1, 0);
                }
            } else if (Obj_IsLoadingLocked()) {
                ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (childIndex = 0, spawnSlot = (u8*)state; childIndex < CHILD_OBJECT_COUNT;
                     spawnSlot += sizeof(GameObject*), childIndex++) {
                    setup = Obj_AllocObjectSetup(sizeof(FlameblastPlacement), TRICKY_CHILD_OBJ_FLAMEBLAST);
                    ((FlameblastPlacement*)setup)->base.color[0] = 2;
                    ((FlameblastPlacement*)setup)->base.color[1] = 1;
                    ((FlameblastPlacement*)setup)->streamIndex = childIndex;
                    TRICKY_FLAME_CHILD_FROM_STATE_BASE(spawnSlot) =
                        objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_SPAWN_BADGE:
            mainSetBits(GAMEBIT_Tricky_LoadBadge, 1);
            if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && ((TrickyState*)state)->spawnedChild == NULL &&
                Obj_IsLoadingLocked()) {
                mapGetLoadedMapFlags(blockFlags);
                if (blockFlags[0xd] != 0) {
                    setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_A);
                } else {
                    setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_B);
                }
                ((TrickyState*)state)->spawnedChild = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
                ObjLink_AttachChild(obj, ((TrickyState*)state)->spawnedChild, 3);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_STORE_PROGRESS:
            *((TrickyState*)state)->progressPtr = ((TrickyState*)state)->progressValue;
            break;
        case TRICKY_SEQUENCE_EVENT_HIDE_SHADOW:
            obj->anim.modelState->flags &= ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case TRICKY_SEQUENCE_EVENT_SHOW_SHADOW:
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }

    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->childA);
    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->childB);
    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->child);
    tricky_updateModelVariantFade(obj, (TrickyState*)state);
    Tricky_updateBlendChannelWeight(obj, (TrickyState*)state);
    objAudioDispatchAnimEvents(obj, &sequence->animEvents, 1, ((TrickyState*)state)->footPoints,
                               &((TrickyState*)state)->pathControlFlags, 1.0f, 1.0f);
    if ((((TrickyState*)state)->stateFlags & 1) != 0) {
        sequence->flags &= ~0x40;
        characterDoEyeAnims(obj, &((TrickyState*)state)->eyeAnimState);
        return (*gObjectTriggerInterface)->func20(obj, sequence, 1, 0xf, 0x1e, 0, 0);
    }
    return 0;
}

void Tricky_requestRecall(GameObject* obj) {
    TrickyState* state = obj->extra;
    if (mainGetBit(GAMEBIT_Tricky_Usable)) {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

int Tricky_isGuarding(GameObject* obj) {
    u8 mode = ((TrickyState*)obj->extra)->stateIndex;
    if (mode == 8 || mode == 0xe) {
        return 1;
    }
    return 0;
}

int Tricky_isPlayingBall(GameObject* obj) {
    u8 mode;
    int result;
    mode = ((TrickyState*)obj->extra)->stateIndex;
    switch (mode) {
    case 5:
        result = 1;
        break;
    default:
        result = 0;
        break;
    }
    return result;
}

int Tricky_requestMoveToObject(GameObject* obj, GameObject* targetObj) {
    TrickyState* state = obj->extra;
    s32 objBlocked = obj->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK;

    if (objBlocked != 0) {
        return 0;
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        state->followObj = targetObj;
        if (state->targetPosPtr != &targetObj->anim.worldPosX) {
            state->targetPosPtr = &targetObj->anim.worldPosX;
            {
                u32 mask;
                u32 flags = state->stateFlags;

                mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 0;
        state->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
    } else {
        state->pendingFollowRequest = 1;
        state->pendingFollowObj = targetObj;
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    return 1;
}

void Tricky_commandPlayBall(GameObject* obj, int commandEnabled, GameObject* targetObj) {
    TrickyState* state = obj->extra;

    if (commandEnabled != 0) {
        if (state->stateIndex == TRICKY_STATE_BALL_ROLL) {
            if (state->substate != 0) {
                state->followObj = targetObj;
            }
        } else {
            u32 busy = state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            void* nextTarget;
            if (busy != 0) {
                return;
            }
            state->scratch700.ptr = Objfsa_FindNearestEnabledCurveType24(&targetObj->anim.worldPosX, -1, 3);
            state->scratch710.f = (f32)(int)randomGetRange(0x168, 0x28);
            state->stateIndex = TRICKY_STATE_BALL_ROLL;
            state->followObj = targetObj;
            nextTarget = &state->scratch700.curve->x;
            if ((void*)state->targetPosPtr != nextTarget) {
                state->targetPosPtr = (f32*)nextTarget;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            state->substate = 0;
        }
    } else {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

u8 Tricky_getEnergyMax(GameObject* obj) {
    return ((TrickyState*)obj->extra)->progressPtr[1];
}
u8 Tricky_getEnergy(GameObject* obj) {
    return ((TrickyState*)obj->extra)->progressPtr[0];
}

void sideCommandEnable(GameObject* obj, GameObject* targetObj, int commandKind, int commandType) {
    int remaining;
    u8* commandEntry;
    u32 count;
    int commandIndex;
    TrickyState* state;

    state = obj->extra;
    if (state->commandCount == ARRAY_COUNT(state->commands)) {
        trickyReportError(sSidekickCommandDebugTextBlock);
        return;
    }
    state->commandRequestBits = (u8)(state->commandRequestBits | (1 << commandType));
    commandIndex = 0;
    commandEntry = (u8*)state;
    count = state->commandCount;
    for (remaining = count; remaining > 0; remaining--) {
        if (TRICKY_COMMAND_FROM_STATE_BASE(commandEntry)->targetObj == targetObj) {
            state->commands[commandIndex].ttl = 3;
            return;
        }
        commandEntry += sizeof(TrickyCommand);
        commandIndex++;
    }
    state->commands[count].targetObj = targetObj;
    state->commands[state->commandCount].kind = commandKind;
    state->commands[state->commandCount].type = commandType;
    state->commands[state->commandCount].ttl = 3;
    state->commandCount++;
}

int Tricky_getCurrentCommandType(GameObject* obj, int* out) {
    *out = ((TrickyState*)obj->extra)->commandPhase;
    return 1;
}

int Tricky_updateSideCommandPrompts(GameObject* obj) {
    TrickyState* state;
    u32 commandMask;
    char cmdByte;
    u16 promptId;
    u8 cond;
    u8 promptA;
    u8 promptB;
    u8 promptC;
    u32 bitVal;
    int ref;
    TrickyState* refB;
    TrickyState* refC;
    u16* setup;
    u32 spawnedObj;
    u8 i;
    char flagsB[4];
    char flagsA[4];
    u32 promptTable[4];

    state = obj->extra;
    cond = false;
    promptA = false;
    promptB = false;
    promptC = false;
    promptTable[0] = *(u32*)gTrickyQuestPromptSfxIds;
    bitVal = mainGetBit(GAMEBIT_Tricky_Usable);
    if (bitVal != 0) {
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            state->commandRequestBits = 0;
        }
        commandMask = state->commandRequestBits | 9;
        if (((state->stateIndex == TRICKY_STATE_GUARD) || (state->stateIndex == TRICKY_STATE_CIRCLING)) ||
            ((state->stateIndex == TRICKY_STATE_GROWL && (state->substate == 1)))) {
            commandMask |= 0x10;
            promptA = true;
        } else {
            if (trickyFindNearestUsableBaddie(state->playerObj, 200.0f, 1) != NULL) {
                promptA = true;
                promptC = true;
            }
        }
        if (state->commandRequestBits != 0) {
            for (i = 0; i < state->commandCount; i++) {
                ref = (int)state + i * 8;
                cmdByte = TRICKY_COMMAND_FROM_STATE_BASE(ref)->kind;
                if (cmdByte == '\0') {
                    if ((TRICKY_COMMAND_FROM_STATE_BASE(ref)->targetObj)->anim.romDefNo == TRICKY_OBJ_BLUE_MUSHROOM) {
                        promptB = true;
                    }
                    promptA = true;
                } else if (cmdByte == '\x01') {
                    cond = true;
                }
            }
        }
        if (((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) &&
            (bitVal = mainGetBit(GAMEBIT_ITEM_TrickyBall_Usable), bitVal != 0)) {
            ref = (int)Obj_GetPlayerObject();
            ref = playerIsInNormalControlUndisguisedOnLand((GameObject*)(ref));
            if ((ref != 0) && (bitVal = mainGetBit(GAMEBIT_NoBallsAllowed), bitVal == 0)) {
                if (playerGetFlags3F0Bit5(state->playerObj) == 0) {
                    commandMask |= 0x20;
                }
            }
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
            commandMask &= ~1;
        }
        if (mainGetBit(0x9e) == 0) {
            commandMask &= ~4;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) == 0) {
            commandMask &= ~0x10;
        }
        state->commandRequestBits = 0;
        if ((cond) && ((state->stateFlags & 0x200) == 0)) {
            state->promptBDespawnTimer = 60.0f;
            if ((state->childB == NULL) && (Obj_IsLoadingLocked() != 0)) {
                bitVal = randomGetRange(0, 1);
                promptId = *(u16*)((int)promptTable + bitVal * 2);
                ref = (int)obj->extra;
                if ((((TrickyState*)ref)->soundSuppressed == 0) &&
                    (((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
                      !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))) {
                    objSoundStartTimed(obj, &((TrickyState*)ref)->soundState, promptId, 0x500, 0xffffffff, 0);
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_QUEST);
                flagsB[0] = -1;
                flagsB[1] = -1;
                flagsB[2] = -1;
                if (state->childA != NULL) {
                    flagsB[state->packedSlots.promptASlot] = '\x01';
                }
                if (state->childB != NULL) {
                    flagsB[state->packedSlots.promptBSlot] = '\x01';
                }
                if (state->child != NULL) {
                    flagsB[state->packedSlots.zzzSlot] = '\x01';
                }
                if (flagsB[0] == -1) {
                    bitVal = 0;
                } else if (flagsB[1] == -1) {
                    bitVal = 1;
                } else if (flagsB[2] == -1) {
                    bitVal = 2;
                } else if (flagsB[3] == -1) {
                    bitVal = 3;
                } else {
                    bitVal = 0xffffffff;
                }
                state->packedSlots.promptBSlot = bitVal;
                spawnedObj = (int)objSetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, obj->anim.parent);
                state->childB = (GameObject*)spawnedObj;
                ObjLink_AttachChild(obj, state->childB, state->packedSlots.promptBSlot);
            }
        } else if (state->childB != NULL) {
            state->promptBDespawnTimer = state->promptBDespawnTimer - timeDelta;
            if (state->promptBDespawnTimer <= 0.0f) {
                objAnimFreeChildren(obj, state, &state->childB);
            }
        }
        if ((promptA) && ((state->stateFlags & 0x200) == 0)) {
            state->promptADespawnTimer = 60.0f;
            if ((state->childA == NULL) && (Obj_IsLoadingLocked() != 0)) {
                if (randomGetRange(0, 3) == 0) {
                    if (promptB) {
                        refB = obj->extra;
                        if ((refB->soundSuppressed == 0) &&
                            (((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
                              !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))) {
                            objSoundStartTimed(obj, &refB->soundState, 0x359, 0x500, 0xffffffff, 0);
                        }
                    } else if ((((promptC) && (refC = obj->extra, refC->soundSuppressed == 0)) &&
                                ((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)))) &&
                               !Sfx_IsPlayingFromObjectChannel(obj, 0x10)) {
                        objSoundStartTimed(obj, &refC->soundState, 0x358, 0x500, 0xffffffff, 0);
                    }
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_EXCLAMATION);
                flagsA[0] = -1;
                flagsA[1] = -1;
                flagsA[2] = -1;
                if (state->childA != NULL) {
                    flagsA[state->packedSlots.promptASlot] = '\x01';
                }
                if (state->childB != NULL) {
                    flagsA[state->packedSlots.promptBSlot] = '\x01';
                }
                if (state->child != NULL) {
                    flagsA[state->packedSlots.zzzSlot] = '\x01';
                }
                if (flagsA[0] == -1) {
                    bitVal = 0;
                } else if (flagsA[1] == -1) {
                    bitVal = 1;
                } else if (flagsA[2] == -1) {
                    bitVal = 2;
                } else if (flagsA[3] == -1) {
                    bitVal = 3;
                } else {
                    bitVal = 0xffffffff;
                }
                state->packedSlots.promptASlot = bitVal;
                spawnedObj = (int)objSetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, obj->anim.parent);
                state->childA = (GameObject*)spawnedObj;
                ObjLink_AttachChild(obj, state->childA, state->packedSlots.promptASlot);
            }
        } else if (state->childA != NULL) {
            state->promptADespawnTimer = state->promptADespawnTimer - timeDelta;
            if (state->promptADespawnTimer <= 0.0f) {
                objAnimFreeChildren(obj, state, &state->childA);
            }
        }
        return commandMask;
    }
    return -1;
}

int Tricky_getAvailableCommands(GameObject* obj) {
    int r = 0;
    if (mainGetBit(GAMEBIT_Tricky_Usable) != 0) {
        r = TRICKY_ABILITY_FIND_SECRET | TRICKY_ABILITY_STAY;
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
            r |= TRICKY_ABILITY_CALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
            r |= TRICKY_ABILITY_THROW_BALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
            r |= TRICKY_ABILITY_FLAME;
        }
    }
    return r;
}

int Tricky_getExtraSize(void) {
    return 0x83c;
}

void Tricky_free(GameObject* obj, int shouldKeepFlameChildren) {
    int i;
    int childSlot;
    TrickyState* state;
    u32 objId = (u32)obj;

    state = obj->extra;
    freeAndNull((void**)&state->pathSearches[0].nodes);
    freeAndNull((void**)&state->pathSearches[1].nodes);
    freeAndNull((void**)&state->pathSearches[2].nodes);
    freeAndNull((void**)&state->pathSearches[3].nodes);
    freeAndNull((void**)&state->pathSearches[4].nodes);
    freeAndNull((void**)&state->pathSearches[5].nodes);
    freeAndNull((void**)&state->pathSearches[6].nodes);
    freeAndNull((void**)&state->pathSearches[7].nodes);
    freeAndNull((void**)&state->pathSearches[8].nodes);
    objFreeObjectType(obj, TRICKY_OBJGROUP);
    (*gExpgfxInterface)->freeSource(objId);
    if ((shouldKeepFlameChildren == 0) && ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0)) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
        state->stateFlags = state->stateFlags | TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
        i = 0;
        childSlot = (int)state;
        do {
            objSetAnimSpeedTo1((GameObject*)((TrickyState*)childSlot)->scratch700.ptr);
            childSlot = childSlot + 4;
            i = i + 1;
        } while (i < 7);
        Sfx_RemoveLoopedObjectSound((GameObject*)objId, SFXTRIG_trpopn_c);
        childSlot = (int)obj->extra;
        if ((((TrickyState*)childSlot)->soundSuppressed == 0) &&
            (((obj->anim.currentMove >= 0x30 || (obj->anim.currentMove < 0x29)) &&
              (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)))) {
            objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, 0x29d, 0, 0xffffffff, 0);
        }
    }
    doNothing_onTrickyFree();
    objAnimFreeChildren(obj, (TrickyState*)state, &state->childA);
    objAnimFreeChildren(obj, (TrickyState*)state, &state->childB);
    objAnimFreeChildren(obj, (TrickyState*)state, (GameObject**)&state->child);
    if ((void*)state->spawnedChild != NULL) {
        ObjLink_DetachChild(obj, state->spawnedChild);
        Obj_FreeObject((GameObject*)state->spawnedChild);
    }
    if ((state->statusFlag7 != 0u) && (gTrickyHelperObject != 0)) {
        Obj_FreeObject((GameObject*)gTrickyHelperObject);
        gTrickyHelperObject = 0;
    }
    return;
}

void Tricky_render(GameObject* obj, int p2, int p3, int p4, int p5, char doRender) {
    int i;
    TrickyState* pathState;
    int pathPoint;
    s16* pathInfo;
    TrickyState* state;

    if (doRender != '\0') {
        state = obj->extra;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        pathState = obj->extra;
        i = 0;
        pathPoint = (int)pathState;
        do {
            ObjPath_GetPointWorldPosition(obj, i + 4, TRICKY_RENDER_PATH_POINT_X_FROM_STATE_BASE(pathPoint),
                                          TRICKY_RENDER_PATH_POINT_Y_FROM_STATE_BASE(pathPoint),
                                          TRICKY_RENDER_PATH_POINT_Z_FROM_STATE_BASE(pathPoint), 0);
            pathPoint = pathPoint + 0xc;
            i = i + 1;
        } while (i < 4);
        ObjPath_GetPointWorldPosition(obj, 8, &pathState->renderPosX, &pathState->renderPosY, &pathState->renderPosZ,
                                      0);
        pathInfo = objFindJointPoseVector(obj, 0);
        pathState->modelAnchorRotY = pathInfo[1];
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            switch (state->stateIndex) {
            case 2:
                skeetla_spawnLinkedSparks(obj);
                break;
            case 3:
                if (state->substate == 4) {
                    skeetla_spawnLinkedSparks(obj);
                }
                break;
            }
            if ((((state->stateFlags & 0x200) == 0) && (state->stateIndex == TRICKY_STATE_FETCH_BALL)) &&
                (state->substate >= 3)) {
                if (state->substate != 3) {
                    state->scratch700.obj->anim.localPosX = state->renderPosX;
                    state->scratch700.obj->anim.localPosY = state->renderPosY;
                    state->scratch700.obj->anim.localPosZ = state->renderPosZ;
                }
                objRenderModelAndHitVolumes(state->scratch700.obj, p2, p3, p4, p5, 1.0f);
            }
        }
        Tricky_emitQueuedPathParticles(obj, state);
        ObjPath_GetPointWorldPositionArray(obj, 4, 4, (float*)state->footPoints);
        state->particleTimer = state->particleTimer - timeDelta;
        if (state->particleTimer > 0.0f) {
            objDoParticleFx(obj, 0.4f, 6, 1.0f, 0);
        }
    }
    return;
}

void Tricky_hitDetect(GameObject* obj) {
    f32 dy;
    f32 y;
    GameObject** objects;
    int i;
    GameObject* firepipeObj;
    TrickyState* state;
    f32 height;
    f32 z;
    f32 th;
    int count[2];

    state = obj->extra;
    y = obj->anim.localPosY;
    dy = (y - obj->anim.previousLocalPosY >= 0.0f) ? y - obj->anim.previousLocalPosY
                                                   : -(y - obj->anim.previousLocalPosY);
    if (1.0f == dy) {
        if (y == obj->anim.worldPosY) {
            state->heightTracking = 1;
            state->heightTrackObjId = -1;
            state->trackedHeight = 0.0f;
        }
    } else {
        firepipeObj = ObjList_FindObjectById(TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID);
        if ((firepipeObj != 0) && (getXZDistanceSquared(&obj->anim.worldPosX, &firepipeObj->anim.worldPosX) < 841.0f)) {
            state->heightTracking = 1;
            state->heightTrackObjId = TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID;
            state->trackedHeight = 0.0f;
        }
    }
    if (state->heightTracking != 0u) {
        {
            GameObject** t = (GameObject**)objGetAllOfType(XYZ_ANIMATOR_OBJECT_GROUP, count);
            i = 0;
            objects = t;
        }
        for (; i < count[0]; i++) {
            height = XyzAnimator_getCoordinate(*objects, XYZ_ANIMATOR_COORD_WORLD_Y);
            if (*(s32*)&state->heightTrackObjId == -1) {
                dy = (height - obj->anim.localPosY >= 0.0f) ? height - obj->anim.localPosY
                                                            : -(height - obj->anim.localPosY);
                if (dy < 6.0f) {
                    state->heightTrackObjId = (*objects)->anim.placement->ident;
                }
            }
            if (state->heightTrackObjId == (u32)(*objects)->anim.placement->ident) {
                th = state->trackedHeight;
                z = 0.0f;
                if ((th != z) && (th == height)) {
                    state->heightTracking = 0;
                } else {
                    obj->anim.localPosY = height;
                    state->trackedHeight = height;
                }
                break;
            }
            objects = objects + 1;
        }
        if (i == count[0]) {
            state->heightTracking = 0;
        }
    }
    return;
}

/* Tricky sidekick command state machine and per-frame update. */
#define TRICKY_RESET_COMMAND(state)                                                                                    \
    ((TrickyState*)(state))->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;                                                  \
    ((TrickyState*)(state))->substate = 0;                                                                             \
    z = 0.0f;                                                                                                          \
    ((TrickyState*)(state))->cooldownA = z;                                                                            \
    ((TrickyState*)(state))->cooldownB.f = z;                                                                          \
    ((TrickyState*)(state))->stateFlags =                                                                              \
        ((TrickyState*)(state))->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;                                  \
    ((TrickyState*)(state))->stateFlags =                                                                              \
        ((TrickyState*)(state))->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;                                  \
    ((TrickyState*)(state))->stateFlags = ((TrickyState*)(state))->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;  \
    ((TrickyState*)(state))->stateFlags = ((TrickyState*)(state))->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST; \
    ((TrickyState*)(state))->commandPhase = -1

#define TRICKY_VOICE(obj, sfx, vol)                                                                                    \
    {                                                                                                                  \
        st = ((GameObject*)obj)->extra;                                                                                \
        if (st->soundSuppressed == 0) {                                                                                \
            if (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29) {         \
                if (Sfx_IsPlayingFromObjectChannel((GameObject*)(obj), 0x10) == 0) {                                   \
                    objSoundStartTimed((GameObject*)(obj), &st->soundState, (sfx), (vol), 0xffffffff, 0);              \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

#define TRICKY_SPAWN_FOOD_BUBBLE(obj, state)                                                                           \
    if (((TrickyState*)(state))->child == NULL) {                                                                      \
        ObjPlacement* setup_;                                                                                          \
        s8 used_[4];                                                                                                   \
        int slot_;                                                                                                     \
        setup_ = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_FOOD);                                                    \
        used_[0] = -1;                                                                                                 \
        used_[1] = -1;                                                                                                 \
        used_[2] = -1;                                                                                                 \
        if (((TrickyState*)(state))->childA != NULL) {                                                                 \
            used_[((TrickyState*)(state))->packedSlots.promptASlot] = 1;                                               \
        }                                                                                                              \
        if (((TrickyState*)(state))->childB != NULL) {                                                                 \
            used_[((TrickyState*)(state))->packedSlots.promptBSlot] = 1;                                               \
        }                                                                                                              \
        if (((TrickyState*)(state))->child != NULL) {                                                                  \
            used_[((TrickyState*)(state))->packedSlots.zzzSlot] = 1;                                                   \
        }                                                                                                              \
        if (used_[0] == -1) {                                                                                          \
            slot_ = 0;                                                                                                 \
        } else if (used_[1] == -1) {                                                                                   \
            slot_ = 1;                                                                                                 \
        } else if (used_[2] == -1) {                                                                                   \
            slot_ = 2;                                                                                                 \
        } else if (used_[3] == -1) {                                                                                   \
            slot_ = 3;                                                                                                 \
        } else {                                                                                                       \
            slot_ = -1;                                                                                                \
        }                                                                                                              \
        ((TrickyState*)(state))->packedSlots.zzzSlot = slot_;                                                          \
        ((TrickyState*)(state))->child = objSetupObject(setup_, 4, -1, -1, ((GameObject*)(obj))->anim.parent);         \
        ObjLink_AttachChild((GameObject*)(obj), ((TrickyState*)(state))->child,                                        \
                            ((TrickyState*)(state))->packedSlots.zzzSlot);                                             \
        z = 0.0f;                                                                                                      \
        ((TrickyState*)(state))->childPhaseTimer0 = z;                                                                 \
        ((TrickyState*)(state))->childPhaseTimer1 = z;                                                                 \
        ((TrickyState*)(state))->childPhaseTimer2 = z;                                                                 \
    }

void Tricky_update(GameObject* obj) {
    char* base;
    int state;
    TrickyState* trickyState;
    int found;
    int sfxId;
    TrickyState* st;
    struct {
        int index;
    } childLoop;
    int i;
    int ref;
    ObjPlacement* setup;
    int count;
    u32 flags;
    GameObject* step;
    int played;
    int talking;
    f32* target;
    f32 z;
    f32 mp;
    u8 blockFlags[120];
    TrickyItemIdList cmdQuery;
    TrickySfxPair pair;

    base = gTrickyDebugStringTable;
    state = (int)((GameObject*)obj)->extra;
    trickyState = (TrickyState*)state;
    found = 0;
    cmdQuery = gTrickyCmdQueryInit;
    pair = sTrickyImpressSfxPair;
    Objfsa_UpdateWalkGroupPatches();
    if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && (void*)trickyState->spawnedChild == NULL &&
        Obj_IsLoadingLocked()) {
        mapGetLoadedMapFlags(blockFlags);
        if (blockFlags[0xd] != 0) {
            setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_A);
        } else {
            setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_B);
        }
        trickyState->spawnedChild =
            (void*)objSetupObject((ObjPlacement*)setup, 4, -1, -1, ((GameObject*)obj)->anim.parent);
        ObjLink_AttachChild((GameObject*)obj, trickyState->spawnedChild, 3);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FEED_VOICE_PENDING_U32) != 0) {
        u8* voiceCursor = *(u8**)state;

        if (*voiceCursor == *(voiceCursor + 1)) {
            TRICKY_VOICE(obj, 0x364, 0x500);
        } else {
            TRICKY_VOICE(obj, 0x363, 0x500);
        }
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_FEED_VOICE_PENDING;
    }
    {
        int flagsByte = trickyState->flags358;
        trickyDebugPrint(base + TRICKY_DBG_SIDECOMMAND_HITS, flagsByte & 1, flagsByte & 2, flagsByte & 4, flagsByte & 8,
                         flagsByte & 0x10, flagsByte & 0x20, flagsByte & 0x40, flagsByte & 0x80);
    }
    {
        u8* debugCursor = *(u8**)state;

        trickyDebugPrint(base + TRICKY_DBG_SIDECOMMAND_ENERGY, *debugCursor, *(debugCursor + 1));
    }
    if ((trickyState->stateFlags & 0x200) != 0) {
        ObjHits_EnableObject((GameObject*)obj);
        if ((trickyState->stateFlags & 0x4000) == 0) {
            TRICKY_RESET_COMMAND(state);
            trickyState->movementState = TRICKY_MOVE_WALK_WAIT;
            trickyState->prevSpeed = z;
            trickyState->speed = z;
            trickyState->homePosX = ((GameObject*)obj)->anim.worldPosX;
            trickyState->homePosY = ((GameObject*)obj)->anim.worldPosY;
            trickyState->homePosZ = ((GameObject*)obj)->anim.worldPosZ;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            if (((GameObject*)obj)->anim.currentMove == 8 || ((GameObject*)obj)->anim.currentMove == 7) {
                trickyState->waterLevel = gTrickyEventStaleSeconds;
                trickyState->eventTime = -10000.0f;
            } else {
                trickyState->waterLevel = 0.0f;
            }
        }
        *(s32*)&trickyState->stateFlags &= ~0x4201;
        if (trickyState->flag82EBit5 != 0) {
            trickyState->flag82EBit5 = 0;
        } else {
            trickyState->blendPending = 1;
        }
    }
    if (trickyState->followObj != NULL && (trickyState->followObj->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->groundSnapCounter = 2;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            ((GameObject*)obj)->anim.localPosX = trickyState->homePosX;
            ((GameObject*)obj)->anim.localPosY = trickyState->homePosY;
            ((GameObject*)obj)->anim.localPosZ = trickyState->homePosZ;
            ((GameObject*)obj)->anim.worldPosX = trickyState->homePosX;
            ((GameObject*)obj)->anim.worldPosY = trickyState->homePosY;
            ((GameObject*)obj)->anim.worldPosZ = trickyState->homePosZ;
            ObjHits_SyncObjectPosition((GameObject*)obj);
            childLoop.index = 0;
            trickyState->movementState = childLoop.index;
            z = 0.0f;
            trickyState->prevSpeed = z;
            trickyState->speed = z;
            trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_WARP_RETURNED;
            trickyState->stateFlags &= ~(u64)0x2000;
            if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                u8* childCursor;

                trickyState->stateFlags = trickyState->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                childCursor = (u8*)state;
                for (; childLoop.index < 7; childCursor += 4, childLoop.index++) {
                    objSetAnimSpeedTo1(((TrickyState*)childCursor)->flameChildren[0]);
                }
                Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                TRICKY_VOICE(obj, 0x29d, 0);
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trwhin1);
        }
        TRICKY_RESET_COMMAND(state);
        trickyState->followObj = NULL;
    }
    {
        int cmd;

        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0 &&
            (*gGameUIInterface)->isItemBeingUsed(0xc1) != 0) {
            cmd = 0;
        } else {
            cmd = (*gGameUIInterface)->isOneOfItemsBeingUsed(cmdQuery.ids, TRICKY_ITEM_ID_COUNT);
        }
        ref = state;
        count = trickyState->commandCount;
        for (i = 0; i < count; i++, ref += 8) {
            if (TRICKY_COMMAND_FROM_STATE_BASE(ref)->type == cmd) {
                found = 1;
                break;
            }
        }
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0 &&
            trickyShouldGoToWarpPoint((GameObject*)obj, (TrickyState*)state) == 2) {
            trickyState->stateIndex = TRICKY_STATE_GO_TO_WARP_POINT;
        } else if (trickyState->stateIndex == TRICKY_STATE_GUARD && cmd == 4) {
            *(u8*)&trickyState->wanderTargetZ = *(u8*)&trickyState->wanderTargetZ ^ 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_CIRCLING && cmd == 4 && found == 0) {
            trickyState->stateWord728 = 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_GROWL && cmd == 4) {
            trickyState->stateWord728 = 1;
        } else if (cmd == 0) {
            trickyState->stateFlags |= TRICKY_STATE_HEEL_RECALL_REQUEST_FLAGS;
        } else {
            flags = trickyState->stateFlags;
            if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                switch (cmd) {
                case 1:
                    trickyState->commandPhase = 1;
                    trickySelectQueuedCommandTarget(trickyState, 1);
                    TRICKY_VOICE(obj, 0x13c, 0);
                    switch (trickyState->followObj->anim.romDefNo) {
                    case 0x1ca:
                        if (**(u8**)state < 4) {
                            if (Obj_IsLoadingLocked()) {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case 0x160:
                        if (**(u8**)state < 4) {
                            if (Obj_IsLoadingLocked()) {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_DIG_TUNNEL;
                        }
                        break;
                    case 0x6a:
                    case 0x193:
                    case 0x3fb:
                    case 0x658:
                        trickyState->stateIndex = TRICKY_STATE_MOVE_TO_FOLLOW_TARGET;
                        break;
                    case 0x195:
                        if (**(u8**)state < 2) {
                            if (Obj_IsLoadingLocked()) {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_TRACK_TUMBLEWEED;
                        }
                        break;
                    case 0x352:
                        if (**(u8**)state < 4) {
                            if (Obj_IsLoadingLocked()) {
                                trickyState->stateFlags |= 4;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case 0x358:
                        trickyState->stateIndex = TRICKY_STATE_GROWL;
                        break;
                    default:
                        TRICKY_RESET_COMMAND(state);
                        trickyReportError(base + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                        break;
                    }
                    break;
                case 3:
                    played = 0;
                    if (trickyState->commandPhase == 3) {
                        ref = state;
                        count = trickyState->commandCount;
                        for (i = 0; i < count; i++, ref += 8) {
                            if (TRICKY_COMMAND_FROM_STATE_BASE(ref)->type == 3) {
                                played = 1;
                            }
                        }
                    } else {
                        played = 1;
                    }
                    if (played != 0) {
                        trickyState->commandPhase = 3;
                        if (trickySelectQueuedCommandTarget(trickyState, 3) != 0) {
                            switch (trickyState->followObj->anim.romDefNo) {
                            case 0x36:
                            case 0x104:
                            case 0x131:
                            case 0x19f:
                            case 0x26c:
                            case 0x475:
                            case 0x546:
                            case 0x7c3:
                                trickyState->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                                trickyState->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
                                break;
                            case 0x6f0:
                                trickyState->stateIndex = TRICKY_STATE_GROWL;
                                break;
                            default:
                                trickyState->stateIndex = TRICKY_STATE_GUARD;
                                break;
                            }
                        } else {
                            trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                        }
                    }
                    break;
                case 4:
                    if (**(u8**)state < 4) {
                        if (Obj_IsLoadingLocked()) {
                            trickyState->stateFlags |= 4;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                        }
                    } else {
                        trickyState->commandPhase = 4;
                        trickySelectQueuedCommandTarget(trickyState, 4);
                        trickyState->stateIndex = TRICKY_STATE_FLAME;
                        switch (trickyState->followObj->anim.romDefNo) {
                        case 0x1c9:
                            trickyState->actionCallback = dimicewall_countdownCallback;
                            break;
                        case 0x718:
                            trickyState->actionCallback = dimtruthhornice_countdownCallback;
                            break;
                        case 0x551:
                            trickyState->actionCallback = vfpflamepoint_countdownCallback;
                            break;
                        case 0x191:
                            trickyState->actionCallback = dimlogfire_countdownCallback;
                            break;
                        case 0x470:
                            trickyState->actionCallback = drchimmey_countdownCallback;
                            break;
                        case 0x102:
                        case 0x194:
                        case 0x542:
                        case 0x54c:
                        case 0x6f9:
                            trickyState->actionCallback = NULL;
                            break;
                        case 0x3c:
                            trickyState->actionCallback = (TrickyActionCallback)sh_beacon_resetFadeTimerCallback;
                            break;
                        case 0x50f:
                            trickyState->actionCallback = (TrickyActionCallback)wcbeacon_aButtonCallback;
                            break;
                        default:
                            TRICKY_RESET_COMMAND(state);
                            trickyReportError(base + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                            break;
                        }
                    }
                    break;
                case 5:
                    if (Obj_IsLoadingLocked()) {
                        trickyState->commandPhase = 5;
                        setup = Obj_AllocObjectSetup(0x18, TRICKY_CHILD_OBJ_SIDEKICK_BALL);
                        setup->color[3] = 0xff;
                        setup->color[0] = 2;
                        setup->posX = ((GameObject*)obj)->anim.worldPosX;
                        setup->posY = ((GameObject*)obj)->anim.worldPosY;
                        setup->posZ = ((GameObject*)obj)->anim.worldPosZ;
                        trickyState->followObj =
                            objSetupObject((ObjPlacement*)setup, 5, -1, -1, ((GameObject*)obj)->anim.parent);
                        target = &trickyState->followObj->anim.worldPosX;
                        if (trickyState->targetPosPtr != target) {
                            trickyState->targetPosPtr = target;
                            {
                                u32 mask;
                                u32 flags = trickyState->stateFlags;
                                mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                                trickyState->stateFlags = flags & mask;
                            }
                            trickyState->linkedWalkGroup = 0;
                        }
                        trickyState->substate = 0;
                        trickyState->stateIndex = TRICKY_STATE_FETCH_BALL;
                    }
                    break;
                default:
                    if (trickyState->stateIndex == TRICKY_STATE_FOLLOW_PLAYER && trickyState->commandPhase != 0 &&
                        (flags & TRICKY_STATE_FLAG_HEEL_REQUEST) == 0) {
                        step = trickyFindNearestUsableBaddie(trickyState->playerObj, 150.0f, 0);
                        if (step != NULL) {
                            trickyState->followObj = step;
                            if (trickyState->targetPosPtr != &step->anim.worldPosX) {
                                trickyState->targetPosPtr = &step->anim.worldPosX;
                                {
                                    u32 mask;
                                    u32 flags = trickyState->stateFlags;
                                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                                    trickyState->stateFlags = flags & mask;
                                }
                                trickyState->linkedWalkGroup = 0;
                            }
                            trickyState->stateIndex = TRICKY_STATE_CIRCLING;
                            trickyState->substate = 0;
                            trickyState->stateWord728 = 0;
                        }
                    }
                    break;
                }
            } else if (cmd == 3) {
                trickyState->stateFlags = flags | (u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            }
        }
    }
    flags = trickyState->stateFlags;
    if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if ((flags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) {
            if ((flags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
                TRICKY_RESET_COMMAND(state);
                trickyState->commandPhase = 0;
            } else {
                TRICKY_RESET_COMMAND(state);
            }
            trickyState->cooldownA = 1200.0f;
        } else if ((flags & TRICKY_STATE_FLAG_GUARD_REQUEST) != 0) {
            trickyState->followObj = (GameObject*)obj;
            trickyState->stateIndex = TRICKY_STATE_IDLE_WANDER;
            trickyState->idleSfxTimer = (f32)(int)randomGetRange(0x1f4, 0x2ee);
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_RESET_FLAG_40000;
                trickyState->stateFlags = flags & mask;
            }
            trickyState->commandPhase = 3;
            if (trickyState->targetPosPtr != &trickyState->wanderTargetX) {
                trickyState->targetPosPtr = &trickyState->wanderTargetX;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_TARGET_DIRTY_FLAG;
                    trickyState->stateFlags = flags & mask;
                }
                trickyState->linkedWalkGroup = 0;
            }
        }
    }
    ((GameObject*)obj)->anim.resetHitboxFlags = ((GameObject*)obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    trickyState->heightUpdateActive = 1;
    ((TrickyHandlerFn*)(base + TRICKY_HANDLER_TABLE_OFFSET))[trickyState->stateIndex](obj, (void*)state);
    trickyState->stateFlags &= ~(u64)0x2;
    trickyState->animTransitionTimer += timeDelta;
    if (trickyState->animTransitionTimer > 15.0f) {
        if (((GameObject*)obj)->anim.currentMove != trickyState->moveId) {
            if ((trickyState->pendingStateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0 &&
                (trickyState->stateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0) {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, ((GameObject*)obj)->anim.currentMoveProgress, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, 0.0f, 0);
            }
            trickyState->stateFlags &= ~TRICKY_MOVE_ACTIVE_FLAG_MASK;
            trickyState->stateFlags |= trickyState->pendingStateFlags;
            trickyState->animTransitionTimer = 0.0f;
            trickyState->moveProgress = trickyState->moveProgressTarget;
        }
    }
    if ((trickyState->stateFlags & TRICKY_MOVE_FLAG_ROOT_TRANSLATE) != 0) {
        ((GameObject*)obj)->anim.localPosX += timeDelta * (trickyState->dirX * trickyState->speed);
        ((GameObject*)obj)->anim.localPosZ += timeDelta * (trickyState->dirZ * trickyState->speed);
        ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, trickyState->speed, &trickyState->moveProgress);
    }
    mp = trickyState->moveProgress;
    z = 0.0f;
    if (mp == z) {
        ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, trickyState->arcMoveProgress);
    }
    if (ObjAnim_AdvanceCurrentMove(obj, trickyState->moveProgress, timeDelta, (void*)&trickyState->animEvents) != 0) {
        trickyState->stateFlags |= TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE;
    } else {
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_ROTATE) != 0) {
        int rotationDiff;
        int rotationStep;

        rotationDiff = trickyState->targetYaw - (u16)((GameObject*)obj)->anim.rotX;
        if (rotationDiff > 0x8000) {
            rotationDiff -= 0xffff;
        }
        if (rotationDiff < -0x8000) {
            rotationDiff += 0xffff;
        }
        rotationStep = (int)((f32)trickyState->animEvents.rootPitch * trickyState->rotStepScale);
        if ((rotationDiff >= 0 ? rotationDiff : -rotationDiff) >= 4) {
            if ((rotationStep > 0 && rotationDiff > 0) || (rotationStep < 0 && rotationDiff < 0)) {
                if ((rotationStep >= 0 ? rotationStep : -rotationStep) >
                    (rotationDiff >= 0 ? rotationDiff : -rotationDiff)) {
                    ((GameObject*)obj)->anim.rotX += rotationDiff;
                } else {
                    ((GameObject*)obj)->anim.rotX += rotationStep;
                }
            } else {
                ((GameObject*)obj)->anim.rotX += rotationStep;
            }
        } else {
            ((GameObject*)obj)->anim.rotX += rotationDiff;
        }
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_BACKSTEP) != 0) {
        ((GameObject*)obj)->anim.localPosX +=
            trickyState->backstepDelta * (trickyState->dirX * -trickyState->animEvents.rootDeltaZ);
        ((GameObject*)obj)->anim.localPosZ +=
            trickyState->backstepDelta * (trickyState->dirZ * -trickyState->animEvents.rootDeltaZ);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_VERTICAL_MOVE) != 0) {
        ((GameObject*)obj)->anim.localPosY += trickyState->animEvents.rootDeltaY * trickyState->verticalDelta;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SIDESTEP) != 0) {
        ((GameObject*)obj)->anim.localPosX +=
            trickyState->sidestepDelta * (trickyState->dirZ * trickyState->animEvents.rootDeltaX);
        ((GameObject*)obj)->anim.localPosZ +=
            trickyState->sidestepDelta * (trickyState->dirX * -trickyState->animEvents.rootDeltaX);
    }
    if (trickyState->followObj != NULL) {
        trickyState->eyeAnimState.lookAtActive = 1;
        trickyState->eyeAnimState.lookAtPosX = trickyState->followObj->anim.worldPosX;
        trickyState->eyeAnimState.lookAtPosY = trickyState->followObj->anim.worldPosY;
        trickyState->eyeAnimState.lookAtPosZ = trickyState->followObj->anim.worldPosZ;
    } else {
        trickyState->eyeAnimState.lookAtActive = 0;
    }
    if (((GameObject*)obj)->anim.currentMove == 0x2a) {
        characterHeadLookRelax((GameObject*)(obj), &trickyState->eyeAnimState);
        characterCloseEyes((GameObject*)(obj), &trickyState->eyeAnimState);
    } else {
        characterUpdateHeadLook((GameObject*)obj, &trickyState->eyeAnimState, 0.0f);
        characterDoEyeAnims((GameObject*)obj, &trickyState->eyeAnimState);
    }
    objSoundUpdateMouth((GameObject*)obj, &trickyState->soundState);
    {
        f32* pathCursor;
        TrickyState* pathState;

        pathState = ((GameObject*)obj)->extra;
        pathCursor = pathState->targetPosPtr;
        pathState->previousPathPoint = pathCursor;
        if (pathState->previousPathPoint != NULL) {
            pathState->previousPathX = pathCursor[0];
            pathState->previousPathY = pathCursor[1];
            pathState->previousPathZ = pathCursor[2];
        }
    }
    trickyState->prevSpeed = trickyState->speed;
    i = trickyState->commandCount - 1;
    {
        u8* cur = (u8*)state + i * 8;

        for (; i >= 0; cur -= sizeof(TrickyCommand), i--) {
            TRICKY_COMMAND_TTL_FROM_STATE_BASE(cur) -= 1;
            if (TRICKY_COMMAND_TTL_FROM_STATE_BASE(cur) == 0) {
                memmove(TRICKY_COMMAND_FROM_STATE_BASE(cur),
                        TRICKY_COMMAND_FROM_STATE_BASE(state + (i + 1) * sizeof(TrickyCommand)),
                        (trickyState->commandCount - i - 1) * sizeof(TrickyCommand));
                trickyState->commandCount -= 1;
            }
        }
    }
    if (getXZDistanceSquared(&((GameObject*)obj)->anim.worldPosX, &trickyState->playerObj->anim.worldPosX) >=
            360000.0f &&
        mainGetBit(GAMEBIT_Tricky_Usable) != 0) {
        trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    trickyState->cooldownC -= timeDelta;
    if (trickyState->cooldownC < 0.0f) {
        trickyState->cooldownC = 0.0f;
    }
    if ((trickyState->stateFlags & 4) != 0) {
        st = ((GameObject*)obj)->extra;
        if (st->soundSuppressed != 0) {
            played = 0;
        } else {
            switch (((GameObject*)obj)->anim.currentMove) {
            case 0x29:
            case 0x2a:
            case 0x2b:
            case 0x2c:
            case 0x2d:
            case 0x2e:
            case 0x2f:
                played = 0;
                break;
            default:
                if (Sfx_IsPlayingFromObjectChannel((GameObject*)obj, 0x10) != 0) {
                    played = 0;
                } else {
                    objSoundStartTimed((GameObject*)obj, &st->soundState, 0x298, 0x500, 0xffffffff, 0);
                    played = 1;
                }
                break;
            }
        }
        if (played != 0) {
            trickyState->stateFlags &= ~(u64)0x4;
        }
    }
    trickyState->voiceCooldown -= timeDelta;
    if (trickyState->voiceCooldown < 0.0f) {
        trickyState->voiceCooldown = 0.0f;
    }
    if (trickyState->voiceCooldown > 0.0f) {
        TRICKY_VOICE(obj, 0x29c, 0x100);
    }
    trickyUpdateCollisionAndPathState(obj);
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_IMPRESS_PENDING_U32) != 0) {
        trickyState->impressTimer -= timeDelta;
        if (trickyState->impressTimer <= 0.0f) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_IMPRESS_PENDING_U32;
            sfxId = ((u16*)&pair)[randomGetRange(0, 1)];
            TRICKY_VOICE(obj, sfxId, 0x500);
        }
    }
    tricky_updateModelVariantFade((GameObject*)obj, (TrickyState*)state);
    Tricky_updateBlendChannelWeight((GameObject*)obj, (TrickyState*)state);
    if (trickyState->speed > 0.2f) {
        objAudioDispatchAnimEvents((GameObject*)obj, &trickyState->animEvents, 1, trickyState->footPoints,
                                   &trickyState->pathControlFlags, trickyState->speed, 1.0f);
    }
    if (0.0f == trickyState->waterLevel) {
        talking = 0;
    } else if (gTrickyEventTimeSentinel == trickyState->eventTime) {
        talking = 1;
    } else if (trickyState->currentTime - trickyState->eventTime > gTrickyEventStaleSeconds) {
        talking = 1;
    } else {
        talking = 0;
    }
    if (talking != 0) {
        ObjAnimEventList* events;
        int sfx2;

        events = &trickyState->animEvents;
        sfx2 = 0;
        for (i = 0, count = events->triggerCount; i < count; i++) {
            switch (events->triggeredIds[i]) {
            case 0:
            case 1:
            case 2:
                sfx2 = 0x433;
                break;
            }
        }
        if (sfx2 != 0) {
            Sfx_PlayFromObject(obj, (u16)sfx2);
        }
    }
    trickyState->prevLocalPosX = ((GameObject*)obj)->anim.previousLocalPosX;
    trickyState->prevLocalPosY = ((GameObject*)obj)->anim.previousLocalPosY;
    trickyState->prevLocalPosZ = ((GameObject*)obj)->anim.previousLocalPosZ;
    if ((void*)trickyState->child != NULL) {
        trickyState->childPhaseTimer0 += timeDelta;
        trickyState->childPhaseTimer1 += timeDelta;
        trickyState->childPhaseTimer2 += timeDelta;
        if (trickyState->childPhaseTimer2 > 30.0f) {
            trickyState->childPhaseTimer2 -= 30.0f;
        }
        if (trickyState->childPhaseTimer2 >= 20.0f) {
            trickyState->child->anim.flags = trickyState->child->anim.flags | 0x4000;
        } else {
            trickyState->child->anim.flags = trickyState->child->anim.flags & ~0x4000;
        }
        if (trickyState->childPhaseTimer1 > 150.0f) {
            if (trickyState->childPhaseTimer1 > TRICKY_TIMER_600_FRAMES) {
                trickyState->childPhaseTimer1 -= TRICKY_TIMER_600_FRAMES;
            }
            trickyState->child->anim.flags = trickyState->child->anim.flags | 0x4000;
        }
        if (trickyState->childPhaseTimer0 > 2400.0f) {
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                TRICKY_VOICE(obj, 0x392, 0x500);
            } else {
                TRICKY_VOICE(obj, 0x298, 0x500);
            }
            trickyState->childPhaseTimer0 -= 2400.0f;
        }
        ObjAnim_AdvanceCurrentMove(trickyState->child, 0.01f, timeDelta, 0);
    }
    if ((void*)trickyState->childB != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->childB, 0.01f, timeDelta, 0);
    }
    if ((void*)trickyState->childA != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->childA, 0.01f, timeDelta, 0);
    }
}

void Tricky_init(GameObject* obj) {
    TrickyState* state;
    ObjModel* model;
    int pathState;
    u32 modelVariant;
    u16 startPath[4];

    state = obj->extra;
    startPath[0] = gTrickyInitialPathControlStartId[0];
    mainSetBits(GAMEBIT_TrickyTalk, 0xff);
    if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
        mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 1);
    }
    (obj)->animEventCallback = tricky_SeqFn;
    objAddObjectType(obj, TRICKY_OBJGROUP);
    pathSearchInit(&state->pathSearches[0]);
    pathSearchInit(&state->pathSearches[1]);
    pathSearchInit(&state->pathSearches[2]);
    pathSearchInit(&state->pathSearches[3]);
    pathSearchInit(&state->pathSearches[4]);
    pathSearchInit(&state->pathSearches[5]);
    pathSearchInit(&state->pathSearches[6]);
    pathSearchInit(&state->pathSearches[7]);
    pathSearchInit(&state->pathSearches[8]);
    state->progressPtr = (*gMapEventInterface)->getTrickyEnergy();
    state->playerObj = Obj_GetPlayerObject();
    state->stateIndex = TRICKY_STATE_ATTACH_TO_WALKGROUP;
    state->commandRequestBits = 0;
    state->previousPathPoint = NULL;
    state->activeWalkGroup = 0;
    state->homePosX = (obj)->anim.worldPosX;
    state->homePosY = (obj)->anim.worldPosY;
    state->homePosZ = (obj)->anim.worldPosZ;
    modelVariant = state->progressPtr[2] / 10;
    state->modelVariant = modelVariant;
    model = Obj_GetActiveModel(obj);
    model->textureRefs->swapSelector = state->modelVariant;
    pathState = (int)&state->pathControlFlags;
    (*gPathControlInterface)->init((void*)pathState, 1, 0xa7, 1);
    (*gPathControlInterface)
        ->setLocalPointCollision((void*)pathState, 1, gTrickyPathPointCollision, &gTrickyPathPointCollisionRadius, 2);
    (*gPathControlInterface)
        ->setup((void*)pathState, 2, gTrickyDebugStringTable, gTrickyPathControlSetupParams, startPath);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)pathState);
    doNothing_onTrickyInit();
    Objfsa_UpdateWalkGroupPatches();
    state->groundSnapCounter = 2;
    state->blendPending = 1;
    state->commandPhase = -1;
}

void trickyReportError(const char* fmt, ...) {
}

void trickyDebugPrint(const char* fmt, ...) {
}

/* pooled sidekick-command debug format strings (embedded NULs), raw bytes. */
char sSidekickCommandDebugTextBlock[] = {
    0x73, 0x69, 0x64, 0x65, 0x43, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x20,
    0x77, 0x61, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x69,
    0x6E, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x20, 0x4D, 0x41, 0x58, 0x5F, 0x43, 0x4F, 0x4D, 0x4D, 0x5F, 0x50,
    0x52, 0x45, 0x53, 0x45, 0x4E, 0x54, 0x0A, 0x00, 0x00, 0x00, 0x68, 0x69, 0x74, 0x73, 0x3A, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64, 0x20, 0x25, 0x64,
    0x20, 0x25, 0x64, 0x00, 0x00, 0x00, 0x0A, 0x45, 0x6E, 0x65, 0x72, 0x67, 0x79, 0x3A, 0x20, 0x25, 0x64, 0x2F,
    0x25, 0x64, 0x0A, 0x00, 0x66, 0x69, 0x6E, 0x64, 0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x20, 0x75,
    0x73, 0x65, 0x64, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77, 0x72, 0x6F, 0x6E, 0x67, 0x20, 0x6F,
    0x62, 0x6A, 0x65, 0x63, 0x74, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const u32 gTrickyLiteralPoolPadding = 0;
