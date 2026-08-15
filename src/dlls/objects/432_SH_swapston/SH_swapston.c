/*
 * SH_swapston (DLL 0x1B0) - the talking WarpStone hub object.
 *
 * It runs the WarpStone's idle/look-at-target animation behaviour,
 * drives the warp menu sequence that lets the player pick a destination,
 * and renders the player model standing on the stone during the menu.
 */

#include "dlls/objects/432_SH_swapston.h"

#include "dolphin/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_sequence_api.h"
#include "main/mapEvent.h"
#include "main/map_load.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/pad.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/shader_api.h"
#include "main/textrender_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/mapEventTypes.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/player_api.h"
#include "main/dll/player_spirit_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/stream_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx_stop_object_api.h"

union WarpStoneAnimEvents {
    ObjAnimEventList list;
    u8 pad[0x20];
} gWarpStoneObjAnimEvents;
extern int lbl_803DC050;

/*
 * scchieflightfoot - Thorntail dust/sand effect spawner.
 *
 * Provides warpstone_updateDustEffects, called by the WarpStone sequence
 * handler. While the runtime's dust state is ACTIVE, the free-running
 * state->dustEffectTimer advances by timeDelta each frame and sweeps through
 * phases keyed off the
 * tuning thresholds in .sdata2 (0, 120, 360, 420, 480 frames):
 *   - rising:  randomly emit small dust puffs (effect 0x7ca)
 *   - 120..360: also emit a growing ground cloud (0x7d2) and arm the burst
 *   - 360..420: on the armed burst, emit 15 large cloud puffs
 *   - 420..480: hold
 *   - >=480:    reset the timer and clear the ACTIVE flag
 * Spawn probability is gated by randomGetRange against the timer scaled by
 * the tuning floats. All effects are parented to the player object.
 */

typedef struct WarpStoneDustEffectParams {
    s16 flags;
    s16 count;
    s16 effectType;
    s16 radius;
    f32 scale;
    Vec position;
} WarpStoneDustEffectParams;

#define DUST_PUFF_EFFECT_ID             0x7ca
#define DUST_CLOUD_EFFECT_ID            0x7d2
#define DUST_PUFF_PARAM_TYPE            0xc0e
#define DUST_SPAWN_CHANCE_RANGE         0x1e0
#define DUST_BURST_PUFF_COUNT           0xf
#define WARPSTONE_DUST_FLAG_BURST_READY 0x02
#define WARPSTONE_DUST_FLAG_ACTIVE      0x04

ObjectDescriptor gWarpStoneObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)warpstone_initialise,
    (ObjectDescriptorCallback)warpstone_release,
    0,
    (ObjectDescriptorCallback)warpstone_init,
    (ObjectDescriptorCallback)warpstone_update,
    (ObjectDescriptorCallback)warpstone_hitDetect,
    (ObjectDescriptorCallback)warpstone_render,
    (ObjectDescriptorCallback)warpstone_free,
    (ObjectDescriptorCallback)warpstone_getObjectTypeId,
    warpstone_getExtraSize,
};

void warpstone_updateDustEffects(GameObject* obj) {
    void* playerObj;
    WarpStoneState* state;
    int burstCount;
    WarpStoneDustEffectParams effectParams;

    playerObj = Obj_GetPlayerObject();
    state = obj->extra;
    effectParams.position.x = 0.0f;
    effectParams.position.y = 55.0f;
    effectParams.position.z = 0.0f;
    effectParams.effectType = DUST_PUFF_PARAM_TYPE;
    effectParams.count = 1;
    if ((state->dustEffectFlags & WARPSTONE_DUST_FLAG_ACTIVE) != 0) {
        if (state->dustEffectTimer < 120.0f) {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < state->dustEffectTimer / 2.0f) {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
        } else if (state->dustEffectTimer < 360.0f) {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < state->dustEffectTimer / 3.0f) {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            effectParams.radius = 0x28;
            effectParams.flags = 0;
            effectParams.scale = 0.0009f * ((state->dustEffectTimer - 120.0f) / 240.0f);
            (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
            state->dustEffectFlags = state->dustEffectFlags | WARPSTONE_DUST_FLAG_BURST_READY;
        } else if (state->dustEffectTimer < 420.0f) {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < state->dustEffectTimer / 2.0f) {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            if ((state->dustEffectFlags & WARPSTONE_DUST_FLAG_BURST_READY) != 0) {
                state->dustEffectFlags = state->dustEffectFlags & ~WARPSTONE_DUST_FLAG_BURST_READY;
                effectParams.radius = 0x46;
                effectParams.scale = 0.00036f;
                for (burstCount = DUST_BURST_PUFF_COUNT; (u8)burstCount != 0; burstCount--) {
                    (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
                }
            }
        } else if (!(state->dustEffectTimer < 480.0f)) {
            state->dustEffectTimer = 0.0f;
            state->dustEffectFlags = state->dustEffectFlags & ~WARPSTONE_DUST_FLAG_ACTIVE;
        }
        state->dustEffectTimer = state->dustEffectTimer + timeDelta;
    }
}

/*
 * sclantern - hanging lantern objects used in SharpClaw-themed areas.
 * warpstone_advanceAnimEvents drives the animation each frame: it fires
 * spark particle SFX at left/right attachment points (path points 0 and 1)
 * on events 1-4, and plays a swing SFX on event 9. Sparks are suppressed
 * during the early frames of move WARPSTONE_SPARK_SUPPRESS_MOVE (0x1b).
 * warpstoneProbePlayerAnimState probes the current player's anim-state flags.
 */

#define WARPSTONE_EVENT_LEFT_SPARK_A  1
#define WARPSTONE_EVENT_RIGHT_SPARK_A 2
#define WARPSTONE_EVENT_LEFT_SPARK_B  3
#define WARPSTONE_EVENT_RIGHT_SPARK_B 4
#define WARPSTONE_EVENT_LANTERN_SWING 9
#define WARPSTONE_SPARK_SFX_ID        0x415
#define WARPSTONE_SPARK_SUPPRESS_MOVE 0x1b

u32 warpstone_advanceAnimEvents(GameObject* lantern, f32 moveStepScale) {
    u32 advanceResult;
    int pointIndex;
    int i;
    float posZ;
    float posY;
    float posX;

    pointIndex = 0;
    gWarpStoneObjAnimEvents.list.triggerCount = 0;
    gWarpStoneObjAnimEvents.list.rootCurveValid = 0;
    advanceResult = ObjAnim_AdvanceCurrentMove(lantern, moveStepScale, timeDelta, &gWarpStoneObjAnimEvents.list);
    if (gWarpStoneObjAnimEvents.list.rootCurveValid != 0) {
        lantern->anim.rotX += gWarpStoneObjAnimEvents.list.rootPitch;
    }
    i = 0;
    while (i < gWarpStoneObjAnimEvents.list.triggerCount) {
        switch (gWarpStoneObjAnimEvents.list.triggeredIds[i]) {
        case WARPSTONE_EVENT_LEFT_SPARK_A:
            pointIndex = 1;
            break;
        case WARPSTONE_EVENT_RIGHT_SPARK_A:
            pointIndex = 2;
            break;
        case WARPSTONE_EVENT_LEFT_SPARK_B:
            pointIndex = 1;
            break;
        case WARPSTONE_EVENT_RIGHT_SPARK_B:
            pointIndex = 2;
            break;
        case WARPSTONE_EVENT_LANTERN_SWING:
            Sfx_PlayFromObject(lantern, SFXTRIG_swapstone_move_short);
            break;
        case 0:
        case 5:
        case 6:
        case 7:
        case 8:
        default:
            break;
        }
        i++;
    }
    if (pointIndex != 0) {
        ObjPath_GetPointWorldPosition(lantern, pointIndex - 1, &posX, &posY, &posZ, 0);
        if (!((lantern->anim.currentMove == WARPSTONE_SPARK_SUPPRESS_MOVE) &&
              (lantern->anim.currentMoveProgress < 0.8f))) {
            Sfx_PlayAtPositionFromObject(lantern, posX, posY, posZ, WARPSTONE_SPARK_SFX_ID);
        }
    }
    return advanceResult;
}

int lbl_803DDBF4;

u32 warpstoneProbePlayerAnimState(void) {
    u32 playerObj;

    (*gMapEventInterface)->getCurChar();
    playerObj = (u32)Obj_GetPlayerObject();
    objGetAnimStateFlags((GameObject*)playerObj, 0xff);
    return 2;
}

int warpstone_testEvent(u32 obj, u32 unused, int option) {
    s8 horizontal;
    s8 vertical;

    Obj_GetPlayerObject();
    padGetAnalogInput(0, &horizontal, &vertical);

    switch (option) {
    case 0x14:
        if (horizontal < 0) {
            loadMapAndParent(0x42);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x42), 0);
            lockLevel(mapGetDirIdx(7), 1);
            (*gMapEventInterface)->setMapAct(0x42, 1);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x15:
        if (vertical > 0 && lbl_803DC050 == 0) {
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x16:
        if (horizontal > 0 && playerHasKrazoaSpirit(1, 0) != 0) {
            loadMapAndParent(0x42);
            lockLevel(mapGetDirIdx(0x42), 0);
            lockLevel(mapGetDirIdx(7), 1);
            if (mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0) {
                (*gMapEventInterface)->setMapAct(0x42, 2);
            } else if (mainGetBit(GAMEBIT_ITEM_SpiritTestFear_Got) != 0) {
                (*gMapEventInterface)->setMapAct(0x42, 2);
            } else if (mainGetBit(GAMEBIT_ITEM_SpiritTestStrength_Got) != 0) {
                (*gMapEventInterface)->setMapAct(0x42, 2);
            } else if (mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0) {
                (*gMapEventInterface)->setMapAct(0x42, 2);
            }
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x17: {
        int hasSpirit = playerHasKrazoaSpirit(1, 0);
        if (horizontal > 0 && hasSpirit == 0) {
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;
    }

    case 0x18:
        lbl_803DDBF4 = 1;
        if (vertical > 0) {
            loadMapAndParent(9);
            lockLevel(mapGetDirIdx(9), 0);
            lockLevel(mapGetDirIdx(7), 1);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_up);
            return 1;
        }
        break;

    case 0x19:
        if ((getButtonsJustPressed(0) & PAD_BUTTON_B) != 0) {
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            mapUnload(mapGetDirIdx(0x17), 0x20000000);
            Sfx_PlayFromObject(0, SFXTRIG_menu_pause_down);
            return 1;
        }
        break;
    }

    return 0;
}

void warpstone_loadBaseUi(void) {
    loadUiDll(0x1);
}

int warpstone_SeqFn(GameObject* obj, u32 unused, ObjSeqState* animObj) {
    WarpStoneState* state = obj->extra;
    int i;
    GameObject* child;
    u8 command;
    ObjSeqState* animUpdate = animObj;

    if (animatedObjGetSeqId(animUpdate) == 0x35f) {
        ObjSeq_SetSlotValue(animUpdate, 0x2648);
        if (getCurUiDll() != 0x10) {
            loadUiDll(0x10);
        }
    }

    child = state->child;
    if ((void*)child != NULL) {
        ObjAnim_AdvanceCurrentMove(
            child, obj->anim.currentMoveProgress - child->anim.currentMoveProgress, timeDelta, NULL);
    }

    animUpdate->conditionCallback = (ObjAnimSequenceConditionCallback)warpstone_testEvent;
    animUpdate->freeCallback = (ObjAnimSequenceFreeCallback)warpstone_loadBaseUi;

    if ((s8)animUpdate->movementState != 0) {
        state->sequenceFlags = state->sequenceFlags & ~3;
        if ((s32)warpstoneProbePlayerAnimState() != 0) {
            state->sequenceFlags = state->sequenceFlags | 1;
        }
        {
            int hit;
            if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone1_Got) != 0) {
                hit = 1;
            } else if (mainGetBit(GAMEBIT_ITEM_FireSpellStone1_Got) != 0) {
                hit = 1;
            } else {
                hit = 0;
            }
            if (hit) {
                state->sequenceFlags = state->sequenceFlags | 2;
            }
        }
        animUpdate->movementState = 0;

        if (mainGetBit(state->sequenceGameBit) != 0 &&
            animatedObjGetSeqId(animObj) == 0x35f) {
            AudioStream_CancelPrepared();
            seqClearTaskTexts();
            AudioStream_Nop(0);
            animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        }
    }

    for (i = 0; i < animUpdate->eventCount; i++) {
        command = animUpdate->eventIds[i];
        switch (command) {
        case 0x17:
            state->dustEffectFlags = state->dustEffectFlags | 4;
            Sfx_PlayFromObject(0, SFXTRIG_id_420);
            break;

        case 3:
            state->pathPointIndex = 0;
            break;

        case 4:
            state->pathPointIndex = 1;
            break;

        case 6:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x7e, 1);
            break;

        case 7:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            mainSetBits(GAMEBIT_SH_WarpStoneRelated0884, 1);
            warpToMap(0x7e, 1);
            break;

        case 0xa:
            state->sequenceToggle = state->sequenceToggle ^ 1;
            break;

        case 9:
            (*gMapEventInterface)->setMapAct(0x17, 1);
            (*gMapEventInterface)->setMapAct(0xe, 2);
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            break;

        case 0xc:
            CMenu_SetFadeCounter(0);
            loadUiDll(1);
            warpToMap(0x33, 0);
            break;

        case 0xd:
            subtitleStop();
        case 0xe:
        case 0xf:
        case 0x10:
        case 0x11:
            if (getCurUiDll() == 0x10) {
                UiDllVTable** uiDll = getCurUiDllInterface();
                (*uiDll)->setState(animUpdate->eventIds[i] - 0xd);
            }
            mainSetBits(state->sequenceGameBit, 1);
            mainSetBits(GAMEBIT_SH_SawWarpStoneIntro, 1);
            break;

        case 0x12:
            (*gMapEventInterface)->setObjGroupStatus(7, 0xa, 0);
            break;

        case 0x14:
            unlockLevel(0, 0, 1);
            break;

        case 0x15:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;

        case 0x16:
            unlockLevel(0, 0, 1);
            mapUnload(mapGetDirIdx(0x42), 0x20000000);
            break;
        }
    }

    warpstone_updateDustEffects(obj);
    return 0;
}

int warpstone_getExtraSize(void) {
    return sizeof(WarpStoneState);
}

int warpstone_getObjectTypeId(void) {
    return 0x48;
}

void warpstone_free(GameObject* obj, int mode) {
    int* state = obj->extra;
    if (*(void**)state != NULL && mode == 0) {
        ObjLink_DetachChild(obj, (GameObject*)state[0]);
        Obj_FreeObject((GameObject*)state[0]);
    }
}

void warpstone_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    GameObject* player;
    WarpStoneState* state = obj->extra;
    ObjModel* model;
    f32 z;
    f32 y;
    f32 x;
    s32 visibleValue = visible;
    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        player = Obj_GetPlayerObject();
        if (player != NULL && playerIsSequenceRenderSuppressed(player) != 0) {
            model = Obj_GetActiveModel(player);
            model->bufferFlags = (u16)(model->bufferFlags & ~0x8);
            ObjPath_GetPointWorldPosition(obj, state->pathPointIndex, &x, &y, &z, 0);
            objSetPos(player, x, y, z);
            playerRender((int)player, renderArg2, renderArg3, renderArg4, renderArg5, -1);
        }
    }
}

void warpstone_hitDetect(GameObject* obj) {
    int* state = obj->extra;
    PartFxSpawnParams lightParams;

    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &lightParams.posX, &lightParams.posY, &lightParams.posZ) != 0) {
        lightParams.posX += playerMapOffsetX;
        lightParams.posZ += playerMapOffsetZ;
        objDoHitParticleFx((void*)obj, 0.01f, &lightParams, 1, 0);
        if (randomChanceOneIn(3) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_short_2bc);
        } else {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_short_2bc);
        }
        objSoundStartTimed(obj, (ObjSoundState*)((u8*)state + offsetof(WarpStoneState, soundState)), 171, -1280, -1, 0);
    }
}

int gWarpStoneLookToggleChance = 300;
int gWarpStoneHeadAimMode = 1;
int gWarpStoneHeadAimHeightOffset = 200;
s16 gWarpStoneHeadYawOffset = 0x800;
int gWarpStoneMumbleChance = 3;
int gWarpStoneYawnChance = 4;
int lbl_803DC050 = 1;

#define WARPSTONE_TARGET_OBJECT_GROUP 8

s16 gWarpStoneHeadPitchOffset;
s16 gWarpStoneYawBias;

void warpstone_update(GameObject* obj) {
    WarpStoneState* state;
    int child;
    int advanceResult;
    GameObject* target;
    s16* modelVec;
    int yawDelta;
    int moveId;

    state = (obj)->extra;
    child = *(int*)state;
    if ((void*)child != NULL) {
        ObjLink_DetachChild(obj, (GameObject*)child);
        Obj_FreeObject(*(GameObject**)state);
        *(int*)state = 0;
    }

    advanceResult = warpstone_advanceAnimEvents(obj, 0.0055555557f);
    if (obj->anim.currentMove == 0) {
        if (randomChanceOneIn(100) != 0) {
            objSoundStartTimed(obj, (ObjSoundState*)((u8*)state + offsetof(WarpStoneState, soundState)), 0xab,
                               -0x100, -1, 0);
        }
        if (randomChanceOneIn(500) != 0) {
            objSoundStartTimed(obj, (ObjSoundState*)((u8*)state + offsetof(WarpStoneState, soundState)), 0x417,
                               -0x500, -1, 0);
        }
    }

    if (mainGetBit(GAMEBIT_ITEM_RockCandy_Used) != 0) {
        if (randomChanceOneIn(gWarpStoneLookToggleChance) != 0) {
            state->behaviorFlags.lookAtPlayer =
                (state->behaviorFlags.lookAtPlayer == 0);
        }
        if (state->behaviorFlags.lookAtPlayer == 0) {
            state->behaviorFlags.lookAtPlayer = mainGetBit(0xa45);
        }
    }

    if (state->behaviorFlags.lookAtPlayer != 0) {
        target = Obj_GetPlayerObject();
    } else {
        target = objGetNearestTypeTo(WARPSTONE_TARGET_OBJECT_GROUP, obj, 0);
    }

    obj->anim.localPosY += gWarpStoneHeadAimHeightOffset;
    characterAimHeadAtTarget((GameObject*)(obj), (void*)target, (void*)((u8*)state + offsetof(WarpStoneState, headAimState)),
                             0x23, 1, gWarpStoneHeadAimMode);
    modelVec = objFindJointPoseVector((GameObject*)(obj), 0);
    obj->anim.localPosY -= gWarpStoneHeadAimHeightOffset;

    if (modelVec != NULL) {
        modelVec[1] = modelVec[1] + gWarpStoneHeadPitchOffset;
        modelVec[0] = 0;
        modelVec[0] += gWarpStoneHeadYawOffset;
    }

    if (advanceResult != 0) {
        state->behaviorFlags.sfxFired = 0;
        yawDelta = Obj_GetYawDeltaToObject(obj, target, NULL);
        yawDelta = (s16)(yawDelta - gWarpStoneYawBias);
        {
            int mag = yawDelta - 0x8000;
            mag = (mag >= 0) ? mag : -mag;
            if (mag > 0x18e3) {
                if (yawDelta > 0) {
                    if (yawDelta > 0xe38) {
                        moveId = 0x17;
                    } else {
                        moveId = 0x16;
                    }
                } else if (yawDelta < -0xe38) {
                    moveId = 0x19;
                } else {
                    moveId = 0x18;
                }
                if (obj->anim.currentMove != moveId) {
                    ObjAnim_SetCurrentMove(obj, moveId, 0.0f, 0);
                }
            } else if (obj->anim.currentMove != 0) {
                ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
                Sfx_StopFromObject(obj, SFXTRIG_swapstone_move_long);
            } else if (randomChanceOneIn(gWarpStoneMumbleChance) != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_swapstone_mumble);
                ObjAnim_SetCurrentMove(obj, 0x1b, 0.0f, 0);
            } else if (randomChanceOneIn(gWarpStoneYawnChance) != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_long);
                ObjAnim_SetCurrentMove(obj, 0x1a, 0.0f, 0);
            }
        }
    }

    objSoundUpdateMouth(obj, (ObjSoundState*)((u8*)state + offsetof(WarpStoneState, soundState)));
    characterDoEyeAnims(obj, (void*)((u8*)state + offsetof(WarpStoneState, eyeAnimState)));
    if (mainGetBit(GAMEBIT_SH_SawWarpStoneIntro) == 0) {
        state->activated = 0;
    }
    if (state->behaviorFlags.sfxFired != 0) {
        return;
    }

    switch (obj->anim.currentMove) {
    case 0x17:
    case 0x19:
        if (obj->anim.currentMoveProgress > 0.5f) {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_long);
            state->behaviorFlags.sfxFired = 1;
        }
        break;
    case 0x16:
    case 0x18:
        if (obj->anim.currentMoveProgress > 0.5f) {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_short_2bc);
            state->behaviorFlags.sfxFired = 1;
        }
        break;
    case 0x1a:
        if (obj->anim.currentMoveProgress > 0.6f) {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_yawn);
            state->behaviorFlags.sfxFired = 1;
        }
        break;
    case 0x1b:
        if (obj->anim.currentMoveProgress > 0.25f) {
            Sfx_PlayFromObject(obj, SFXTRIG_swapstone_move_short);
            state->behaviorFlags.sfxFired = 1;
        }
        break;
    }
}

void warpstone_init(GameObject* obj, const WarpStonePlacement* placement) {
    WarpStoneState* state;
    s16 rotX;

    state = obj->extra;
    rotX = (s16)(placement->rotXByte << 8);
    obj->anim.rotX = rotX;
    obj->animEventCallback = warpstone_SeqFn;
    state->sequenceGameBit = GAMEBIT_SH_WarpStoneRelated015A;
    state->resetGameBit = GAMEBIT_ITEM_RockCandyRelated0886;
    ObjHits_EnableObject(obj);
    if (mainGetBit(GAMEBIT_SH_SawWarpStoneIntro) != 0 && mainGetBit(GAMEBIT_SH_WarpStoneRelated015A) != 0) {
        state->activated = 1;
    } else {
        state->activated = 0;
    }
    mainSetBits(state->resetGameBit, 0);
    *(int*)state = 0;
}

void warpstone_release(void) {
}

void warpstone_initialise(void) {
}
