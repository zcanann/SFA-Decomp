/*
 * DLL 0xFE - MagicPlant.
 *
 * A plant grows a coloured gem, reacts to hits, and fades out before its map
 * event rearms it. The gem colour mapping and the complete state cycle have
 * been verified in Dolphin.
 */
#include "dlls/objects/254_MagicPlant.h"
#include "dlls/objects/255.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/mm.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "dlls/objects/237.h"

extern f32 lbl_803E385C;
extern f32 lbl_803E3880;
extern f32 lbl_803E3858;
extern f32 lbl_803E387C;
extern f32 lbl_803E3878;
extern f32 lbl_803E3874;
extern f32 lbl_803E3870;
extern f32 gMagicPlantHitReactAnimStep;
extern f32 gMagicPlantHitLightScale;
extern f32 gMagicPlantIdleAnimStep;
extern f32 lbl_803E3890;
extern f32 gMagicPlantBuzzStartDist;
extern f32 gMagicPlantBuzzStopDist;

#define MAGICPLANT_ZERO                         lbl_803E385C
#define MAGICPLANT_ONE                          lbl_803E3858
#define MAGICPLANT_DROP_PROGRESS_THRESHOLD      lbl_803E3870
#define MAGICPLANT_LAUNCH_SPEED_DIVISOR         lbl_803E3874
#define MAGICPLANT_ROTATION_RADIANS_NUMERATOR   lbl_803E3878
#define MAGICPLANT_ROTATION_RADIANS_DENOMINATOR lbl_803E387C
#define MAGICPLANT_FADE_OUT_ANIM_STEP           lbl_803E3880
#define MAGICPLANT_RANDOM_PROGRESS_SCALE        lbl_803E3890

#define MAGICPLANT_OBJECT_TYPE_BASE        0x400
#define MAGICPLANT_OBJECT_TYPE_MODEL_SHIFT 11

#define MAGICPLANT_OBJGROUP_A 0x34
#define MAGICPLANT_OBJGROUP_B 0x3E

#define MAGICPLANT_HIT_KIND_FADE_IN 0x10
#define MAGICPLANT_HIT_BURST_FX     0x34E
#define MAGICPLANT_HIT_BURST_COUNT  20

#define MAGICPLANT_IDLE_TIMER_MIN 300
#define MAGICPLANT_IDLE_TIMER_MAX 600

#define MAGICPLANT_SFX_CHANNEL             0x40
#define MAGICPLANT_MODEL_FADE_FRAMES       300
#define MAGICPLANT_HIT_FLASH_FRAMES        15
#define MAGICPLANT_HIT_FLASH_RED           200
#define MAGICPLANT_PARTFX_MODE             2
#define MAGICPLANT_PARTFX_MODEL_NONE       -1
#define MAGICPLANT_HIT_FLASH_START_AT_HALF 1
#define MAGICPLANT_EVENT_MIN_DURATION      100
#define MAGICPLANT_GEM_COLOR_MASK          3
#define MAGICPLANT_FADE_OUT_ALPHA_STEP     2
#define MAGICPLANT_MAX_ALPHA               0xFF
#define MAGICPLANT_MODEL_STATE_FLAGS       0x810

#define MAGICPLANT_CHILD_SETUP_FLAGS 5
#define MAGICPLANT_CHILD_UNK1A       0x14
#define MAGICPLANT_CHILD_YAW_OFFSET  0xF
#define MAGICPLANT_CHILD_SENTINEL    -1

s16 gMagicPlantGemDefIds[4] = {
    MAGICGEM_DEF_GREEN,
    MAGICGEM_DEF_RED,
    MAGICGEM_DEF_YELLOW,
    MAGICGEM_DEF_BLUE,
};

void magicPlantDropGem(GameObject* obj, MagicPlantPlacement* unusedPlacement, MagicPlantState* state) {
    GameObject* player;
    GameObject* childObj;
    f32 launchSpeed;
    int angle;

    player = Obj_GetPlayerObject();
    Sfx_StopObjectChannel(obj, MAGICPLANT_SFX_CHANNEL);

    childObj = *(GameObject**)&state->childObject;
    if ((childObj != NULL) && (childObj->ownerObj != NULL) &&
        (obj->anim.currentMoveProgress >= MAGICPLANT_DROP_PROGRESS_THRESHOLD)) {
        state->childObject = NULL;
        ObjLink_DetachChild(obj, childObj);

        launchSpeed = (f32)randomGetRange(0x27, 0x2C) / MAGICPLANT_LAUNCH_SPEED_DIVISOR;
        angle = getAngle(obj->anim.localPosX - player->anim.localPosX, obj->anim.localPosZ - player->anim.localPosZ);
        randomGetRange(((u16)angle) - 0x1000, ((u16)angle) + 0x1000);

        childObj->anim.velocityX =
            launchSpeed * mathSinf((MAGICPLANT_ROTATION_RADIANS_NUMERATOR * (f32)obj->anim.rotX) /
                                   MAGICPLANT_ROTATION_RADIANS_DENOMINATOR);
        childObj->anim.velocityZ =
            launchSpeed * mathCosf((MAGICPLANT_ROTATION_RADIANS_NUMERATOR * (f32)obj->anim.rotX) /
                                   MAGICPLANT_ROTATION_RADIANS_DENOMINATOR);
        Sfx_PlayFromObject(obj, SFXTRIG_id_5e);
    }

    if (obj->anim.currentMoveProgress >= MAGICPLANT_ONE) {
        state->mode = MAGICPLANT_MODE_FADE_OUT;
        state->animStepScale = MAGICPLANT_FADE_OUT_ANIM_STEP;
        ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_BURST, MAGICPLANT_ZERO, 0);
    }
}

void MagicPlant_updateActive(GameObject* obj, MagicPlantPlacement* unusedPlacement, MagicPlantState* state) {
    int hitVolume;
    int hitSphereIndex;
    GameObject* hitObject;
    PartFxSpawnParams lightParams;
    int hitKind;
    int particleCount;
    int playerAddress;
    GameObject* player;
    f32 distance;

    playerAddress = (int)Obj_GetPlayerObject();
    player = (GameObject*)playerAddress;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;

    hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, (u32*)&hitVolume, &lightParams.posX,
                                                 &lightParams.posY, &lightParams.posZ);
    if ((hitKind != 0) && (hitVolume != 0)) {
        switch (hitKind) {
        case MAGICPLANT_HIT_KIND_FADE_IN:
            Obj_StartModelFadeIn(obj, MAGICPLANT_MODEL_FADE_FRAMES);
            break;
        case 0:
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_ladderslide16);
            state->mode = MAGICPLANT_MODE_HIT_REACT;
            state->animStepScale = gMagicPlantHitReactAnimStep;
            ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_HIT, MAGICPLANT_ZERO, 0);

            particleCount = MAGICPLANT_HIT_BURST_COUNT;
            do {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, MAGICPLANT_HIT_BURST_FX, NULL, MAGICPLANT_PARTFX_MODE,
                                  MAGICPLANT_PARTFX_MODEL_NONE, NULL);
                particleCount--;
            } while (particleCount != 0);

            lightParams.posX += playerMapOffsetX;
            lightParams.posZ += playerMapOffsetZ;
            objDoHitParticleFx((void*)obj, gMagicPlantHitLightScale, &lightParams, 1, 0);
            Obj_SetModelColorFadeRecursive(obj, MAGICPLANT_HIT_FLASH_FRAMES, MAGICPLANT_HIT_FLASH_RED, 0, 0,
                                           MAGICPLANT_HIT_FLASH_START_AT_HALF);
            break;
        }
    }

    if (state->mode == MAGICPLANT_MODE_ACTIVE) {
        if (obj->anim.currentMove == MAGICPLANT_MOVE_SWAY_FAST) {
            if (obj->anim.currentMoveProgress >= MAGICPLANT_ONE) {
                state->animStepScale = gMagicPlantIdleAnimStep;
                ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_IDLE, MAGICPLANT_ZERO, 0);
            } else {
                state->animStepScale = MAGICPLANT_RANDOM_PROGRESS_SCALE;
            }
        } else if ((state->idleTimer -= framesThisStep) <= 0) {
            state->idleTimer = randomGetRange(MAGICPLANT_IDLE_TIMER_MIN, MAGICPLANT_IDLE_TIMER_MAX);
        } else if (obj->anim.currentMove != MAGICPLANT_MOVE_IDLE) {
            state->animStepScale = gMagicPlantIdleAnimStep;
            ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_IDLE,
                                   MAGICPLANT_RANDOM_PROGRESS_SCALE * (f32)randomGetRange(0, 99), 0);
        }
    }

    distance = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, MAGICPLANT_SFX_CHANNEL) == 0) {
        if (distance < gMagicPlantBuzzStartDist) {
            Sfx_PlayFromObject(obj, SFXTRIG_neonbuzzlp16);
        }
    } else if (distance > gMagicPlantBuzzStopDist) {
        Sfx_StopObjectChannel(obj, MAGICPLANT_SFX_CHANNEL);
    }
}

void MagicPlant_spawnChild(GameObject* obj, int objectId) {
    CollectibleSetup* placement;
    GameObject* childObj;
    u8* placementData;
    MagicPlantState* state;

    placementData = (u8*)obj->anim.placementData;
    state = obj->extra;
    if (Obj_IsLoadingLocked() != 0) {
        placement = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), objectId);
        placement->unk1A = MAGICPLANT_CHILD_UNK1A;
        placement->counterGameBit = MAGICPLANT_CHILD_SENTINEL;
        placement->hideGameBit = MAGICPLANT_CHILD_SENTINEL;
        placement->base.posX = obj->anim.localPosX;
        placement->base.posY = obj->anim.localPosY;
        placement->base.posZ = obj->anim.localPosZ;
        placement->visibilityGameBit = MAGICPLANT_CHILD_SENTINEL;
        placement->base.color[0] = placementData[0x04];
        placement->base.color[2] = placementData[0x06];
        placement->base.color[1] = placementData[0x05];
        placement->base.unk07 = (u8)(placementData[0x07] - MAGICPLANT_CHILD_YAW_OFFSET);
        childObj = objSetupObject(&placement->base, MAGICPLANT_CHILD_SETUP_FLAGS, obj->anim.mapEventSlot,
                                   MAGICPLANT_CHILD_SENTINEL, obj->anim.parent);
        if (childObj != NULL) {
            ObjLink_AttachChild(obj, childObj, 0);
            state->childObject = childObj;
        } else {
            mm_free(placement);
            state->childObject = NULL;
        }
    }
}

int MagicPlant_SeqFn(GameObject* obj) {
    (*gCameraInterface)->setTargetReticleOverride(obj);
    return 0;
}

int MagicPlant_getExtraSize(void) {
    return sizeof(MagicPlantState);
}

u32 MagicPlant_getObjectTypeId(GameObject* obj) {
    MagicPlantPlacement* placement = (MagicPlantPlacement*)obj->anim.placementData;

    return (placement->modelIndex << MAGICPLANT_OBJECT_TYPE_MODEL_SHIFT) | MAGICPLANT_OBJECT_TYPE_BASE;
}

void MagicPlant_free(GameObject* obj, int keepChildren) {
    MagicPlantState* state;

    state = obj->extra;
    objFreeObjectType(obj, MAGICPLANT_OBJGROUP_A);
    objFreeObjectType(obj, MAGICPLANT_OBJGROUP_B);
    if (obj->childCount != 0) {
        ObjLink_DetachChild(obj, state->childObject);
        if (keepChildren == 0) {
            Obj_FreeObject(state->childObject);
        }
    }
}

void MagicPlant_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    MagicPlantState* state;
    GameObject* child;

    state = obj->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, MAGICPLANT_ONE);
        child = state->childObject;
        if (child != NULL) {
            if (child->ownerObj != NULL) {
                ObjPath_GetPointWorldPosition(obj, 0, &child->anim.localPosX, &child->anim.localPosY,
                                              &child->anim.localPosZ, 0);
            }
        }
    }
}

void MagicPlant_update(GameObject* obj) {
    s32 alpha;
    MagicPlantPlacement* placement;
    MagicPlantState* state;
    GameObject* hitObject;
    u32 hitVolume;
    int hitSphereIndex;
    PartFxSpawnParams lightParams;
    int hitKind;
    f32 progress;
    f32 resetProgress;
    int divisor;

    placement = (MagicPlantPlacement*)obj->anim.placementData;
    state = obj->extra;

    if ((state->childObject != 0) && (obj->childCount == 0)) {
        state->childObject = NULL;
        Obj_FreeObject(obj);
        return;
    }

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (objIsFrozen(obj) != 0) {
        hitKind = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &lightParams.posX,
                                                     &lightParams.posY, &lightParams.posZ);
        if ((hitKind != 0) && (hitKind != MAGICPLANT_HIT_KIND_FADE_IN)) {
            lightParams.posX += playerMapOffsetX;
            lightParams.posZ += playerMapOffsetZ;
            objDoHitParticleFx((void*)obj, gMagicPlantHitLightScale, &lightParams, 1, 0);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
            Obj_Shatter(obj);
        }
        return;
    }

    switch (state->mode) {
    case MAGICPLANT_MODE_WAIT_FOR_EVENT:
        if ((*gMapEventInterface)->shouldNotSaveTime(placement->eventId) != 0) {
            MagicPlant_spawnChild(obj, gMagicPlantGemDefIds[placement->gemColor & MAGICPLANT_GEM_COLOR_MASK]);
            state->mode = MAGICPLANT_MODE_ACTIVE;
            state->idleTimer = randomGetRange(MAGICPLANT_IDLE_TIMER_MIN, MAGICPLANT_IDLE_TIMER_MAX);
        } else {
            progress = (*gMapEventInterface)->getTime(placement->eventId);
            divisor = placement->eventDuration;
            if (divisor < MAGICPLANT_EVENT_MIN_DURATION) {
                divisor = MAGICPLANT_EVENT_MIN_DURATION;
            }
            progress /= divisor;
            if (progress > MAGICPLANT_ONE) {
                progress = MAGICPLANT_ONE;
            } else if (progress < MAGICPLANT_ZERO) {
                progress = MAGICPLANT_ZERO;
            }
            state->animProgress = MAGICPLANT_ONE - progress;
        }
        if (obj->anim.currentMove != MAGICPLANT_MOVE_CLOSED) {
            ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_CLOSED, state->animProgress, 0);
        }
        ObjAnim_SetMoveProgress(&obj->anim, state->animProgress);
        break;

    case MAGICPLANT_MODE_ACTIVE:
        MagicPlant_updateActive(obj, placement, state);
        break;

    case MAGICPLANT_MODE_HIT_REACT:
        magicPlantDropGem(obj, placement, state);
        break;

    case MAGICPLANT_MODE_FADE_OUT:
        if (obj->anim.currentMoveProgress >= MAGICPLANT_ONE) {
            alpha = obj->anim.alpha;
            alpha -= framesThisStep * MAGICPLANT_FADE_OUT_ALPHA_STEP;
            if (alpha < 0) {
                alpha = 0;
                state->mode = MAGICPLANT_MODE_FADE_IN;
                resetProgress = MAGICPLANT_ZERO;
                state->animProgress = resetProgress;
                state->animStepScale = resetProgress;
                ObjAnim_SetCurrentMove(obj, MAGICPLANT_MOVE_CLOSED, resetProgress, 0);
                ObjAnim_SetMoveProgress(&obj->anim, MAGICPLANT_ZERO);
            }
            obj->anim.alpha = alpha;
        }
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        break;

    case MAGICPLANT_MODE_FADE_IN:
        alpha = obj->anim.alpha;
        alpha += framesThisStep;
        if (alpha >= MAGICPLANT_MAX_ALPHA) {
            alpha = MAGICPLANT_MAX_ALPHA;
            state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
            (*gMapEventInterface)->addTime(placement->eventId, placement->eventDuration);
        }
        obj->anim.alpha = alpha;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
        break;
    }

    ObjAnim_AdvanceCurrentMove(obj, state->animStepScale, timeDelta, NULL);
}

void MagicPlant_init(GameObject* obj, MagicPlantPlacement* placement) {
    ObjAnimComponent* anim;
    MagicPlantState* state;
    s32 noSaveTime;
    f32 progress;
    int divisor;

    anim = &obj->anim;
    state = obj->extra;
    objAddObjectType(obj, MAGICPLANT_OBJGROUP_A);
    objAddObjectType(obj, MAGICPLANT_OBJGROUP_B);
    noSaveTime = (*gMapEventInterface)->shouldNotSaveTime(placement->eventId);
    if (noSaveTime == 0) {
        progress = (*gMapEventInterface)->getTime(placement->eventId);
        divisor = placement->eventDuration;
        if (divisor < MAGICPLANT_EVENT_MIN_DURATION)
            divisor = MAGICPLANT_EVENT_MIN_DURATION;
        progress /= divisor;
        if (progress > MAGICPLANT_ONE) {
            progress = MAGICPLANT_ONE;
        } else if (progress < MAGICPLANT_ZERO) {
            progress = MAGICPLANT_ZERO;
        }
        state->animProgress = MAGICPLANT_ONE - progress;
    } else {
        state->animProgress = MAGICPLANT_ONE;
    }
    state->mode = MAGICPLANT_MODE_WAIT_FOR_EVENT;
    state->animStepScale = MAGICPLANT_ZERO;
    ObjAnim_SetMoveProgress(&obj->anim, state->animProgress);
    anim->rotX = (s16)((u32)placement->yawByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    anim->bankIndex = placement->modelIndex;
    if (anim->bankIndex >= anim->modelInstance->modelCount) {
        anim->bankIndex = 0;
    }
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= MAGICPLANT_MODEL_STATE_FLAGS;
    }
    obj->animEventCallback = MagicPlant_SeqFn;
}

ObjectDescriptor gMagicPlantObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};
