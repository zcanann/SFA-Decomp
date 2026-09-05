/*
 * DLL 0x11C implements the staff-activated mechanisms shared by several
 * object definitions, including action pads, lifts, and destructible scenery.
 */
#include "dlls/objects/284.h"
#include "dlls/objects/262.h"
#include "dlls/objects/283_Landed_Arwi.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/pad_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/player_api.h"
#include "main/objtype.h"

STATIC_ASSERT(sizeof(StaffActivatedState) == sizeof(LandedArwingHitReactionState));
STATIC_ASSERT(offsetof(StaffActivatedState, pad08) == offsetof(LandedArwingHitReactionState, animationStepScale));
STATIC_ASSERT(offsetof(StaffActivatedState, liftReset) == offsetof(LandedArwingHitReactionState, hitStarted));
STATIC_ASSERT(offsetof(StaffActivatedState, flags) == offsetof(LandedArwingHitReactionState, flags));
STATIC_ASSERT(offsetof(StaffActivatedState, hitCooldown) == offsetof(LandedArwingHitReactionState, hitEffectCooldown));

#define STAFF_ACTIVATED_OBJECT_TYPE_ID 0x40
#define STAFF_ACTIVATED_PARTICLE_ID    0x7C3
#define STAFF_ACTIVATED_GAME_BIT_NONE  -1

#define STAFF_ACTIVATED_LIFT_MAX_SIZE_VARIANT 2
#define STAFF_ACTIVATED_LIFT_MOVE_HEIGHT      0x800
#define STAFF_ACTIVATED_LIFT_SFX_HEIGHT       0x40
#define STAFF_ACTIVATED_LIFT_RUMBLE_DIVISOR   200

#define STAFF_ACTIVATED_SCARAB_ACTIVE_FRAMES 0x190
#define STAFF_ACTIVATED_SCARAB_RANDOM_RANGE  0x19
#define STAFF_ACTIVATED_SCARAB_Y_VELOCITY    2.2f

#define STAFF_ACTIVATED_PI              3.1415927f
#define STAFF_ACTIVATED_BIN_ANGLE_SCALE 32768.0f
#define STAFF_ACTIVATED_TARGET_DISTANCE 20.0f
#define STAFF_ACTIVATED_ACTION_DISTANCE 18.0f

extern const f32 lbl_803E3BBC;
extern const f32 lbl_803E3BC4;

s16 gStaffActivatedScarabObjectIds[4] = {
    SCARAB_OBJECT_GREEN,
    SCARAB_OBJECT_RED,
    SCARAB_OBJECT_GOLD,
    SCARAB_OBJECT_RAIN,
};

void staffactivated_updateLiftHeight(GameObject* obj, StaffActivatedState* state) {
    s32 previousHeight;
    s32 rumbleStrength;

    if (!state->flags.active || state->flags.locked) {
        return;
    }
    if (state->liftReset == 0) {
        state->liftVelocity = (s32) - (4.0f * timeDelta - state->liftVelocity);
        state->liftHeight = (s32)((f32)state->liftVelocity * timeDelta + state->liftHeight);
        if (state->liftHeight > state->peakLiftHeight) {
            state->peakLiftHeight = state->liftHeight;
        }
        if (state->previousLiftHeight == STAFF_ACTIVATED_LIFT_MOVE_HEIGHT &&
            state->liftHeight < STAFF_ACTIVATED_LIFT_MOVE_HEIGHT) {
            Sfx_PlayFromObject(obj, SFXTRIG_mammoth_grunt);
        }
        if (state->liftHeight < 0) {
            if (state->previousLiftHeight > 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_mammoth_grunt1);
                rumbleStrength = state->peakLiftHeight / STAFF_ACTIVATED_LIFT_RUMBLE_DIVISOR;
                if (rumbleStrength > 0) {
                    doRumble((f32)rumbleStrength);
                }
            }
            state->liftVelocity = 0;
            state->liftHeight = 0;
        }
    } else {
        state->liftReset = 0;
        state->peakLiftHeight = 0;
    }

    previousHeight = state->previousLiftHeight;
    if ((previousHeight < STAFF_ACTIVATED_LIFT_SFX_HEIGHT && state->liftHeight >= STAFF_ACTIVATED_LIFT_SFX_HEIGHT) ||
        (previousHeight >= STAFF_ACTIVATED_LIFT_SFX_HEIGHT && state->liftHeight < STAFF_ACTIVATED_LIFT_SFX_HEIGHT)) {
        Sfx_PlayFromObject(obj, SFXTRIG_mammoth_grunt);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, STAFF_ACTIVATED_HIT_EFFECT_MODE, STAFF_ACTIVATED_HIT_EFFECT_RED,
                                              STAFF_ACTIVATED_HIT_EFFECT_GREEN, STAFF_ACTIVATED_HIT_EFFECT_BLUE,
                                              STAFF_ACTIVATED_HIT_EFFECT_SFX, &state->hitCooldown);
    state->previousLiftHeight = state->liftHeight;
    ObjAnim_SetMoveProgress(&obj->anim, state->liftHeight / 2048.0f);
}

void staffactivated_setGameBitMirror(GameObject* obj, u8 enabled) {
    StaffActivatedPlacement* placement = (StaffActivatedPlacement*)obj->anim.placementData;
    StaffActivatedState* state = obj->extra;
    if (enabled != 0) {
        mainSetBits(placement->lockGameBit, 1);
        state->flags.gameBitMirror = 1;
    } else {
        mainSetBits(placement->lockGameBit, 0);
        state->flags.gameBitMirror = 0;
    }
}

int staffactivated_isGameBitMirrorSet(GameObject* obj) {
    StaffActivatedState* state = obj->extra;
    return state->flags.gameBitMirror;
}

void staffactivated_spawnMapEventDebris(GameObject* obj) {
    int scarabIndex;
    StaffActivatedPlacement* placement;
    GameObject* player;
    GameObject* tricky;
    StaffActivatedState* state;
    GameObject* scarab;
    ScarabPlacement* scarabPlacement;
    f32 zero;
    f32 speedSquared;
    f32 speed;
    s32 rotationDelta;
    MatrixTransform rotation;
    u8 canSetupObject;

    placement = (StaffActivatedPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    state = obj->extra;

    if ((*gMapEventInterface)->shouldNotSaveTime(placement->base.ident) != 0) {
        canSetupObject = Obj_CanSetupObject();
        if (canSetupObject > 0) {
            (*gMapEventInterface)->addTime(placement->base.ident, 60.0f * placement->timedEventSeconds);
            if (tricky != NULL) {
                trickyImpress(tricky);
            }

            zero = 0.0f;
            scarabIndex = 0;
            while (scarabIndex < placement->scarabCount) {
                scarabPlacement = (ScarabPlacement*)Obj_AllocObjectSetup(
                    SCARAB_PLACEMENT_SIZE, gStaffActivatedScarabObjectIds[placement->scarabObjectSet]);
                scarabPlacement->base.posX = state->targetX;
                scarabPlacement->base.posY = obj->anim.localPosY;
                scarabPlacement->base.posZ = state->targetZ;
                scarabPlacement->activeTimer = STAFF_ACTIVATED_SCARAB_ACTIVE_FRAMES;

                scarab = objSetupObject(&scarabPlacement->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                scarab->anim.velocityX = obj->anim.localPosX - player->anim.localPosX;
                scarab->anim.velocityZ = obj->anim.localPosZ - player->anim.localPosZ;

                speedSquared = (scarab->anim.velocityX * scarab->anim.velocityX) +
                               (scarab->anim.velocityZ * scarab->anim.velocityZ);
                if (speedSquared != zero) {
                    speed = sqrtf(speedSquared);
                    scarab->anim.velocityX = scarab->anim.velocityX / speed;
                    scarab->anim.velocityZ = scarab->anim.velocityZ / speed;
                }

                scarab->anim.velocityX =
                    scarab->anim.velocityX *
                    (lbl_803E3BBC - (lbl_803E3BC4 * (f32)randomGetRange(0, STAFF_ACTIVATED_SCARAB_RANDOM_RANGE)));
                scarab->anim.velocityZ =
                    scarab->anim.velocityZ *
                    (lbl_803E3BBC - (lbl_803E3BC4 * (f32)randomGetRange(0, STAFF_ACTIVATED_SCARAB_RANDOM_RANGE)));
                scarab->anim.velocityY = STAFF_ACTIVATED_SCARAB_Y_VELOCITY;

                rotation.x = zero;
                rotation.y = zero;
                rotation.z = zero;
                rotation.scale = lbl_803E3BBC;
                rotation.rotZ = 0;
                rotation.rotY = 0;
                rotation.rotX = randomGetRange(-10000, 10000);
                vecRotateZXY(&rotation.rotX, &scarab->anim.velocityX);

                rotationDelta = scarab->anim.rotX - (u16)getAngle(scarab->anim.velocityX, -scarab->anim.velocityZ);
                if (rotationDelta > 0x8000) {
                    rotationDelta -= 0xFFFF;
                }
                if (rotationDelta < -0x8000) {
                    rotationDelta += 0xFFFF;
                }
                scarab->anim.rotX = rotationDelta;
                scarabIndex++;
            }
        }
    }
}

u32 staffactivated_getPullRateMode(GameObject* obj) {
    u32 sizeVariant;

    sizeVariant = ((StaffActivatedPlacement*)obj->anim.placementData)->sizeVariant;
    if (sizeVariant > STAFF_ACTIVATED_LIFT_MAX_SIZE_VARIANT) {
        sizeVariant = STAFF_ACTIVATED_LIFT_MAX_SIZE_VARIANT;
    }
    return sizeVariant;
}

void staffactivated_calcInteractionTargetXZ(GameObject* obj, f32* outX, f32* outZ) {
    int mode;
    StaffActivatedState* state;

    state = obj->extra;
    mode = ((StaffActivatedPlacement*)obj->anim.placementData)->mode;

    switch (mode) {
    case STAFF_ACTIVATED_MODE_LIFT:
        *outX = -(STAFF_ACTIVATED_TARGET_DISTANCE *
                      mathSinf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) -
                  state->targetX);
        *outZ = -(STAFF_ACTIVATED_TARGET_DISTANCE *
                      mathCosf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) -
                  state->targetZ);
        break;
    case STAFF_ACTIVATED_MODE_HIT_REACTION:
        *outX = STAFF_ACTIVATED_TARGET_DISTANCE *
                    mathSinf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                state->targetX;
        *outZ = STAFF_ACTIVATED_TARGET_DISTANCE *
                    mathCosf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                state->targetZ;
        break;
    case STAFF_ACTIVATED_MODE_ACTION:
        *outX = STAFF_ACTIVATED_ACTION_DISTANCE *
                    mathSinf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                obj->anim.localPosX;
        *outZ = STAFF_ACTIVATED_ACTION_DISTANCE *
                    mathCosf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                obj->anim.localPosZ;
        break;
    default:
        *outX = STAFF_ACTIVATED_TARGET_DISTANCE *
                    mathSinf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                obj->anim.localPosX;
        *outZ = STAFF_ACTIVATED_TARGET_DISTANCE *
                    mathCosf(STAFF_ACTIVATED_PI * (f32)(obj->anim.rotX) / STAFF_ACTIVATED_BIN_ANGLE_SCALE) +
                obj->anim.localPosZ;
        break;
    }
}

u32 staffactivated_getLiftHeight(GameObject* obj) {
    StaffActivatedState* state = obj->extra;
    return state->liftHeight;
}

void staffactivated_setLiftHeight(GameObject* obj, int height) {
    StaffActivatedState* state = obj->extra;
    state->liftHeight = height;
    state->liftReset = 1;
}

u8 staffactivated_getMode(GameObject* obj) {
    StaffActivatedPlacement* placement = (StaffActivatedPlacement*)obj->anim.placementData;
    return placement->mode;
}

int staffactivated_getExtraSize(void) {
    return sizeof(StaffActivatedState);
}

int staffactivated_getObjectTypeId(void) {
    return STAFF_ACTIVATED_OBJECT_TYPE_ID;
}

void staffactivated_free(GameObject* obj) {
    objFreeObjectType(obj, STAFF_ACTIVATED_OBJECT_GROUP);
}

void staffactivated_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, lbl_803E3BBC);
}

void staffactivated_update(GameObject* obj) {
    PartFxSpawnParams particle;
    StaffActivatedPlacement* placement = (StaffActivatedPlacement*)obj->anim.placementData;
    StaffActivatedState* state = obj->extra;
    GameObject* player;
    int isActive;
    int gameBit;

    player = Obj_GetPlayerObject();

    if (state->flags.locked) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    }

    if (state->flags.active == 0 || playerIsPathFollowing(player) == 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    switch (placement->mode) {
    case STAFF_ACTIVATED_MODE_LIFT:
        staffactivated_updateLiftHeight(obj, state);
        break;
    case STAFF_ACTIVATED_MODE_HIT_REACTION:
        landed_arwing_updateHitReaction(obj, (LandedArwingHitReactionState*)state);
        break;
    case STAFF_ACTIVATED_MODE_DAMAGE_FIRST:
    case STAFF_ACTIVATED_MODE_DAMAGE_SECOND:
        landed_arwing_updateDamageTexture(obj, (LandedArwingHitReactionState*)state);
        break;
    case STAFF_ACTIVATED_MODE_ACTION:
        if (obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) {
            if (mainGetBit(GAMEBIT_SawStaffBoostPad) == 0) {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                mainSetBits(GAMEBIT_SawStaffBoostPad, 1);
            }
        }
        if (mainGetBit(GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER) == 0) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        isActive = 0;
        gameBit = placement->activeGameBit;
        if (gameBit == STAFF_ACTIVATED_GAME_BIT_NONE || mainGetBit(gameBit) != 0) {
            isActive = 1;
        }
        state->flags.active = isActive;
        if (state->flags.active) {
            particle.posX = 2.8f;
            particle.posY = 1.7f;
            particle.posZ = 0.0f;
            particle.scale = lbl_803E3BBC;
            particle.arg3 = 0;
            particle.arg2 = 0x64;
            (*gPartfxInterface)->spawnObject(obj, STAFF_ACTIVATED_PARTICLE_ID, &particle, 2, -1, NULL);
            particle.posX = 2.8f;
            particle.posY = 1.7f;
            particle.posZ = 0.0f;
            particle.scale = lbl_803E3BBC;
            particle.arg3 = 5;
            particle.arg2 = 0xA;
            (*gPartfxInterface)->spawnObject(obj, STAFF_ACTIVATED_PARTICLE_ID, &particle, 2, -1, NULL);
        }
        break;
    default:
        isActive = 0;
        gameBit = placement->activeGameBit;
        if (gameBit == STAFF_ACTIVATED_GAME_BIT_NONE || mainGetBit(gameBit) != 0) {
            isActive = 1;
        }
        state->flags.active = isActive;
        break;
    }
}

void staffactivated_init(GameObject* obj, StaffActivatedPlacement* placement) {
    StaffActivatedState* state;
    int sizeVariant;
    int modelVariant;
    f32 scale;
    StaffActivatedFlags* flags;

    state = obj->extra;
    objAddObjectType(obj, STAFF_ACTIVATED_OBJECT_GROUP);
    obj->anim.rotX = (s16)((s32)placement->rotationX << 8);

    sizeVariant = placement->sizeVariant;
    if (sizeVariant > STAFF_ACTIVATED_LIFT_MAX_SIZE_VARIANT) {
        sizeVariant = STAFF_ACTIVATED_LIFT_MAX_SIZE_VARIANT;
    }

    if (placement->mode == STAFF_ACTIVATED_MODE_LIFT) {
        switch (sizeVariant) {
        case 2:
            modelVariant = 2;
            scale = 1.25f;
            break;
        default:
            modelVariant = 1;
            scale = lbl_803E3BBC;
            break;
        case 0:
            modelVariant = 0;
            scale = 0.75f;
            break;
        }
    } else {
        scale = lbl_803E3BBC;
    }

    if (obj->anim.hitReactState != NULL) {
        ObjHitbox_SetSphereRadius(&obj->anim,
                                  (int)((f32)((ObjHitsPriorityState*)obj->anim.hitReactState)->primaryRadius * scale));
    }

    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase * scale;
    if (obj->anim.rootMotionScale < 0.1f) {
        obj->anim.rootMotionScale = 0.1f;
    }

    switch (placement->mode) {
    case STAFF_ACTIVATED_MODE_LIFT:
        obj->hitVolumeIndex = modelVariant;
        state->targetX =
            -(0.5f * (obj->anim.rootMotionScale * (10.0f * mathSinf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f))) -
              obj->anim.localPosX);
        state->targetZ =
            -(0.5f * (obj->anim.rootMotionScale * (10.0f * mathCosf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f))) -
              obj->anim.localPosZ);
        break;
    case STAFF_ACTIVATED_MODE_HIT_REACTION:
        state->targetX =
            0.5f * (obj->anim.rootMotionScale * (10.0f * mathSinf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f))) +
            obj->anim.localPosX;
        state->targetZ =
            0.5f * (obj->anim.rootMotionScale * (10.0f * mathCosf((3.1415927f * (f32)obj->anim.rotX) / 32768.0f))) +
            obj->anim.localPosZ;
        break;
    default:
        state->targetX = obj->anim.localPosX;
        state->targetZ = obj->anim.localPosZ;
        break;
    }

    flags = &state->flags;
    if (placement->activeGameBit > 0) {
        flags->active = mainGetBit(placement->activeGameBit);
    } else {
        flags->active = 1;
    }
    flags->unk4 = 0;

    if (placement->lockGameBit > 0) {
        if ((flags->locked = mainGetBit(placement->lockGameBit)) != 0) {
            switch (placement->mode) {
            case STAFF_ACTIVATED_MODE_HIT_REACTION:
                ObjAnim_SetMoveProgress(&obj->anim, lbl_803E3BBC);
                break;
            case STAFF_ACTIVATED_MODE_DAMAGE_FIRST:
                flags->locked = 0;
                break;
            case STAFF_ACTIVATED_MODE_LIFT:
                break;
            case STAFF_ACTIVATED_MODE_DAMAGE_SECOND:
                break;
            }
        }
    }
}

ObjectDescriptor gStaffActivatedObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)staffactivated_init,
    (ObjectDescriptorCallback)staffactivated_update,
    0,
    (ObjectDescriptorCallback)staffactivated_render,
    (ObjectDescriptorCallback)staffactivated_free,
    (ObjectDescriptorCallback)staffactivated_getObjectTypeId,
    staffactivated_getExtraSize,
};
