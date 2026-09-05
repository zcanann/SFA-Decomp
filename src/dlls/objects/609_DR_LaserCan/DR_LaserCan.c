/* DR_LaserCan (DLL 609): Dragon Rock laser-cannon object callbacks. */

#include "dlls/objects/609_DR_LaserCan.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/maketex_timer_api.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/rom_curve_interface.h"
#include "dlls/objects/229_Shield.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "game/objects/object.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objfx.h"
#include "main/dll/objfx_api.h"
#include "main/object_update_list.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_play_api.h"

int lbl_803DDD6C;
f32 lbl_803DDD68;
f32 gLaserCannonAdvanceSpeed = 5.0f;
s16 gLaserCannonPitchStep = 0x80;
s16 gLaserCannonMaxAimStep = 0x400;

#define DR_LASERCANNON_ABS(value) ((value) >= 0 ? (value) : -(value))

#define DR_LASERCANNON_GROUP_ID          0x3
#define DR_LASERCANNON_FIREPIPE_GROUP_ID 0x4a

#define DR_LASERCANNON_PITCH_FLIP_TYPE      0x417
#define DR_LASERCANNON_BEAM_OBJECT_TYPE     0x429
#define DR_LASERCANNON_FIREPIPE_OBJECT_TYPE 0x1b5

#define DR_LASERCANNON_SETUP_SIZE       0x20
#define DR_LASERCANNON_INITIAL_HEALTH   4
#define DR_LASERCANNON_HIDDEN_FLAG      0x4000
#define DR_LASERCANNON_TRICKY_COOLDOWN  0x258
#define DR_LASERCANNON_OPTIONAL_GAMEBIT 0xe90

#define DR_LASERCANNON_WARNING_ACTIVE_MODE 4
#define DR_LASERCANNON_WARNING_HIDE_MODE   5
#define DR_LASERCANNON_WARNING_HIT_MODE    6

/* Retain this unused helper: its conversion constant anchors the TU literal pool order. */
static f32 drlasercannon_aimStepFraction(s16 step, s16 limit) {
    return (f32)step / (f32)limit;
}

static const f32 gLaserCannonAngleRateScale = 32768.0f / 180.0f;

int drlasercannon_aimAtTarget(GameObject* self, GameObject* target, ObjJointTrackChannel* out, int maxRate,
                              f32* eyePos) {
    Vec3s* pitchRotation;
    f32 direction[3];
    f32 horizontalDistance;
    s16 angles[2];
    int i;
    s16 wrapDelta;

    /* Fetch the barrel's secondary rotation vector (pitch channel) from the model. */
    pitchRotation = (Vec3s*)objFindJointPoseVector(self, 0xb);
    if (pitchRotation == NULL) {
        return 0;
    }
    /* No target: ease both yaw and pitch back toward rest by halving each frame. */
    if (target == NULL) {
        self->anim.rotX = (s16)(self->anim.rotX >> 1);
        pitchRotation->x = (s16)(pitchRotation->x >> 1);
        return 0;
    }
    /* Vector from the cannon's eye position to the target. */
    for (i = 0; i < 3; i++) {
        direction[i] = ((f32*)&target->anim.localPos)[i] - eyePos[i];
    }
    horizontalDistance = sqrtf(direction[0] * direction[0] + direction[2] * direction[2]);
    /* Desired yaw from the ground-plane heading, pitch from height over horizontal range. */
    angles[0] = getAngle(direction[0], direction[2]);
    angles[1] = (s16)getAngle(direction[1], horizontalDistance);
    if (self->anim.romDefNo == DR_LASERCANNON_PITCH_FLIP_TYPE) {
        angles[1] = (s16)-angles[1];
    }
    /* Below the full-speed threshold, clamp the requested aim to a scaled per-frame angle. */
    if (maxRate < 0x168) {
        maxRate = (s16)(gLaserCannonAngleRateScale * maxRate);
        for (i = 0; i < 2; i++) {
            out[i].angle = angles[i];
            if (out[i].angle > maxRate) {
                out[i].angle = maxRate;
            }
            if (out[i].angle < -maxRate) {
                out[i].angle = -maxRate;
            }
        }
    } else {
        out[0].angle = angles[0];
        out[1].angle = angles[1];
    }
    /* Shortest signed angular delta from current yaw to target, wrapped into [-0x8000, 0x8000]. */
    wrapDelta = out[0].angle - (u16)self->anim.rotX;
    if (wrapDelta > 0x8000) {
        wrapDelta = wrapDelta - 0xFFFF;
    }
    if (wrapDelta < -0x8000) {
        wrapDelta = wrapDelta + 0xFFFF;
    }
    /* Limit the step to the max aim rate, then interpolate current yaw toward the target. */
    wrapDelta = (wrapDelta < -gLaserCannonMaxAimStep)
                    ? -gLaserCannonMaxAimStep
                    : (s16)((wrapDelta > gLaserCannonMaxAimStep) ? gLaserCannonMaxAimStep : wrapDelta);
    self->anim.rotX = (s16)((f32)self->anim.rotX + interpolate((f32)wrapDelta, 0.25f, timeDelta));
    /* Same wrap-and-step interpolation applied to the pitch channel. */
    if (pitchRotation != NULL) {
        wrapDelta = out[1].angle - (u16)pitchRotation->x;
        if (wrapDelta > 0x8000) {
            wrapDelta = wrapDelta - 0xFFFF;
        }
        if (wrapDelta < -0x8000) {
            wrapDelta = wrapDelta + 0xFFFF;
        }
        wrapDelta = (wrapDelta < -gLaserCannonMaxAimStep)
                        ? -gLaserCannonMaxAimStep
                        : (s16)((wrapDelta > gLaserCannonMaxAimStep) ? gLaserCannonMaxAimStep : wrapDelta);
        pitchRotation->x = (s16)(pitchRotation->x + interpolate((f32)wrapDelta, 0.25f, timeDelta));
    }
    /* Report whether yaw is still far (> 0x100) from the target, i.e. not yet on-aim. */
    return DR_LASERCANNON_ABS(self->anim.rotX - out[0].angle) > 0x100;
}

GameObject* drlasercannon_getTrackedTarget(GameObject* obj, int* cooldownTimer) {
    int* tricky = (int*)getTrickyObject();
    GameObject* player;
    GameObject* target;
    int cooldown;
    if (tricky != 0 && cooldownTimer != 0 && TRICKY_INTERFACE(tricky)->isPlayingBall((GameObject*)tricky)) {
        cooldown = *cooldownTimer - framesThisStep;
        *cooldownTimer = cooldown;
        if (cooldown < 0) {
            TRICKY_INTERFACE(tricky)->commandPlayBall((GameObject*)tricky, 0, NULL);
            *cooldownTimer = DR_LASERCANNON_TRICKY_COOLDOWN;
        }
        return (GameObject*)tricky;
    }
    player = Obj_GetPlayerObject();
    if (player != 0) {
        target = playerGetFocusObject(player);
        if (target != 0 && (target->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            return target;
        }
        if ((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
            return player;
        }
    }
    return NULL;
}

int DR_LaserCannon_getExtraSize(void) {
    return sizeof(DrLaserCannonState);
}

int DR_LaserCannon_getObjectTypeId(void) {
    return 0x0;
}

void DR_LaserCannon_free(GameObject* obj) {
    DrLaserCannonState* state = (obj)->extra;
    if (state->firepipeObject != NULL) {
        firepipe_clearLinkedUpdateFlag(state->firepipeObject);
        ObjLink_DetachChild(obj, state->firepipeObject);
    }
    if (state->warningObject != NULL) {
        Obj_FreeObject(state->warningObject);
    }
    objFreeObjectType(obj, DR_LASERCANNON_GROUP_ID);
}

void DR_LaserCannon_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible) {
    DrLaserCannonState* state = (obj)->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)1.0f);
        ObjPath_GetPointWorldPosition(obj, 0, &state->muzzleX, &state->muzzleY, &state->muzzleZ, 0);
        state->muzzleY = state->muzzleY - 5.0f;
    }
}

void DR_LaserCannon_hitDetect(GameObject* obj) {
    DrLaserCannonState* state = (obj)->extra;
    DrLaserCannonSetup* setup = (DrLaserCannonSetup*)(obj)->anim.placementData;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    u32 hitVolume;
    GameObject* hitObject;
    int hit;
    int* tricky;
    if (state->flags.b0 || state->flags.b3) {
        return;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, 0, &hitVolume, &hitPosX, &hitPosY, &hitPosZ);
    if (state->flags.b6 != 0) {
        if (hit != 0 && hitObject->anim.romDefNo != state->hitExcludeType && state->warningObject != NULL) {
            Shield_setMode(state->warningObject, DR_LASERCANNON_WARNING_HIT_MODE);
        }
    } else if (((u32)(hit - 0xe) <= 1 || hit == 5) && state->lastHitObject != hitObject &&
               hitObject->anim.romDefNo != state->hitExcludeType) {
        state->lastHitObject = hitObject;
        state->health -= hitVolume;
        Obj_SpawnHitLightAndFade(obj, (const Vec3f*)&hitPosX, 6.0f);
        objfx_shakeCameraByDistance(obj, 300.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_ar_awghitobj16);
        if (state->health <= 0) {
            tricky = (int*)getTrickyObject();
            Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11_4b6);
            spawnExplosion((GameObject*)obj, 50.0f, 0, 1, 1, 1, 0, 1, 0);
            state->flags.b0 = 1;
            mainSetBits(setup->destroyedGameBit, 1);
            if (tricky != 0) {
                TRICKY_INTERFACE(tricky)->commandPlayBall((GameObject*)tricky, 0, NULL);
            }
            (obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (hit == 0) {
        state->lastHitObject = 0;
    } else {
        state->lastHitObject = hitObject;
    }
}

void DR_LaserCannon_update(GameObject* obj) {
    GameObject* target;
    DrLaserCannonState* state = (obj)->extra;
    DrLaserCannonSetup* setup = (DrLaserCannonSetup*)(obj)->anim.placementData;
    GameObject* player = Obj_GetPlayerObject();
    GameObject* spawned;
    DrLaserCannonState* cannonState;
    int hit;
    f32 dist;
    f32 nearDist;
    int spawnFlag;
    f32 hitPos[3];
    f32 outv[6];
    f32 inv[6];
    (obj)->anim.localPosY -= state->bobOffset;
    if (state->flags.b7 != 0) {
        nearDist = 50.0f;
        if ((state->firepipeObject = objGetNearestTypeTo(DR_LASERCANNON_FIREPIPE_GROUP_ID, obj, &nearDist)) != 0u) {
            state->hasFirepipe = 1;
            ObjLink_AttachChild(obj, state->firepipeObject, 0);
            firepipe_setLinkedUpdateFlag(state->firepipeObject);
        }
        state->flags.b7 = 0;
    }
    if (state->flags.b4 == 0) {
        if (mainGetBit(setup->destroyedGameBit) != 0) {
            state->flags.b4 = 1;
            state->flags.b0 = 1;
            (obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (state->flags.b0 != 0) {
        return;
    }
    if (state->warningObject != NULL) {
        state->warningObject->anim.localPosX = (obj)->anim.localPosX;
        state->warningObject->anim.localPosY = (obj)->anim.localPosY - 30.0f;
        state->warningObject->anim.localPosZ = (obj)->anim.localPosZ;
    }
    if (state->flags.b6 != 0) {
        if (mainGetBit(setup->warningOffGameBit) != 0) {
            state->flags.b6 = 0;
            if (state->warningObject != NULL) {
                Shield_setMode(state->warningObject, DR_LASERCANNON_WARNING_HIDE_MODE);
            }
        }
    } else {
        objfx_spawnFrameTimedHitPulse(obj, 3.5f, 1, (u8)(5 - state->health), -5.0f);
        if (state->warningObject != NULL) {
            Shield_setMode(state->warningObject, DR_LASERCANNON_WARNING_HIDE_MODE);
        }
        state->activeFrames += 1;
        if (state->health == 0) {
            return;
        }
    }
    target = drlasercannon_getTrackedTarget(obj, &state->trickyCooldown);
    if ((void*)target != NULL && (state->optionalGameBit == -1 || mainGetBit(state->optionalGameBit) == 0)) {
        hit = 1;
        dist = Vec_xzDistance(&target->anim.worldPosX, &(obj)->anim.worldPosX);
        if (dist < setup->targetRange) {
            hit = drlasercannon_aimAtTarget(obj, (GameObject*)target, state->aim, 0x168, &state->muzzleX);
            if (hit != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_id_1ad);
            }
        } else {
            s16* v;
            (obj)->anim.rotX += gLaserCannonPitchStep;
            v = (s16*)objFindJointPoseVector(obj, 0xb);
            v[0] = (s16)(v[0] >> 1);
        }
        if (hit == 0 && dist < setup->targetRange) {
            if ((void*)target == (void*)player) {
                objGetFirstChild(player);
            }
            switch (state->hasFirepipe) {
            case 0:
                state->hitExcludeType = DR_LASERCANNON_BEAM_OBJECT_TYPE;
                if (timerCountDown(&state->reloadTimer) != 0) {
                    if (Obj_PredictInterceptPoint((GameObject*)target, setup->beamSpeed / 10.0f,
                                                  (const Vec3f*)&state->muzzleX, (Vec3f*)hitPos) != 0) {
                        cannonState = (obj)->extra;
                        if ((u8)Obj_CanSetupObject() == 0) {
                            spawned = NULL;
                        } else {
                            ObjPlacement* o =
                                Obj_AllocObjectSetup(DR_LASERCANNON_SETUP_SIZE, DR_LASERCANNON_BEAM_OBJECT_TYPE);
                            o->objectId = DR_LASERCANNON_BEAM_OBJECT_TYPE;
                            o->size = 8;
                            o->color[0] = 1;
                            o->color[2] = 0xff;
                            o->color[1] = 1;
                            o->color[3] = 0xff;
                            o->posX = cannonState->muzzleX;
                            o->posY = cannonState->muzzleY;
                            o->posZ = cannonState->muzzleZ;
                            spawned = objSetupObject(o, 5, (obj)->anim.mapEventSlot, -1, NULL);
                        }
                        if (spawned != NULL) {
                            outv[3] = state->muzzleX;
                            outv[4] = state->muzzleY;
                            outv[5] = state->muzzleZ;
                            inv[3] = hitPos[0];
                            inv[4] = hitPos[1];
                            inv[5] = hitPos[2];
                            (*(void (**)(int, f32*, f32*, f32))(*(int*)((int)spawned->anim.dll) + 0x24))(
                                (int)spawned, outv, inv, setup->beamSpeed / 10.0f);
                            state->beamObject = (int)spawned;
                            ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                            state->animStepScale = 0.018f;
                            Sfx_PlayFromObject(obj, SFXTRIG_wp_cahit2_c);
                            Sfx_PlayFromObject(obj, SFXTRIG_wp_blasershot11);
                        }
                    }
                    s16toFloat(&state->reloadTimer, (s16)(setup->reloadFrames << 2));
                }
                break;
            case 1:
                state->hitExcludeType = DR_LASERCANNON_FIREPIPE_OBJECT_TYPE;
                firepipe_setLinkedUpdateFlag(state->firepipeObject);
                break;
            }
        } else if (state->firepipeObject != NULL) {
            firepipe_clearLinkedUpdateFlag(state->firepipeObject);
        }
    }
    spawned = state->firepipeObject;
    if (spawned != NULL) {
        if ((spawned->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
            state->firepipeObject = 0;
        } else {
            s16* v = (s16*)objFindJointPoseVector(obj, 0xb);
            *(s16*)spawned = (s16)((f32) * (s16*)obj + lbl_803DDD68);
            spawned->anim.rotY = v[0];
        }
    }
    if (state->flags.b5 != 0) {
        Obj_UpdateRomCurveFollowVelocity(obj, &state->curveFollow, 0.1f * gLaserCannonAdvanceSpeed, 200.0f, 10.0f, 1);
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
    } else {
        spawnFlag = 1;
        if ((*gRomCurveInterface)->initCurve(&state->curveFollow, (void*)obj, 100.0f, &spawnFlag, 0) == 0) {
            state->flags.b5 = 1;
            obj->anim.localPosX = state->curveFollow.posX;
            obj->anim.localPosZ = state->curveFollow.posZ;
            obj->anim.localPosY = state->curveFollow.posY;
        }
    }
    {
        GameObject* tricky = getTrickyObject();
        if (tricky != NULL) {
            TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY,
                                                        TRICKY_COMMAND_TYPE_DISTRACT);
        }
    }
    hit = ObjAnim_AdvanceCurrentMove(obj, state->animStepScale, timeDelta, 0);
    if ((obj)->anim.currentMove == 1 && hit != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        state->animStepScale = 0.005f;
    }
    state->bobPhase = (250.0f * timeDelta + (f32)(u32)state->bobPhase);
    state->bobOffset = 5.0f * mathSinf(3.1415927f * (f32)(u32)state->bobPhase / 32768.0f);
    (obj)->anim.localPosY += state->bobOffset;
}

void DR_LaserCannon_init(GameObject* obj, DrLaserCannonSetup* setup) {
    DrLaserCannonState* state = (obj)->extra;
    f32 fz;
    state->health = DR_LASERCANNON_INITIAL_HEALTH;
    ObjHits_EnableObject(obj);
    if (mainGetBit(setup->destroyedGameBit) != 0) {
        (obj)->anim.flags |= DR_LASERCANNON_HIDDEN_FLAG;
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
    }
    objAddObjectType(obj, DR_LASERCANNON_GROUP_ID);
    state->beamObject = 0;
    state->flags.b3 = 0;
    (obj)->anim.rotX = (s16)(setup->initialYaw << 8);
    state->trickyCooldown = DR_LASERCANNON_TRICKY_COOLDOWN;
    state->animStepScale = 0.005f;
    if (mainGetBit(setup->destroyedGameBit) != 0) {
        state->flags.b0 = 1;
        state->flags.b4 = 1;
    } else {
        state->flags.b4 = 0;
    }
    state->flags.b5 = 0;
    fz = 0.0f;
    (obj)->anim.velocityX = fz;
    (obj)->anim.velocityY = fz;
    (obj)->anim.velocityZ = fz;
    if (mainGetBit(setup->destroyedGameBit) == 0) {
        state->warningObject = Shield_spawnOmniShield(obj, 15.0f);
        if (state->warningObject != NULL) {
            Shield_setMode(state->warningObject, DR_LASERCANNON_WARNING_ACTIVE_MODE);
        }
        state->flags.b6 = 1;
    } else {
        state->flags.b6 = 0;
        state->warningObject = NULL;
    }
    storeZeroToFloatParam(&state->reloadTimer);
    s16toFloat(&state->reloadTimer, (s16)(setup->reloadFrames * 4 + 1));
    state->hasFirepipe = 0;
    state->flags.b7 = 1;
    state->hitExcludeType = DR_LASERCANNON_BEAM_OBJECT_TYPE;
    if ((obj)->anim.mapEventSlot == 2) {
        state->optionalGameBit = DR_LASERCANNON_OPTIONAL_GAMEBIT;
    } else {
        state->optionalGameBit = -1;
    }
}

void DR_LaserCannon_release(void) {
}

void DR_LaserCannon_initialise(void) {
}

ObjectDescriptor gDrLaserCannonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_LaserCannon_initialise,
    (ObjectDescriptorCallback)DR_LaserCannon_release,
    0,
    (ObjectDescriptorCallback)DR_LaserCannon_init,
    (ObjectDescriptorCallback)DR_LaserCannon_update,
    (ObjectDescriptorCallback)DR_LaserCannon_hitDetect,
    (ObjectDescriptorCallback)DR_LaserCannon_render,
    (ObjectDescriptorCallback)DR_LaserCannon_free,
    (ObjectDescriptorCallback)DR_LaserCannon_getObjectTypeId,
    DR_LaserCannon_getExtraSize,
};
