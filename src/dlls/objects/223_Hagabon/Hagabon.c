/*
 * Hagabon object (DLL slot 223).
 *
 * Follows a ROM curve, chases nearby players, and handles its gated fade and
 * hit reactions.
 */
#include "dlls/objects/223_Hagabon.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/objfx_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/mm.h"
#include "main/objanim.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "main/curve.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/objtype.h"
#include "main/mapEventTypes.h"

#define HAGABON_HIT_VOLUME_SLOT 10
#define HAGABON_OBJECT_GROUP    3

#define HAGABON_FLAG_PATH_NEEDS_LINK 0x01
#define HAGABON_FLAG_CHASE           0x02
#define HAGABON_FLAG_PATH_RETURN     0x04
#define HAGABON_FLAG_FADE_IN         0x08
#define HAGABON_FLAG_FADE_OUT        0x10

#define HAGABON_GAME_BIT_NONE          -1
#define HAGABON_ALPHA_MAX              255.0f
#define HAGABON_FADE_OUT_END_ALPHA     6
#define HAGABON_FADE_IN_END_ALPHA      0xf9
#define HAGABON_PARTICLE_FADE_OUT      3
#define HAGABON_PARTICLE_FADE_IN       4
#define HAGABON_SOUND_START_DISTANCE   300.0f
#define HAGABON_SOUND_STOP_DISTANCE    350.0f
#define HAGABON_SOUND_CHANNEL_ALL      0x7f
#define HAGABON_MAP_SECONDS_PER_MINUTE 60
#define HAGABON_PATH_RETURN_DISTANCE   250.0f
#define HAGABON_PATH_RESUME_DISTANCE   30.0f
#define HAGABON_CURVE_STEP_DIVISOR     100.0f
#define HAGABON_ANIMATION_SPEED        0.005f
#define HAGABON_CHASE_RADIUS_SCALE     4.0f
#define HAGABON_CURVE_ALLOCATOR_TAG    0x1a

typedef union HagabonAnimEventBuffer {
    ObjAnimEventList events;
    u8 storage[0x20];
} HagabonAnimEventBuffer;

STATIC_ASSERT(sizeof(HagabonAnimEventBuffer) == 0x20);

int gHagabonCurveInitData[2] = {2, 3};
int gHagabonLastCurvePoint;

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Hagabon_initialise,
    (ObjectDescriptorCallback)Hagabon_release,
    0,
    (ObjectDescriptorCallback)Hagabon_init,
    (ObjectDescriptorCallback)Hagabon_update,
    (ObjectDescriptorCallback)Hagabon_hitDetect,
    (ObjectDescriptorCallback)Hagabon_render,
    (ObjectDescriptorCallback)Hagabon_free,
    (ObjectDescriptorCallback)Hagabon_getObjectTypeId,
    Hagabon_getExtraSize,
};

void Hagabon_updateMovement(GameObject* obj, HagabonState* state) {
    RomCurveWalker* curve;
    GameObject* player;
    int angleDelta;
    int angle;
    HagabonAnimEventBuffer animEvents;
    f32 waveA;
    f32 waveB;
    f32 damp;

    curve = state->curve;

    if (((Curve_AdvanceAlongPath(&curve->curve, state->curveStep) != 0) ||
         (curve->atSegmentEnd != gHagabonLastCurvePoint)) &&
        ((*gRomCurveInterface)->goNextPoint((void*)curve) != 0) &&
        ((*gRomCurveInterface)->initCurve((void*)state->curve, (void*)obj, (400.0f), gHagabonCurveInitData, -1) != 0)) {
        state->flags &= ~HAGABON_FLAG_PATH_NEEDS_LINK;
    }

    gHagabonLastCurvePoint = curve->atSegmentEnd;

    state->wavePhaseA += (u16)(128.0f * timeDelta);
    state->wavePhaseB += (u16)(256.0f * timeDelta);
    state->wavePhaseC += (u16)(512.0f * timeDelta);

    obj->anim.rotZ = (s16)((1000.0f) * (mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseA) / (32768.0f)) +
                                        mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseB) / (32768.0f))));

    obj->anim.rotY = (s16)((1000.0f) * (mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseA) / (32768.0f)) +
                                        mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseC) / (32768.0f))));

    if ((state->flags & HAGABON_FLAG_CHASE) != 0) {
        obj->anim.velocityX += (0.001f) * (state->player->anim.localPosX - obj->anim.localPosX);
        obj->anim.velocityY += (0.001f) * ((60.0f + state->player->anim.localPosY) - obj->anim.localPosY);
        obj->anim.velocityZ += (0.001f) * (state->player->anim.localPosZ - obj->anim.localPosZ);
    } else if ((state->flags & HAGABON_FLAG_PATH_RETURN) != 0) {
        obj->anim.velocityX += (0.001f) * (curve->posX - obj->anim.localPosX);
        obj->anim.velocityY += (0.001f) * (curve->posY - obj->anim.localPosY);
        obj->anim.velocityZ += (0.001f) * (curve->posZ - obj->anim.localPosZ);
    } else {
        obj->anim.velocityX += (0.001f) * (curve->posX - obj->anim.localPosX);
        waveA = mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseB) / (32768.0f));
        waveB = mathSinf(((3.1415927f) * (f32)(u32)state->wavePhaseA) / (32768.0f));
        waveA = waveB + waveA;
        waveA = ((10.0f * waveA) + curve->posY) - obj->anim.localPosY;
        obj->anim.velocityY += (0.001f) * waveA;
        obj->anim.velocityZ += (0.001f) * (curve->posZ - obj->anim.localPosZ);
    }

    obj->anim.velocityX *= (damp = 0.9f);
    obj->anim.velocityY *= damp;
    obj->anim.velocityZ *= damp;

    if (obj->anim.velocityX > 0.5f) {
        obj->anim.velocityX = 0.5f;
    }
    if (obj->anim.velocityY > 0.5f) {
        obj->anim.velocityY = 0.5f;
    }
    if (obj->anim.velocityZ > 0.5f) {
        obj->anim.velocityZ = 0.5f;
    }

    if (obj->anim.velocityX < -0.5f) {
        obj->anim.velocityX = -0.5f;
    }
    if (obj->anim.velocityY < -0.5f) {
        obj->anim.velocityY = -0.5f;
    }
    if (obj->anim.velocityZ < -0.5f) {
        obj->anim.velocityZ = -0.5f;
    }

    (void)objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                  obj->anim.velocityZ * timeDelta);
    (void)ObjAnim_AdvanceCurrentMove(obj, state->animSpeed, timeDelta, &animEvents.events);

    player = state->player;
    angle = (u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX, obj->anim.worldPosZ - player->anim.worldPosZ);
    angleDelta = angle - ((int)obj->anim.rotX & 0xffff);
    if (angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }

    obj->anim.rotX += (s32)(((f32)angleDelta * timeDelta) / 12.0f);
}

int Hagabon_getExtraSize(void) {
    return sizeof(HagabonState);
}

int Hagabon_getObjectTypeId(void) {
    return 0xb;
}

void Hagabon_free(GameObject* objAddress) {
    void** curveSlot = objAddress->extra;
    objFreeObjectType(objAddress, HAGABON_OBJECT_GROUP);
    Sfx_StopFromObject(objAddress, SFXTRIG_en_twiggysnap11);
    if (*curveSlot != NULL) {
        mm_free(*curveSlot);
        *curveSlot = NULL;
    }
}

void Hagabon_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    HagabonState* state = obj->extra;
    s32 visible32 = visible;
    if (visible32 != 0) {
        switch (obj->userData1) {
        case 0:
            objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
            if ((state->flags & HAGABON_FLAG_FADE_OUT) != 0) {
                objDoParticleFx(obj, 1.0f, HAGABON_PARTICLE_FADE_OUT,
                                       (f32)(u32)obj->anim.alpha / HAGABON_ALPHA_MAX, 0);
            }
            if ((state->flags & HAGABON_FLAG_FADE_IN) != 0) {
                objDoParticleFx(obj, 1.0f, HAGABON_PARTICLE_FADE_IN,
                                       (f32)(u32)obj->anim.alpha / HAGABON_ALPHA_MAX, 0);
            }
            break;
        }
    }
}

void Hagabon_hitDetect(GameObject* obj) {
    ObjHitsPriorityState* hitState;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState->lastHitObject != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_32b);
    }
}

void Hagabon_update(GameObject* obj) {
    GameObject* player;
    HagabonState* state;
    RomCurveWalker* oldCurve;
    HagabonPlacement* placement;
    PartFxSpawnParams effectParams;
    f32 distanceDelta[3];
    f32 dist;
    GameObject* hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    u8 flags;

    state = obj->extra;
    oldCurve = state->curve;
    placement = (HagabonPlacement*)obj->anim.placementData;

    if (obj->userData1 != 0) {
        if ((placement->armGameBit != HAGABON_GAME_BIT_NONE) && (mainGetBit(placement->armGameBit) != 0)) {
            return;
        }
        if ((*gMapEventInterface)->shouldNotSaveTime(placement->base.ident) == 0) {
            return;
        }
        obj->userData1 = 0;
        obj->anim.alpha = 1;
        state->flags |= HAGABON_FLAG_FADE_IN;
        Sfx_PlayFromObject(obj, SFXTRIG_dn_seal4_c);
        return;
    }

    player = Obj_GetPlayerObject();
    dist = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
    if (dist < HAGABON_SOUND_START_DISTANCE) {
        Sfx_PlayFromObject(obj, SFXTRIG_en_twiggysnap11);
    } else if (dist > HAGABON_SOUND_STOP_DISTANCE) {
        Sfx_StopFromObject(obj, SFXTRIG_en_twiggysnap11);
    }

    if ((obj->anim.alpha != 0) && (((flags = state->flags) & (HAGABON_FLAG_FADE_IN | HAGABON_FLAG_FADE_OUT)) != 0)) {
        if ((flags & HAGABON_FLAG_FADE_OUT) != 0) {
            obj->anim.alpha = (u8)((f32)(u32)obj->anim.alpha - timeDelta);
            if (obj->anim.alpha <= HAGABON_FADE_OUT_END_ALPHA) {
                obj->userData1 = 1;
                obj->anim.alpha = 0;
                state->flags &= ~HAGABON_FLAG_FADE_OUT;
                Sfx_StopFromObject(obj, SFXTRIG_en_twiggysnap11);
            }
            ObjHits_DisableObject(obj);
        }
        if ((state->flags & HAGABON_FLAG_FADE_IN) != 0) {
            obj->anim.alpha = (u8)((f32)(u32)obj->anim.alpha + timeDelta);
            if (obj->anim.alpha >= HAGABON_FADE_IN_END_ALPHA) {
                obj->anim.alpha = 0xff;
                state->flags &= ~HAGABON_FLAG_FADE_IN;
            }
        }
    } else {
        if (ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume, &effectParams.posX, &effectParams.posY,
                                               &effectParams.posZ) != 0) {
            Sfx_StopObjectChannel(obj, HAGABON_SOUND_CHANNEL_ALL);
            state->flags |= HAGABON_FLAG_FADE_OUT;
            Sfx_PlayFromObject(obj, SFXTRIG_en_rfall5_c);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
            Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_238);
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stftest122_1f2);
            effectParams.posX += playerMapOffsetX;
            effectParams.posZ += playerMapOffsetZ;
            objDoHitParticleFx((void*)obj, 0.014f, &effectParams, 3, 0);
            (*gMapEventInterface)
                ->addTime(placement->base.ident, (f32)(s32)(placement->timeReward * HAGABON_MAP_SECONDS_PER_MINUTE));
            if (placement->armGameBit != HAGABON_GAME_BIT_NONE) {
                mainSetBits(placement->armGameBit, 1);
            }
        }
        ObjHits_SetHitVolumeSlot(&obj->anim, HAGABON_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
    }

    state->player = Obj_GetPlayerObject();
    player = state->player;
    if (player != NULL) {
        f32* delta = distanceDelta;
        delta[0] = player->anim.worldPosX - obj->anim.worldPosX;
        delta[1] = player->anim.worldPosY - obj->anim.worldPosY;
        delta[2] = player->anim.worldPosZ - obj->anim.worldPosZ;
        state->playerDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }
    if (oldCurve != NULL) {
        f32* delta = distanceDelta;
        delta[0] = oldCurve->posX - obj->anim.worldPosX;
        delta[1] = oldCurve->posY - obj->anim.worldPosY;
        delta[2] = oldCurve->posZ - obj->anim.worldPosZ;
        state->pathDistance = sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1]));
    }
    if (((state->flags & HAGABON_FLAG_CHASE) != 0) && (state->pathDistance > HAGABON_PATH_RETURN_DISTANCE)) {
        state->flags &= ~HAGABON_FLAG_CHASE;
        state->flags |= HAGABON_FLAG_PATH_RETURN;
    }
    if (((state->flags & HAGABON_FLAG_PATH_RETURN) != 0) && (state->pathDistance < HAGABON_PATH_RESUME_DISTANCE)) {
        state->flags &= ~HAGABON_FLAG_PATH_RETURN;
    }
    if (((state->flags & (HAGABON_FLAG_CHASE | HAGABON_FLAG_PATH_RETURN)) == 0) && (placement->startInactive == 0) &&
        (state->player != NULL) && (state->playerDistance < state->chaseRadius)) {
        state->flags |= HAGABON_FLAG_CHASE;
    }
    Hagabon_updateMovement(obj, state);
}

void Hagabon_init(GameObject* obj, HagabonPlacement* placement, int skipAlloc) {
    HagabonState* state = obj->extra;
    state->curveStep = (f32)(s32)placement->curveStepRaw / HAGABON_CURVE_STEP_DIVISOR;
    state->animSpeed = HAGABON_ANIMATION_SPEED;
    state->chaseRadius = HAGABON_CHASE_RADIUS_SCALE * (f32)(s32)placement->chaseRadiusScale;
    if (skipAlloc == 0) {
        state->curve = mmAlloc(sizeof(RomCurveWalker), HAGABON_CURVE_ALLOCATOR_TAG, 0);
        if (state->curve != NULL) {
            memset(state->curve, 0, sizeof(RomCurveWalker));
        }
        if ((*gRomCurveInterface)
                ->initCurve((void*)state->curve, (void*)obj, state->chaseRadius, gHagabonCurveInitData, -1) == 0) {
            state->flags |= HAGABON_FLAG_PATH_NEEDS_LINK;
        }
    }
    if (placement->armGameBit != HAGABON_GAME_BIT_NONE) {
        if (mainGetBit(placement->armGameBit) != 0) {
            obj->userData1 = 1;
        }
    }
}

void Hagabon_release(void) {
}

void Hagabon_initialise(void) {
}
