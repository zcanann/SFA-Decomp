/*
 * DIM_BossGut (DLL 0x1E3) - the DarkIce Mines boss's mobile gut target.
 * It follows a ROM curve, bobs at the water surface, emits splash particles,
 * and owns the target's green point light.
 */
#include "dlls/objects/483_DIM_BossGut.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/curve.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/curve_walker.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/model_light.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIMBOSSGUT2_OBJGROUP           3
#define DIMBOSSGUT2_PARTFX             0x32b
#define DIMBOSSGUT2_OBJECT_TYPE_ID     0x49
#define DIMBOSSGUT2_WATER_SURFACE_TYPE 0xE
static void dimbossgut2_spawnBreathSplash(GameObject* obj, DimBossGut2Control* control, PartFxSpawnParams* effectParams) {
    u32 randomThreshold;
    f32 heightDiff;
    f32 xyScale;

    if ((control->verticalVelocity < -0.025f) && (control->pathSpeed < 0.25f)) {
        heightDiff = control->surfaceY - obj->anim.localPosY;
        if (heightDiff < 0.0f) {
            heightDiff = -heightDiff;
        }
        if ((heightDiff < 14.0f) &&
            (effectParams->posY = control->surfaceY, randomThreshold = randomGetRange(0x1e, 0x3c),
             (int)(u32)control->breathFxTimer > (int)randomThreshold)) {
            xyScale = 20.0f * control->pathSpeed;
            effectParams->posX = obj->anim.localPosX - xyScale * mathSinf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
            effectParams->posZ = obj->anim.localPosZ - xyScale * mathCosf(3.1415927f * (f32)obj->anim.rotX / 32768.0f);
            effectParams->scale = 0.65f * (1.0f - heightDiff / 14.0f);
            (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSGUT2_PARTFX, effectParams, 1, -1, NULL);
            control->breathFxTimer = 0;
        }
    }
}

void dimbossgut2_updateBobAndSway(GameObject* obj, DimBossGut2State* state) {
    DimBossGut2Control* control;
    f32 heightDelta;
    s16 rollDelta;

    control = state->groundBaddie.control;
    heightDelta = control->surfaceY - obj->anim.localPosY;

    control->bobPhase += 0x400;
    heightDelta = heightDelta + (f32)sin16(control->bobPhase) / 65535.0f;

    control->verticalVelocity = timeDelta * (heightDelta / 50.0f - control->turnHeightBias) + control->verticalVelocity;

    obj->anim.localPosY = obj->anim.localPosY + control->verticalVelocity;

    obj->anim.rotY = (s16)(2048.0f * control->verticalVelocity);

    rollDelta = (s16) - (u16)obj->anim.rotZ;
    if (rollDelta > 0x8000) {
        rollDelta = (s16)((rollDelta - 0x10000) + 1);
    }
    if (rollDelta < (s16)-0x8000) {
        rollDelta = (s16)((rollDelta + 0x10000) - 1);
    }

    control->swayVelocity = control->swayVelocity + (f32)((int)(rollDelta / 16) * framesThisStep);
    obj->anim.rotZ = (s16)((f32)(int)obj->anim.rotZ + control->swayVelocity);

    control->verticalVelocity = control->verticalVelocity / 1.07f;
    control->swayVelocity = control->swayVelocity / 1.04f;
}

void dimbossgut2_updateTracking(GameObject* obj, DimBossGut2State* state) {
    DimBossGut2Control* control;
    RomCurveWalker* pathWalker;
    s16 delta;
    s16 angle;
    int angleMag;
    f32 angleScale;
    GameObject* player;
    int rel;

    control = state->groundBaddie.control;
    pathWalker = state->groundBaddie.path;
    if ((state->groundBaddie.flags400 & BADDIE_FLAG400_PATH_ACTIVE) != 0) {
        if ((Curve_AdvanceAlongPath(&pathWalker->curve, control->pathSpeed) != 0) || pathWalker->atSegmentEnd != 0) {
            if ((*gRomCurveInterface)->goNextPoint((void*)pathWalker) != 0) {
                state->groundBaddie.flags400 &= ~BADDIE_FLAG400_PATH_ACTIVE;
            }
        }
        angle = (s16)(getAngle(pathWalker->tangentX, pathWalker->tangentZ) + 0x8000);
        delta = (s16)(angle - (u16)obj->anim.rotX);
        if (delta > 0x8000) {
            delta = (s16)(delta - 0xffff);
        }
        if (delta < -0x8000) {
            delta = (s16)(delta + 0xffff);
        }
        obj->anim.rotX = angle;
        control->swayVelocity = control->swayVelocity + (f32)(delta >> 4);
        if (control->pathSpeed < 0.15f) {
            control->pathSpeed += 0.002f;
        }
        angleMag = delta / 0xb6;
        if (angleMag < 0) {
            angleMag = -angleMag;
        }
        angleScale = (f32)(s32)angleMag;
        angleScale *= 0.25f;
        if (angleScale > 1.0f) {
            control->pathSpeed = control->pathSpeed / angleScale;
            control->turnHeightBias += 0.01f;
        }
        if (control->turnHeightBias > 0.0f) {
            control->turnHeightBias = control->turnHeightBias / 1.04f;
        }
        obj->anim.localPosX = pathWalker->posX;
        obj->anim.localPosZ = pathWalker->posZ;
    } else {
        player = Obj_GetPlayerObject();
        rel = (int)(u16)getAngle(-(player->anim.worldPosX - obj->anim.worldPosX),
                                 -(player->anim.worldPosZ - obj->anim.worldPosZ)) -
              (int)(u16)obj->anim.rotX;
        if (rel > 0x8000) {
            rel = rel - 0xffff;
        }
        if (rel < -0x8000) {
            rel = rel + 0xffff;
        }
        obj->anim.rotX = (s16)(*(s16*)(long)obj + rel * framesThisStep / 3);
    }
}

void DIM_BossGut2_func0B(void) {
}

int DIM_BossGut2_func0A(void) {
    return 0;
}

int DIM_BossGut2_getExtraSize(void) {
    return sizeof(DimBossGut2State);
}

int DIM_BossGut2_getObjectTypeId(void) {
    return DIMBOSSGUT2_OBJECT_TYPE_ID;
}

void DIM_BossGut2_free(GameObject* obj) {
    ModelLightStruct* light;
    DimBossGut2State* state;
    GameObject* childObj;

    state = obj->extra;
    light = ((DimBossGut2Control*)state->groundBaddie.control)->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
    }
    objFreeObjectType(obj, DIMBOSSGUT2_OBJGROUP);
    childObj = obj->childObjs[0];
    if (childObj != NULL) {
        Obj_FreeObject(childObj);
        obj->childObjs[0] = NULL;
    }
    (*gBaddieControlInterface)->releaseState(obj, state, 0);
}

void DIM_BossGut2_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DimBossGut2State* state;
    DimBossGut2Control* control;
    ModelLightStruct* light;

    state = obj->extra;
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        control = state->groundBaddie.control;
        light = control->light;
        if ((light != NULL) && (light->glowType != 0) && (light->enabled != 0)) {
            queueGlowRender(light);
        }
    }
}

void DIM_BossGut2_hitDetect(void) {
}

enum {
    DIMBOSSGUT2_HIT_VOLUME_PRIORITY = 9,
    DIMBOSSGUT2_HIT_VOLUME_ID = 1,
};

enum {
    DIMBOSSGUT2_IDLE_MOVE_ID = 0,
};

void DIM_BossGut2_update(GameObject* obj) {
    DimBossGut2State* state;
    int result;
    u32 randomThreshold;
    u32 brightness;
    DimBossGut2Control* control;
    DimBossGut2Control* lightOwner;
    f32 heightDiff;
    f32 xyScale;
    ModelLightStruct* light;
    u32 msgB;
    u32 msgA;
    u32 msgC;
    PartFxSpawnParams effectParams;

    state = obj->extra;
    if ((obj->userData1 == 0) &&
        ((obj->anim.parent != NULL ||
          (result = objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ),
           result >= 0)))) {
        msgC = 0;
        do {
            result = ObjMsg_Pop(obj, (u32*)&msgA, (u32*)&msgB, (u32*)&msgC);
        } while (result != 0);
        control = state->groundBaddie.control;
        dimbossgut2_spawnBreathSplash(obj, control, &effectParams);
        control->breathFxTimer += framesThisStep;
        ((void (*)(GameObject*, DimBossGut2State*))dimbossgut2_updateBobAndSway)(obj, state);
        dimbossgut2_updateTracking(obj, state);
        ObjAnim_AdvanceCurrentMove(obj, 0.015f, timeDelta, NULL);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = DIMBOSSGUT2_HIT_VOLUME_PRIORITY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = DIMBOSSGUT2_HIT_VOLUME_ID;
        ObjHits_RegisterActiveHitVolumeObject(obj);
        lightOwner = state->groundBaddie.control;
        light = lightOwner->light;
        if ((light != NULL) && (light->glowType != 0) && (light->enabled != 0)) {
            brightness = (light->glowAlpha + light->glowAlphaStep) & 0xffff;
            if (brightness > 0xc) {
                brightness = (brightness + randomGetRange(-12, 12)) & 0xffff;
                if (brightness > 0xff) {
                    brightness = 0xff;
                    lightOwner->light->glowAlphaStep = 0;
                }
            }
            lightOwner->light->glowAlpha = brightness;
        }
    }
}

void DIM_BossGut2_init(GameObject* obj, u8* placementAddress, int isAltVariant) {
    DimBossGut2State* state;
    DimBossGut2Control* control;
    int count;
    int i;
    TrackGroundHit** list;
    u8 flags;
    f32 z;

    state = obj->extra;
    flags = 0x16;
    if (isAltVariant != 0) {
        flags |= 1;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, placementAddress, (u8*)state, 0, 0, 0x102, flags, 20.0f);
    obj->animEventCallback = NULL;
    control = state->groundBaddie.control;
    z = 0.0f;
    control->verticalVelocity = z;
    control->swayVelocity = z;
    control->bobPhase = randomGetRange(-0x7fff, 0x7fff);
    z = 0.0f;
    control->turnHeightBias = z;
    control->breathFxTimer = 0;
    control->pathSpeed = z;
    count = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &list, 0, 0);
    control->surfaceY = 0.0f;
    if (count != 0) {
        control->surfaceY = -9999.0f;
        for (i = 0; i < count; i++) {
            f32 heightDelta = list[i]->height - obj->anim.localPosY;
            if ((s8)list[i]->surfaceType == DIMBOSSGUT2_WATER_SURFACE_TYPE) {
                if (heightDelta > control->surfaceY) {
                    control->surfaceY = heightDelta;
                }
            }
        }
    }
    control->surfaceY += obj->anim.localPosY;
    ObjAnim_SetCurrentMove(obj, DIMBOSSGUT2_IDLE_MOVE_ID, (f32)randomGetRange(0, 0x63) / 100.0f, 0);
    ObjAnim_AdvanceCurrentMove(obj, 0.015f, timeDelta, NULL);
    control->light = objCreateLight(obj, 1);
    if (control->light != NULL) {
        modelLightStruct_setLightKind(control->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(control->light, 0, 255, 0, 0);
        modelLightStruct_setFieldBC(control->light, 1);
        modelLightStruct_setDistanceAttenuation(control->light, 10.0f, 20.0f);
        modelLightStruct_setupGlow(control->light, 0, 0, 255, 0, 127, 15.0f);
        modelLightStruct_setGlowProjectionRadius(control->light, 50.0f);
    }
}

void DIM_BossGut2_release(void) {
}

void DIM_BossGut2_initialise(void) {
}

ObjectDescriptor12 gDIM_BossGut2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    DIM_BossGut2_initialise,
    DIM_BossGut2_release,
    0,
    (ObjectDescriptorCallback)DIM_BossGut2_init,
    (ObjectDescriptorCallback)DIM_BossGut2_update,
    DIM_BossGut2_hitDetect,
    (ObjectDescriptorCallback)DIM_BossGut2_render,
    (ObjectDescriptorCallback)DIM_BossGut2_free,
    (ObjectDescriptorCallback)DIM_BossGut2_getObjectTypeId,
    DIM_BossGut2_getExtraSize,
    (ObjectDescriptorCallback)DIM_BossGut2_func0A,
    DIM_BossGut2_func0B,
};
