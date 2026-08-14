/*
 * Fireball object family (DLL slot 227 / 0xE3).
 *
 * Drives homing magic projectiles, their model lights, contact effects,
 * spiral motion, and fadeout.
 */
#include "dlls/objects/227_Fireball.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_02B1_cmbsrc.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"
#include "main/objseq.h"

#define FIREBALL_HIT_VOLUME_SLOT 14

#define FIREBALL_OBJECT_GROUP 2

#define FIREBALL_FLAG_POS_LATCHED 0x1
#define FIREBALL_FLAG_GRAVITY     0x4
#define FIREBALL_FLAG_DISABLED    0x8

#define FIREBALL_SEQID_HIDDEN         0x83E
#define FIREBALL_SEQID_CMBSRC_RECOLOR 0x6E8

#define FIREBALL_SPIRAL_AMPLITUDE 8.0f
#define FIREBALL_PI               3.1415927f
#define FIREBALL_ANGLE_SCALE      32768.0f

#define FIREBALL_HIT_STATE(obj) ((ObjHitsPriorityState*)(obj)->anim.hitReactState)

u8 gFireballColorIndexTable[8] = {0, 2, 4, 0, 0, 0, 0, 0};

u8 gFireballLightColors[4][3] = {
    {0xFF, 0x20, 0x20}, {0x20, 0xFF, 0x20}, {0x20, 0x20, 0xFF}, {0x00, 0x00, 0x00},
};

ObjectDescriptor10WithPadding gFireballObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)Fireball_initialise,
        (ObjectDescriptorCallback)Fireball_release,
        0,
        (ObjectDescriptorCallback)Fireball_init,
        (ObjectDescriptorCallback)Fireball_update,
        (ObjectDescriptorCallback)Fireball_hitDetect,
        (ObjectDescriptorCallback)Fireball_render,
        (ObjectDescriptorCallback)Fireball_free,
        (ObjectDescriptorCallback)Fireball_getObjectTypeId,
        Fireball_getExtraSize,
    },
    0,
};

u8 Fireball_getColorIndex(GameObject* obj) {
    return ((FireballState*)obj->extra)->colorIndex;
}

int Fireball_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int i;
    FireballState* state = obj->extra;

    (void)unused;

    if (state->stateFlags & FIREBALL_FLAG_DISABLED) {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1) {
            if (state->light != NULL) {
                modelLightStruct_setEnabled(state->light, 1, 0.0f);
            }
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        } else if (cmd == 2) {
            if (state->light != NULL) {
                modelLightStruct_setEnabled(state->light, 0, 0.0f);
            }
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    return 0;
}

void Fireball_homeToTarget(GameObject* obj, FireballState* state, GameObject* target) {
    ObjHitVolumeRuntimeTransform* hitVolume = &target->anim.hitVolumeTransforms[target->hitVolumeIndex];
    if (hitVolume != NULL) {
        f32 dx = hitVolume->jointX - state->posX;
        f32 dy = hitVolume->jointY - 8.0f - state->posY;
        f32 dz = hitVolume->jointZ - state->posZ;
        s16 angY;
        s16 angP;
        s16 difY;
        s16 difP;
        s16 targY;
        s16 targP;
        f32 t1;
        f32 t2;
        f32 t;

        angY = (s16)getAngle(obj->anim.velocityX, obj->anim.velocityZ);
        t1 = obj->anim.velocityX * obj->anim.velocityX;
        t2 = obj->anim.velocityZ * obj->anim.velocityZ;
        angP = (s16)getAngle(obj->anim.velocityY, sqrtf(t1 + t2));
        targY = (s16)getAngle(dx, dz);
        targP = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));

        difY = (s16)(targY - (u16)angY);
        if (difY > 0x8000) {
            difY = (s16)((difY - 0x10000) + 1);
        }
        if (difY < -0x8000) {
            difY += 0xffff;
        }
        difP = (s16)(targP - (u16)angP);
        if (difP > 0x8000) {
            difP = (s16)((difP - 0x10000) + 1);
        }
        if (difP < -0x8000) {
            difP += 0xffff;
        }
        difY >>= 5;
        if (difY > 364) {
            difY = 364;
        }
        if (difY < -364) {
            difY = -364;
        }
        difP >>= 4;
        if (difP > 728) {
            difP = 728;
        }
        if (difP < -728) {
            difP = -728;
        }
        angY += framesThisStep * difY;
        angP += framesThisStep * difP;

        dx = FIREBALL_PI * angY / FIREBALL_ANGLE_SCALE;
        obj->anim.velocityX = mathSinf(dx);
        obj->anim.velocityZ = mathCosf(dx);
        dx = FIREBALL_PI * angP / FIREBALL_ANGLE_SCALE;
        t = mathSinf(dx);
        {
            f32 cosP = mathCosf(dx);
            if (cosP != 0.0f) {
                t = t / cosP;
            }
        }
        obj->anim.velocityY = t;

        t = 5.0f / sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                         (obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityY * obj->anim.velocityY));
        obj->anim.velocityX *= t;
        obj->anim.velocityY *= t;
        obj->anim.velocityZ *= t;
    }
}

int Fireball_getExtraSize(void) {
    return sizeof(FireballState);
}

int Fireball_getObjectTypeId(void) {
    return 0;
}

void Fireball_free(GameObject* obj) {
    FireballState* state = obj->extra;
    ModelLightStruct* light = state->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    objFreeObjectType(obj, FIREBALL_OBJECT_GROUP);
}

void Fireball_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    ObjModel* model;
    FireballState* state = obj->extra;
    u16 savedRotZ;
    u16 savedRotY;
    u8 i;
    f32 savedF8;
    f32 zero = 0.0f;

    if (visible == 0 || (state->stateFlags & FIREBALL_FLAG_DISABLED) != 0 || state->startupDelay != zero) {
        return;
    }
    ((ObjAnimComponent*)obj)->bankIndex = 1;
    model = Obj_GetActiveModel(obj);
    model->textureRefs->swapSelector = gFireballColorIndexTable[state->colorIndex];
    savedRotZ = (u16)obj->anim.rotZ;
    savedRotY = (u16)obj->anim.rotY;
    savedF8 = obj->anim.rootMotionScale;
    obj->anim.rootMotionScale = 0.9f;
    for (i = 0; i < FIREBALL_ROTATION_COUNT; i++) {
        state->rotZBase[i] += state->rotZDelta[i];
        state->rotYBase[i] += state->rotYDelta[i];
        obj->anim.rotZ = (s16)state->rotZBase[i];
        obj->anim.rotY = (s16)state->rotYBase[i];
        model->bufferFlags &= ~0x8;
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
    obj->anim.rotZ = (s16)savedRotZ;
    obj->anim.rotY = (s16)savedRotY;
    obj->anim.rootMotionScale = savedF8;
    ((ObjAnimComponent*)obj)->bankIndex = 0;
    model = Obj_GetActiveModel(obj);
    model->textureRefs->swapSelector = gFireballColorIndexTable[state->colorIndex];
    objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    if (state->light != NULL) {
        if (state->light->glowType != 0 && state->light->enabled != 0) {
            u16 sum = (u16)(state->light->glowAlpha + state->light->glowAlphaStep);
            if (sum > 12) {
                sum = (u16)(sum + randomGetRange(-12, 12));
                if (sum > 255) {
                    sum = 255;
                    state->light->glowAlphaStep = 0;
                }
            }
            state->light->glowAlpha = (u8)sum;
        }
        if (state->light->glowType != 0 && state->light->enabled != 0) {
            queueGlowRender(state->light);
        }
    }
}

void Fireball_hitDetect(GameObject* obj) {
    FireballState* state = obj->extra;
    GameObject* target;

    if (obj->anim.romDefNo == FIREBALL_SEQID_HIDDEN) {
        return;
    }
    switch (state->stateFlags & FIREBALL_FLAG_DISABLED) {
    case 0:
        break;
    default:
        return;
    }
    target = (GameObject*)((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
    if (target == NULL) {
        return;
    }
    if (target->anim.romDefNo == FIREBALL_SEQID_CMBSRC_RECOLOR) {
        int colorIndex = cmbsrc_getColorIndex(target);
        if ((s8)colorIndex != -1) {
            state->colorIndex = (u8)colorIndex;
            if (state->light != NULL) {
                int paletteBase = state->colorIndex * 3;
                u8* pal = (u8*)gFireballLightColors;
                modelLightStruct_setDiffuseColor(state->light, pal[paletteBase], pal[paletteBase + 1],
                                                 pal[paletteBase + 2], 0);
            }
        }
        ObjHits_EnableObject(obj);
    } else {
        u8 colorIndex;
        state->fadeoutTimer = 60.0f;
        colorIndex = state->colorIndex;
        if (colorIndex == 0) {
            projectileDoParticleFx(obj, 1.0f, 3);
        } else if (colorIndex == 1) {
            projectileDoParticleFx(obj, 1.0f, 0);
        } else {
            projectileDoParticleFx(obj, 1.0f, 6);
        }
        obj->anim.alpha = 0;
        if (state->light != NULL) {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
    }
    objFreeObjectType(obj, FIREBALL_OBJECT_GROUP);
}

void Fireball_update(GameObject* obj) {
    FireballState* state = obj->extra;
    GameObject* other = (GameObject*)obj->userData2;
    FireballPlacement* placement = (FireballPlacement*)obj->anim.placementData;
    f32 zero = 0.0f;

    if ((state->stateFlags & FIREBALL_FLAG_DISABLED) != 0) {
        return;
    }
    state->startupDelay -= timeDelta;
    if (state->startupDelay < 0.0f) {
        state->startupDelay = 0.0f;
    }
    if (obj->anim.romDefNo == FIREBALL_SEQID_HIDDEN) {
        if (state->light != NULL) {
            modelLightStruct_setEnabled(state->light, 0, 0.0f);
        }
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        return;
    }
    if (state->elapsedTime == 0.0f) {
        state->flightDuration = 7.0f / Vec3_Length(&obj->anim.velocityX);
    }
    state->elapsedTime += timeDelta;
    if (state->elapsedTime > state->flightDuration) {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIREBALL_HIT_VOLUME_SLOT, placement->hitVolumeMode != 0 ? 3 : 1,
                                 0);
    }
    if ((state->stateFlags & FIREBALL_FLAG_POS_LATCHED) == 0) {
        state->posX = obj->anim.localPosX;
        state->posY = obj->anim.localPosY;
        state->posZ = obj->anim.localPosZ;
        state->stateFlags |= FIREBALL_FLAG_POS_LATCHED;
    }
    {
        if (FIREBALL_HIT_STATE(obj)->contactFlags != 0) {
            if (FIREBALL_HIT_STATE(obj)->contactHitVolume != FIREBALL_HIT_VOLUME_SLOT) {
                Sfx_PlayFromObject(obj, SFXTRIG_npu_216);
            } else {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_water_walk_1);
                (*gWaterfxInterface)
                    ->spawnSplashBurst(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, 6.0f);
                (*gWaterfxInterface)
                    ->spawnRipple(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, *(s16*)obj, 0.0f, 2);
            }
            {
                u8 colorIndex = state->colorIndex;
                if (colorIndex == 0) {
                    projectileDoParticleFx(obj, 1.0f, 3);
                } else if (colorIndex == 1) {
                    projectileDoParticleFx(obj, 1.0f, 0);
                } else {
                    projectileDoParticleFx(obj, 1.0f, 6);
                }
            }
            state->fadeoutTimer = 60.0f;
            obj->anim.alpha = 0;
            if (state->light != NULL) {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
            objFreeObjectType(obj, FIREBALL_OBJECT_GROUP);
            ObjHits_DisableObject(obj);
        }
    }
    if (state->fadeoutTimer != zero) {
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        state->fadeoutTimer -= timeDelta;
        if (state->fadeoutTimer <= 0.0f) {
            Obj_FreeObject(obj);
        }
    } else {
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        if (other != NULL) {
            if ((other->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
                obj->userData2 = 0;
            } else {
                Fireball_homeToTarget(obj, state, other);
            }
        }
        state->posX += obj->anim.velocityX * timeDelta;
        state->posY += obj->anim.velocityY * timeDelta;
        state->posZ += obj->anim.velocityZ * timeDelta;
        state->spiralPhase += framesThisStep * 1500;
        if ((state->stateFlags & FIREBALL_FLAG_GRAVITY) != 0) {
            f32 ground;
            state->posY -= 2.0f * timeDelta;
            if (trackGetNearestGroundOffset(obj, state->posX, state->posY, state->posZ, &ground, 0) == 0) {
                ground -= 10.0f;
                if (ground < 0.0f && ground > -15.0f) {
                    state->posY -= ground;
                }
            }
        }
        obj->anim.localPosX = state->posX;
        obj->anim.localPosY = state->posY;
        obj->anim.localPosZ = state->posZ;
        if (other != NULL) {
            obj->anim.localPosX +=
                FIREBALL_SPIRAL_AMPLITUDE * mathSinf(FIREBALL_PI * (f32)state->spiralPhase / FIREBALL_ANGLE_SCALE);
            obj->anim.localPosZ +=
                FIREBALL_SPIRAL_AMPLITUDE * mathCosf(FIREBALL_PI * (f32)state->spiralPhase / FIREBALL_ANGLE_SCALE);
        }
        if ((obj->userData1 -= framesThisStep) < 0) {
            Obj_FreeObject(obj);
        }
    }
}

void Fireball_init(GameObject* obj) {
    FireballState* state = obj->extra;
    FireballPlacement* placement = (FireballPlacement*)obj->anim.placementData;

    if (placement->startDisabled != 0) {
        state->stateFlags |= FIREBALL_FLAG_DISABLED;
    } else {
        int i;
        state->unk40 = (s16)randomGetRange(600, 900);
        state->unk42 = (s16)randomGetRange(-600, 600);
        state->colorIndex = 0;
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if (hitState != NULL) {
                hitState->trackContactMask = 257;
            }
        }
        if (state->light == NULL) {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL) {
                int c;
                u8* base1;
                u8* base2;
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                lightSetField4D(state->light, 0);
                modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
                modelLightStruct_setFieldBC(state->light, 1);
                c = state->colorIndex * 3;
                modelLightStruct_setDiffuseColor(state->light, ((u8*)gFireballLightColors)[c],
                                                 (base1 = (u8*)gFireballLightColors + 1)[state->colorIndex * 3],
                                                 (base2 = (u8*)gFireballLightColors + 2)[state->colorIndex * 3], 0);
                modelLightStruct_setDistanceAttenuation(state->light, 60.0f, 80.0f);
                c = state->colorIndex * 3;
                modelLightStruct_setupGlow(state->light, 0, ((u8*)gFireballLightColors)[c], base1[c], base2[c], 32, 50.0f);
                modelLightStruct_setGlowProjectionRadius(state->light, 50.0f);
            }
        }
        obj->anim.alpha = 200;
        for (i = 0; i < FIREBALL_ROTATION_COUNT; i++) {
            state->rotZBase[i] = (u16)randomGetRange(-32767, 32767);
            state->rotZDelta[i] = (u16)randomGetRange(-1024, 1024);
            state->rotYBase[i] = (u16)randomGetRange(-32767, 32767);
            state->rotYDelta[i] = (u16)randomGetRange(-1024, 1024);
        }
        obj->animEventCallback = Fireball_SeqFn;
        objAddObjectType(obj, FIREBALL_OBJECT_GROUP);
        if (obj->anim.romDefNo != FIREBALL_SEQID_HIDDEN && placement->startupDelayEnabled != 0) {
            state->startupDelay = 4.0f;
        }
    }
}

void Fireball_release(void) {
}

void Fireball_initialise(void) {
}
