/*
 * DLL 0xE3 - fireball object (a homing magic projectile).
 *
 * The fireball spawns a model light (objCreateLight) tinted per colorIndex
 * from lbl_80320978 (owned by the staff TU), flies for flightDuration
 * computed from its launch velocity, optionally homes onto a target
 * hit-volume (fn_8016F260) on a spiral (spiralPhase), runs ground collision
 * when stateFlags bit 4 is set, and on contact plays an impact SFX /
 * particle burst, frees its light and fades out. seqId 2110 hides the
 * object; seqId 0x6e8 contact recolors it from the combat source palette.
 * stateFlags: bit0 = launch position latched, bit1 = (unused here),
 * bit3 = disabled/no-update, bit4 = affected by gravity+ground snap.
 */
#include "main/model.h"
#include "main/object_render.h"
#include "main/track_dolphin_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/obj_group.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/vecmath.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_02B1_cmbsrc.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

u8 gFireballColorIndexTable[8] = {0, 2, 4, 0, 0, 0, 0, 0};
#define FIREBALL_HIT_VOLUME_SLOT 14

/* object group this object joins while active */
#define FIREBALL_OBJGROUP 2

/* FireballState.stateFlags bits (see file header comment) */
#define FIREBALL_FLAG_POS_LATCHED 0x1 /* launch position has been latched into posX/Y/Z */
#define FIREBALL_FLAG_GRAVITY     0x4 /* affected by gravity + ground snap */
#define FIREBALL_FLAG_DISABLED    0x8 /* disabled / no-update */

/* anim.seqId of the invisible variant (docblock: "seqId 2110 hides the object"). */
#define FIREBALL_SEQID_HIDDEN 0x83e
/* anim.seqId of the hit object that triggers combat-source recolor. */
#define FIREBALL_SEQID_CMBSRC_RECOLOR 0x6e8

void fn_8016F260(GameObject* obj, int* state, int* other);

u8 fn_8016F16C(GameObject* obj)
{
    return ((FireballState*)obj->extra)->colorIndex;
}

int Fireball_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    FireballState* state = obj->extra;
    if (state->stateFlags & FIREBALL_FLAG_DISABLED)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            if (state->light != NULL)
            {
                modelLightStruct_setEnabled(state->light, 1, 0.0f);
            }
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        else if (cmd == 2)
        {
            if (state->light != NULL)
            {
                modelLightStruct_setEnabled(state->light, 0, 0.0f);
            }
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    return 0;
}

void fn_8016F260(GameObject* obj, int* state, int* other)
{
    ObjHitVolumeRuntimeTransform* hitVolume =
        &((GameObject*)other)->anim.hitVolumeTransforms[((GameObject*)other)->hitVolumeIndex];
    if (hitVolume != NULL)
    {
        f32 dx = hitVolume->jointX - ((FireballState*)state)->posX;
        f32 dy = hitVolume->jointY - 8.0f - ((FireballState*)state)->posY;
        f32 dz = hitVolume->jointZ - ((FireballState*)state)->posZ;
        s16 angY;
        s16 angP;
        s16 difY;
        s16 difP;
        s16 targY;
        s16 targP;
        f32 t1;
        f32 t2;
        f32 c;

        angY = getAngle(obj->anim.velocityX, obj->anim.velocityZ);
        t1 = obj->anim.velocityX * obj->anim.velocityX;
        t2 = obj->anim.velocityZ * obj->anim.velocityZ;
        angP = getAngle(obj->anim.velocityY, sqrtf(t1 + t2));
        targY = getAngle(dx, dz);
        targP = getAngle(dy, sqrtf(dx * dx + dz * dz));

        difY = targY - (u16)angY;
        if (difY > 0x8000)
        {
            difY = (difY - 0x10000) + 1;
        }
        if (difY < -0x8000)
        {
            difY += 0xffff;
        }
        difP = targP - (u16)angP;
        if (difP > 0x8000)
        {
            difP = (difP - 0x10000) + 1;
        }
        if (difP < -0x8000)
        {
            difP += 0xffff;
        }
        difY >>= 5;
        if (difY > 364)
        {
            difY = 364;
        }
        if (difY < -364)
        {
            difY = -364;
        }
        difP >>= 4;
        if (difP > 728)
        {
            difP = 728;
        }
        if (difP < -728)
        {
            difP = -728;
        }
        angY += framesThisStep * difY;
        angP += framesThisStep * difP;

        dx = 3.1415927f * angY / 32768.0f;
        obj->anim.velocityX = mathSinf(dx);
        obj->anim.velocityZ = mathCosf(dx);
        dx = 3.1415927f * angP / 32768.0f;
        c = mathSinf(dx);
        {
            f32 cosP = mathCosf(dx);
            if (0.0f != cosP)
            {
                c = c / cosP;
            }
        }
        obj->anim.velocityY = c;

        c = 5.0f / sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                                 (obj->anim.velocityX * obj->anim.velocityX +
                                  obj->anim.velocityY * obj->anim.velocityY));
        obj->anim.velocityX *= c;
        obj->anim.velocityY *= c;
        obj->anim.velocityZ *= c;
    }
}

int Fireball_getExtraSize(void)
{
    return 0x74;
}
int Fireball_getObjectTypeId(void)
{
    return 0x0;
}

void Fireball_free(GameObject* obj)
{
    FireballState* state = obj->extra;
    ModelLightStruct* light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void Fireball_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* model;
    u8* state = obj->extra;
    u16 savedRot4;
    u16 savedRot2;
    u8 i;
    f32 savedF8;
    f32 zero = 0.0f;
    if (visible == 0 || (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0 ||
        ((FireballState*)state)->startupDelay != zero)
    {
        return;
    }
    ((ObjAnimComponent*)obj)->bankIndex = 1;
    model = (int*)Obj_GetActiveModel(obj);
    ((ObjModel*)model)->textureRefs->unk08 = gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    savedRot4 = obj->anim.rotZ;
    savedRot2 = obj->anim.rotY;
    savedF8 = obj->anim.rootMotionScale;
    obj->anim.rootMotionScale = 0.9f;
    for (i = 0; i < FIREBALL_ROT_COUNT; i++)
    {
        FireballState* fs = (FireballState*)(state + i * 2);
        fs->rotZBase[0] += fs->rotZDelta[0];
        fs->rotYBase[0] += fs->rotYDelta[0];
        obj->anim.rotZ = (s16)fs->rotZBase[0];
        obj->anim.rotY = (s16)fs->rotYBase[0];
        ((ObjModel*)model)->bufferFlags &= ~0x8;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
    obj->anim.rotZ = savedRot4;
    obj->anim.rotY = savedRot2;
    obj->anim.rootMotionScale = savedF8;
    ((ObjAnimComponent*)obj)->bankIndex = 0;
    model = (int*)Obj_GetActiveModel(obj);
    ((ObjModel*)model)->textureRefs->unk08 = gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    if (((FireballState*)state)->light != NULL)
    {
        if (((FireballState*)state)->light->glowType != 0 && ((FireballState*)state)->light->enabled != 0)
        {
            u16 sum = ((FireballState*)state)->light->glowAlpha + ((FireballState*)state)->light->glowAlphaStep;
            if (sum > 12)
            {
                sum += randomGetRange(-12, 12);
                if (sum > 255)
                {
                    sum = 255;
                    ((FireballState*)state)->light->glowAlphaStep = 0;
                }
            }
            ((FireballState*)state)->light->glowAlpha = sum;
        }
        if (((FireballState*)state)->light->glowType != 0 && ((FireballState*)state)->light->enabled != 0)
        {
            queueGlowRender(((FireballState*)state)->light);
        }
    }
}

void Fireball_hitDetect(GameObject* obj)
{
    FireballState* state = obj->extra;
    int* target;
    if (obj->anim.seqId == FIREBALL_SEQID_HIDDEN)
        return;
    switch (state->stateFlags & FIREBALL_FLAG_DISABLED)
    {
    case 0:
        break;
    default:
        return;
    }
    target = (int*)((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
    if (target == NULL)
        return;
    if (((GameObject*)target)->anim.seqId == FIREBALL_SEQID_CMBSRC_RECOLOR)
    {
        int idx = cmbsrc_getColorIndex((CmbSrcObject*)target);
        if ((s8)idx != -1)
        {
            state->colorIndex = idx;
            if (state->light != NULL)
            {
                int paletteBase = state->colorIndex * 3;
                u8* pal = (u8*)lbl_80320978;
                modelLightStruct_setDiffuseColor(state->light, pal[paletteBase], pal[paletteBase + 1],
                                                 pal[paletteBase + 2], 0);
            }
        }
        ObjHits_EnableObject(obj);
    }
    else
    {
        u8 colorIndex;
        state->fadeoutTimer = 60.0f;
        colorIndex = state->colorIndex;
        if (colorIndex == 0)
        {
            projectileParticleFxFn_80099660(obj, 1.0f, 3);
        }
        else if (colorIndex == 1)
        {
            projectileParticleFxFn_80099660(obj, 1.0f, 0);
        }
        else
        {
            projectileParticleFxFn_80099660(obj, 1.0f, 6);
        }
        obj->anim.alpha = 0;
        if (state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = NULL;
        }
    }
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void Fireball_update(GameObject* obj)
{
    FireballState* state = obj->extra;
#define hitState ((ObjHitsPriorityState*)obj->anim.hitReactState)
    int* other = *(int**)&obj->userData2;
    int* params = *(int**)&obj->anim.placementData;
    f32 zero = 0.0f;

    if ((state->stateFlags & FIREBALL_FLAG_DISABLED) != 0)
    {
        return;
    }
    state->startupDelay -= timeDelta;
    if (state->startupDelay < 0.0f)
    {
        state->startupDelay = 0.0f;
    }
    if (obj->anim.seqId == FIREBALL_SEQID_HIDDEN)
    {
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 0.0f);
        }
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        return;
    }
    if (0.0f == state->elapsedTime)
    {
        state->flightDuration = 7.0f / Vec3_Length(&obj->anim.velocityX);
    }
    state->elapsedTime += timeDelta;
    if (state->elapsedTime > state->flightDuration)
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIREBALL_HIT_VOLUME_SLOT,
                                ((FireballPlacement*)params)->hitVolumeMode != 0 ? 3 : 1, 0);
    }
    if ((state->stateFlags & FIREBALL_FLAG_POS_LATCHED) == 0)
    {
        state->posX = obj->anim.localPosX;
        state->posY = obj->anim.localPosY;
        state->posZ = obj->anim.localPosZ;
        state->stateFlags |= FIREBALL_FLAG_POS_LATCHED;
    }
    {
        if (hitState->contactFlags != 0)
        {
            if (hitState->contactHitVolume != 14)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_npu_216);
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_foot_water_walk_1);
                (*gWaterfxInterface)
                    ->spawnSplashBurst(obj, obj->anim.localPosX, obj->anim.localPosY,
                                       obj->anim.localPosZ, 6.0f);
                (*gWaterfxInterface)->spawnRipple(
                    obj->anim.localPosX, obj->anim.localPosY,
                    obj->anim.localPosZ, *(s16*)obj, 0.0f, 2);
            }
            {
                u8 v = state->colorIndex;
                if (v == 0)
                {
                    projectileParticleFxFn_80099660(obj, 1.0f, 3);
                }
                else if (v == 1)
                {
                    projectileParticleFxFn_80099660(obj, 1.0f, 0);
                }
                else
                {
                    projectileParticleFxFn_80099660(obj, 1.0f, 6);
                }
            }
            state->fadeoutTimer = 60.0f;
            obj->anim.alpha = 0;
            if (state->light != NULL)
            {
                ModelLightStruct_free(state->light);
                state->light = NULL;
            }
            ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
            ObjHits_DisableObject(obj);
        }
    }
    if (state->fadeoutTimer != zero)
    {
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        state->fadeoutTimer -= timeDelta;
        if (state->fadeoutTimer <= 0.0f)
        {
            Obj_FreeObject(obj);
        }
    }
    else
    {
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        if (other != NULL)
        {
            if ((((GameObject*)other)->objectFlags & OBJECT_OBJFLAG_FREED) != 0)
            {
                obj->userData2 = 0;
            }
            else
            {
                fn_8016F260(obj, (int*)state, other);
            }
        }
        state->posX += obj->anim.velocityX * timeDelta;
        state->posY += obj->anim.velocityY * timeDelta;
        state->posZ += obj->anim.velocityZ * timeDelta;
        state->spiralPhase += framesThisStep * 1500;
        if ((state->stateFlags & FIREBALL_FLAG_GRAVITY) != 0)
        {
            f32 ground;
            state->posY -= 2.0f * timeDelta;
            if (hitDetectFn_800658a4(obj, state->posX, state->posY,
                                     state->posZ, &ground, 0) == 0)
            {
                ground -= 10.0f;
                if (ground < 0.0f && ground > -15.0f)
                {
                    state->posY -= ground;
                }
            }
        }
        obj->anim.localPosX = state->posX;
        obj->anim.localPosY = state->posY;
        obj->anim.localPosZ = state->posZ;
        if (other != NULL)
        {
            obj->anim.localPosX +=
                8.0f *
                mathSinf(3.1415927f * (f32)state->spiralPhase / 32768.0f);
            obj->anim.localPosZ +=
                8.0f *
                mathCosf(3.1415927f * (f32)state->spiralPhase / 32768.0f);
        }
        if ((obj->userData1 -= framesThisStep) < 0)
        {
            Obj_FreeObject(obj);
        }
    }
#undef hitState
}

void Fireball_init(GameObject* obj)
{
    FireballState* state = obj->extra;
    int* params = *(int**)&obj->anim.placementData;

    if (((FireballPlacement*)params)->startDisabled != 0)
    {
        state->stateFlags |= FIREBALL_FLAG_DISABLED;
    }
    else
    {
        FireballState* fs;
        int i;
        state->unk40 = randomGetRange(600, 900);
        state->unk42 = randomGetRange(-600, 600);
        state->colorIndex = 0;
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if (hitState != NULL)
            {
                hitState->trackContactMask = 257;
            }
        }
        if (state->light == NULL)
        {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL)
            {
                int c;
                u8* base1;
                u8* base2;
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                lightSetField4D(state->light, 0);
                modelLightStruct_setPosition(state->light, 0.0f, 0.0f,
                                             0.0f);
                lightSetFieldBC_8001db14(state->light, 1);
                c = state->colorIndex * 3;
                modelLightStruct_setDiffuseColor(
                    state->light, ((u8*)lbl_80320978)[c],
                    (base1 = (u8*)lbl_80320978 + 1)[state->colorIndex * 3],
                    (base2 = (u8*)lbl_80320978 + 2)[state->colorIndex * 3], 0);
                modelLightStruct_setDistanceAttenuation(state->light, 60.0f, 80.0f);
                c = state->colorIndex * 3;
                modelLightStruct_setupGlow(state->light, 0, ((u8*)lbl_80320978)[c], base1[c],
                                           base2[c], 32, 50.0f);
                modelLightStruct_setGlowProjectionRadius(state->light, 50.0f);
            }
        }
        obj->anim.alpha = 200;
        for (i = 0, fs = state; i < FIREBALL_ROT_COUNT; i++)
        {
            fs->rotZBase[0] = randomGetRange(-32767, 32767);
            fs->rotZDelta[0] = randomGetRange(-1024, 1024);
            fs->rotYBase[0] = randomGetRange(-32767, 32767);
            fs->rotYDelta[0] = randomGetRange(-1024, 1024);
            fs = (FireballState*)((char*)fs + 2);
        }
        obj->animEventCallback = Fireball_SeqFn;
        ObjGroup_AddObject((int)obj, FIREBALL_OBJGROUP);
        if (obj->anim.seqId != FIREBALL_SEQID_HIDDEN &&
            ((FireballPlacement*)params)->startupDelayEnabled != 0)
        {
            state->startupDelay = 4.0f;
        }
    }
}

void Fireball_release(void)
{
}

void Fireball_initialise(void)
{
}

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
