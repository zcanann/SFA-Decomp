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

u8 fn_8016F16C(int* obj)
{
    return ((FireballState*)((GameObject*)obj)->extra)->colorIndex;
}

int Fireball_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int* state = obj->extra;
    if (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            if (((FireballState*)state)->light != NULL)
            {
                modelLightStruct_setEnabled(((FireballState*)state)->light, 1, 0.0f);
            }
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        else if (cmd == 2)
        {
            if (((FireballState*)state)->light != NULL)
            {
                modelLightStruct_setEnabled(((FireballState*)state)->light, 0, 0.0f);
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
    int* state = obj->extra;
    int* target;
    if (obj->anim.seqId == FIREBALL_SEQID_HIDDEN)
        return;
    switch (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
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
            ((FireballState*)state)->colorIndex = idx;
            if (((FireballState*)state)->light != NULL)
            {
                int paletteBase = ((FireballState*)state)->colorIndex * 3;
                u8* pal = (u8*)lbl_80320978;
                modelLightStruct_setDiffuseColor(((FireballState*)state)->light, pal[paletteBase], pal[paletteBase + 1],
                                                 pal[paletteBase + 2], 0);
            }
        }
        ObjHits_EnableObject(obj);
    }
    else
    {
        u8 colorIndex;
        ((FireballState*)state)->fadeoutTimer = 60.0f;
        colorIndex = ((FireballState*)state)->colorIndex;
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
        if (((FireballState*)state)->light != NULL)
        {
            ModelLightStruct_free(((FireballState*)state)->light);
            ((FireballState*)state)->light = NULL;
        }
    }
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void Fireball_update(GameObject* obj)
{
    int* state = obj->extra;
#define hitState ((ObjHitsPriorityState*)obj->anim.hitReactState)
    int* other = *(int**)&obj->userData2;
    int* params = *(int**)&obj->anim.placementData;
    f32 zero = 0.0f;

    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0)
    {
        return;
    }
    ((FireballState*)state)->startupDelay -= timeDelta;
    if (((FireballState*)state)->startupDelay < 0.0f)
    {
        ((FireballState*)state)->startupDelay = 0.0f;
    }
    if (obj->anim.seqId == FIREBALL_SEQID_HIDDEN)
    {
        if (((FireballState*)state)->light != NULL)
        {
            modelLightStruct_setEnabled(((FireballState*)state)->light, 0, 0.0f);
        }
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        return;
    }
    if (0.0f == ((FireballState*)state)->elapsedTime)
    {
        ((FireballState*)state)->flightDuration = 7.0f / Vec3_Length(&obj->anim.velocityX);
    }
    ((FireballState*)state)->elapsedTime += timeDelta;
    if (((FireballState*)state)->elapsedTime > ((FireballState*)state)->flightDuration)
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIREBALL_HIT_VOLUME_SLOT,
                                ((FireballPlacement*)params)->hitVolumeMode != 0 ? 3 : 1, 0);
    }
    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_POS_LATCHED) == 0)
    {
        ((FireballState*)state)->posX = obj->anim.localPosX;
        ((FireballState*)state)->posY = obj->anim.localPosY;
        ((FireballState*)state)->posZ = obj->anim.localPosZ;
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_POS_LATCHED;
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
                u8 v = ((FireballState*)state)->colorIndex;
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
            ((FireballState*)state)->fadeoutTimer = 60.0f;
            obj->anim.alpha = 0;
            if (((FireballState*)state)->light != NULL)
            {
                ModelLightStruct_free(((FireballState*)state)->light);
                ((FireballState*)state)->light = NULL;
            }
            ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
            ObjHits_DisableObject(obj);
        }
    }
    if (((FireballState*)state)->fadeoutTimer != zero)
    {
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        ((FireballState*)state)->fadeoutTimer -= timeDelta;
        if (((FireballState*)state)->fadeoutTimer <= 0.0f)
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
                fn_8016F260(obj, state, other);
            }
        }
        ((FireballState*)state)->posX += obj->anim.velocityX * timeDelta;
        ((FireballState*)state)->posY += obj->anim.velocityY * timeDelta;
        ((FireballState*)state)->posZ += obj->anim.velocityZ * timeDelta;
        ((FireballState*)state)->spiralPhase += framesThisStep * 1500;
        if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_GRAVITY) != 0)
        {
            f32 ground;
            ((FireballState*)state)->posY -= 2.0f * timeDelta;
            if (hitDetectFn_800658a4(obj, ((FireballState*)state)->posX, ((FireballState*)state)->posY,
                                     ((FireballState*)state)->posZ, &ground, 0) == 0)
            {
                ground -= 10.0f;
                if (ground < 0.0f && ground > -15.0f)
                {
                    ((FireballState*)state)->posY -= ground;
                }
            }
        }
        obj->anim.localPosX = ((FireballState*)state)->posX;
        obj->anim.localPosY = ((FireballState*)state)->posY;
        obj->anim.localPosZ = ((FireballState*)state)->posZ;
        if (other != NULL)
        {
            obj->anim.localPosX +=
                8.0f *
                mathSinf(3.1415927f * (f32)((FireballState*)state)->spiralPhase / 32768.0f);
            obj->anim.localPosZ +=
                8.0f *
                mathCosf(3.1415927f * (f32)((FireballState*)state)->spiralPhase / 32768.0f);
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
    int* state = obj->extra;
    int* params = *(int**)&obj->anim.placementData;

    if (((FireballPlacement*)params)->startDisabled != 0)
    {
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_DISABLED;
    }
    else
    {
        FireballState* fs;
        int i;
        ((FireballState*)state)->unk40 = randomGetRange(600, 900);
        ((FireballState*)state)->unk42 = randomGetRange(-600, 600);
        ((FireballState*)state)->colorIndex = 0;
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if (hitState != NULL)
            {
                hitState->trackContactMask = 257;
            }
        }
        if (((FireballState*)state)->light == NULL)
        {
            ((FireballState*)state)->light = objCreateLight(obj, 1);
            if (((FireballState*)state)->light != NULL)
            {
                int c;
                u8* base1;
                u8* base2;
                modelLightStruct_setLightKind(((FireballState*)state)->light, MODEL_LIGHT_KIND_POINT);
                lightSetField4D(((FireballState*)state)->light, 0);
                modelLightStruct_setPosition(((FireballState*)state)->light, 0.0f, 0.0f,
                                             0.0f);
                lightSetFieldBC_8001db14(((FireballState*)state)->light, 1);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setDiffuseColor(
                    ((FireballState*)state)->light, ((u8*)lbl_80320978)[c],
                    (base1 = (u8*)lbl_80320978 + 1)[((FireballState*)state)->colorIndex * 3],
                    (base2 = (u8*)lbl_80320978 + 2)[((FireballState*)state)->colorIndex * 3], 0);
                modelLightStruct_setDistanceAttenuation(((FireballState*)state)->light, 60.0f, 80.0f);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setupGlow(((FireballState*)state)->light, 0, ((u8*)lbl_80320978)[c], base1[c],
                                           base2[c], 32, 50.0f);
                modelLightStruct_setGlowProjectionRadius(((FireballState*)state)->light, 50.0f);
            }
        }
        obj->anim.alpha = 200;
        for (i = 0, fs = (FireballState*)state; i < FIREBALL_ROT_COUNT; i++)
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
            ((FireballState*)state)->startupDelay = 4.0f;
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
