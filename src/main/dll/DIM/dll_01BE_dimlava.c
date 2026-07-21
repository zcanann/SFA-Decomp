/*
 * dimlava (DLL 0x1BE) - DIM lava-ball objects; the 0x1BE variant handles
 * both a small debris particle (seqId 0x1FA) and a full physics lava-ball
 * that homes on a target, glows, and triggers explosions on contact.
 */

#define LAVA1BE_SEQID_DEBRIS 0x1fa
#define LAVA1BE_PARTFX       0x1f5

#define LAVA1BE_FLAG_UPDATED    0x08
#define LAVA1BE_FLAG_INACTIVE   0x10
#define LAVA1BE_FLAG_FALLING    0x20
#include "main/dll/partfx_interface.h"
#include "main/dll/DIM/dll_01BE_dimlava.h"
#include "main/rcp_dolphin_api.h"
#include "main/object_api.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/dll/IM/dll_016D_imicepillar.h"
#include "main/object_descriptor.h"

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objfx.h"
#include "main/audio/sfx_play_api.h"
#include "main/frame_timing.h"
#include "main/model_light.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

typedef struct DimLavaDebrisLaunch
{
    Vec3f velocity;
    Vec3s rotation;
    u8 pad12[0x24 - 0x12];
} DimLavaDebrisLaunch;

const Vec3f gDimLavaDebrisBaseVec = {1.2f, 0.0f, 0.0f};

STATIC_ASSERT(offsetof(DimLavaDebrisLaunch, rotation) == 0x0C);
STATIC_ASSERT(sizeof(DimLavaDebrisLaunch) == 0x24);

static void lavaball1be_applyDebrisGravity(GameObject* obj)
{
    obj->anim.velocityY = -(0.05f * timeDelta - obj->anim.velocityY);
}

static void lavaball1be_scaleDebrisRootMotion(GameObject* obj)
{
    obj->anim.rootMotionScale *= 0.25f;
}

void lavaball1be_relaunch(GameObject* obj, int verticalSpeed, int horizontalSpeed)
{
    Lavaball1beState* state;
    DimLavaPlacement* placement;
    f32 vxz;
    f32 x;

    state = obj->extra;
    placement = (DimLavaPlacement*)obj->anim.placement;
    vxz = 0.1f * horizontalSpeed;
    x = state->targetObj->anim.localPosX;
    obj->anim.worldPosX = x;
    obj->anim.localPosX = x;
    x = state->targetObj->anim.localPosY;
    obj->anim.worldPosY = x;
    obj->anim.localPosY = x;
    x = state->targetObj->anim.localPosZ;
    obj->anim.worldPosZ = x;
    obj->anim.localPosZ = x;
    x = obj->anim.localPosX;
    obj->anim.previousWorldPosX = x;
    obj->anim.previousLocalPosX = x;
    x = obj->anim.localPosY;
    obj->anim.previousWorldPosY = x;
    obj->anim.previousLocalPosY = x;
    x = obj->anim.localPosZ;
    obj->anim.previousWorldPosZ = x;
    obj->anim.previousLocalPosZ = x;
    obj->anim.rotX = (s16)((s32)placement->launchYaw << 8);
    obj->anim.velocityX = vxz * -mathSinf(3.14159274f * (f32)obj->anim.rotX / 32768.0f);
    obj->anim.velocityY = 0.1f * verticalSpeed;
    obj->anim.velocityZ = vxz * -mathCosf(3.14159274f * (f32)obj->anim.rotX / 32768.0f);
    obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    state->statusFlags &= ~LAVA1BE_FLAG_INACTIVE;
}

u32 lavaball1be_isInactive(GameObject* obj)
{
    Lavaball1beState* state = obj->extra;
    return state->statusFlags & LAVA1BE_FLAG_INACTIVE;
}

int lavaball1be_getExtraSize(GameObject* obj)
{
    if (obj->anim.seqId == LAVA1BE_SEQID_DEBRIS)
        return 0x0;
    return sizeof(Lavaball1beState);
}

int lavaball1be_getObjectTypeId(GameObject* obj)
{
    if (obj->anim.seqId == LAVA1BE_SEQID_DEBRIS)
        return 0x0;
    return 0x2;
}

void lavaball1be_free(GameObject* obj)
{
    Lavaball1beState* inner = obj->extra;
    if (inner->light != 0)
    {
        ModelLightStruct_free(inner->light);
        inner->light = 0;
    }
}

void lavaball1be_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    Lavaball1beState* state = obj->extra;
    if (state->light != NULL)
    {
        if (modelLightStruct_getActiveState(state->light) != 0)
        {
            queueGlowRender(state->light);
        }
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void lavaball1be_hitDetect(void)
{
}

void lavaball1be_update(GameObject* obj)
{
    Lavaball1beState* state;
    ObjHitsPriorityState* hitState;

    if (obj->anim.seqId == LAVA1BE_SEQID_DEBRIS)
    {
        obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
        (*gPartfxInterface)->spawnObject(obj, LAVA1BE_PARTFX, NULL, 1, -1, NULL);
        obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x374;
        obj->anim.rotY = obj->anim.rotY + framesThisStep * 0x12c;
        lavaball1be_applyDebrisGravity(obj);
        obj->userData1 = obj->userData1 - framesThisStep;
        if (obj->userData1 < 0)
        {
            Obj_FreeObject(obj);
        }
    }
    else
    {
        state = obj->extra;
        if (state->statusFlags & LAVA1BE_FLAG_INACTIVE)
        {
            ObjHits_DisableObject(obj);
        }
        else
        {
            f32 dt = timeDelta;
            u8 steps = framesThisStep;
            if (state->explosionCooldown != 0)
            {
                state->explosionCooldown--;
            }
            obj->anim.rotX = obj->anim.rotX + (steps << 6);
            obj->anim.rotY = obj->anim.rotY - (steps << 9);
            obj->anim.velocityY = -0.09f * dt + obj->anim.velocityY;
            objMove(obj, obj->anim.velocityX * dt, obj->anim.velocityY * dt, obj->anim.velocityZ * dt);
            if (obj->anim.velocityY < 2.0f)
            {
                if (!(state->statusFlags & LAVA1BE_FLAG_FALLING))
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_en_cvdrip1c_3dd);
                    state->statusFlags |= LAVA1BE_FLAG_FALLING;
                }
            }
            else
            {
                state->statusFlags &= ~LAVA1BE_FLAG_FALLING;
            }
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if (hitState != NULL)
            {
                hitState->hitVolumePriority = 0xb;
                hitState->hitVolumeId = 1;
                hitState->objectHitMask = 0x10;
                hitState->skeletonHitMask = 0x10;
                if (*(void**)&hitState->lastHitObject != NULL)
                {
                    if (state->explosionCooldown != 0)
                    {
                        spawnExplosion(obj, 60.0f, 0, 1, 0, 0, 0, 0, 0);
                    }
                    else
                    {
                        state->explosionCooldown = 0xa;
                        spawnExplosion(obj, 60.0f, 1, 1, 0, 0, 0, 0, 0);
                    }
                    state->statusFlags |= LAVA1BE_FLAG_INACTIVE;
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
                if (hitState->contactFlags & OBJHITS_CONTACT_FLAG_KIND0)
                {
                    spawnExplosion(obj, 60.0f, 1, 1, 0, 0, 0, 0, 0);
                    state->statusFlags |= LAVA1BE_FLAG_INACTIVE;
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    return;
                }
            }
            if (obj->anim.localPosY < state->floorY)
            {
                state->statusFlags |= LAVA1BE_FLAG_INACTIVE;
            }
            if (!(state->statusFlags & LAVA1BE_FLAG_UPDATED))
            {
                state->statusFlags |= LAVA1BE_FLAG_UPDATED;
            }
            if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
            {
                modelLightStruct_updateGlowAlpha(state->light);
            }
        }
    }
}

void lavaball1be_init(GameObject* obj, DimLavaPlacement* placement)
{
    Lavaball1beState* state;
    if (obj->anim.seqId == LAVA1BE_SEQID_DEBRIS)
    {
        DimLavaDebrisLaunch launch;
        launch.velocity = gDimLavaDebrisBaseVec;
        launch.rotation.z = 0;
        launch.rotation.y = randomGetRange(-0x2ee0, 0x2ee0);
        launch.rotation.x = randomGetRange(0, 0xfffe);
        vecRotateZXY((s16*)((u8*)&launch + offsetof(DimLavaDebrisLaunch, rotation)), (f32*)&launch.velocity);
        obj->userData1 = 0x4b;
        obj->anim.velocityX = launch.velocity.x;
        obj->anim.velocityY = launch.velocity.y;
        obj->anim.velocityZ = launch.velocity.z;
        lavaball1be_scaleDebrisRootMotion(obj);
    }
    else
    {
        f32 vy;
        f32 vxz;
        ObjHitsPriorityState* hitState;
        ModelLightStruct* light;

        obj->anim.rotX = (s16)((s32)placement->launchYaw << 8);
        state = obj->extra;
        vy = 0.1f * (f32)placement->verticalSpeed;
        vxz = 0.1f * (f32)placement->horizontalSpeed;
        state->floorY = obj->anim.localPosY;
        state->linkedObjectId = placement->linkedObjectId;
        placement->linkedObjectId = -1;
        obj->anim.velocityX = vxz * -mathSinf(3.14159274f * (f32)obj->anim.rotX / 32768.0f);
        obj->anim.velocityY = vy;
        obj->anim.velocityZ = vxz * -mathCosf(3.14159274f * (f32)obj->anim.rotX / 32768.0f);
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        if (hitState != NULL)
        {
            hitState->lateralResponseWeight = 0;
        }
        if (obj->anim.modelState != NULL)
        {
            obj->anim.modelState->flags |= 0x810;
        }
        state->targetObj = ObjList_FindObjectById(state->linkedObjectId);
        state->statusFlags |= LAVA1BE_FLAG_INACTIVE;
        ObjHits_DisableObject(obj);
        obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
        state->light = objCreateLight(obj, 1);
        light = state->light;
        if (light != NULL)
        {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0x80, 0, 0);
            modelLightStruct_setDistanceAttenuation(state->light, 30.0f,
                                                    50.0f);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0x80, 0, 0x64, 20.0f);
            modelLightStruct_setGlowProjectionRadius(state->light, 20.0f);
        }
    }
}

void lavaball1be_release(void)
{
}

void lavaball1be_initialise(void)
{
}

ObjectDescriptor12 gLavaBall1BEObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)lavaball1be_initialise,
    (ObjectDescriptorCallback)lavaball1be_release,
    0,
    (ObjectDescriptorCallback)lavaball1be_init,
    (ObjectDescriptorCallback)lavaball1be_update,
    (ObjectDescriptorCallback)lavaball1be_hitDetect,
    (ObjectDescriptorCallback)lavaball1be_render,
    (ObjectDescriptorCallback)lavaball1be_free,
    (ObjectDescriptorCallback)lavaball1be_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)lavaball1be_getExtraSize,
    (ObjectDescriptorCallback)lavaball1be_relaunch,
    (ObjectDescriptorCallback)lavaball1be_isInactive,
};
