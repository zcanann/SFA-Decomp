/*
 * DLL 0x00DA - the homing pollen-cloud projectile/fragment
 * spawned by the pollen object. Each fragment picks one of five
 * PollenFragmentConfig presets by its pollen type (0..5), spawns a burst of
 * particle fx and a loop sfx on init, then per-frame steers toward the
 * nearest object in its target group, applies velocity damping/gravity,
 * optionally smooth-turns to face its velocity (or free-spins for the
 * 0x482 fragment object), and bursts (explosion fx + sfx) on contact with a
 * non-owner object. Timed variants fade their alpha out and self-free.
 */
#include "main/dll/partfx_interface.h"
#include "dolphin/mtx/vec.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/dll_00DA_pollenfragment_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/obj_path.h"
#include "main/objfx.h"
#include "dlls/object_descriptor.h"
#include "main/model_light.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/maketex_timer_api.h"
#include "main/objseq_api.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

f32 gPollenFragmentSpinRateX = 1024.0f;
f32 gPollenFragmentSpinRateY = 512.0f;

PollenFragmentConfig gPollenFragmentConfig0 = {
    0x0000, 0x049F, 0x00B9, 0x04BA, 0x04BA, -1, 0.2f, 0x0000, 1, 1, 0, 0,
};

PollenFragmentConfig gPollenFragmentConfig1 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0, 1, 1, 1,
};

PollenFragmentConfig gPollenFragmentConfig2 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0, 0, 1, 0,
};

PollenFragmentConfig gPollenFragmentConfig3 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, -1, 0.2f, 0x0000, 0, 0, 1, 0,
};

PollenFragmentConfig gPollenFragmentConfig4 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0, 0, 1, 1,
};

PollenFragmentConfig* gPollenFragmentConfigs[] = {
    &gPollenFragmentConfig0, &gPollenFragmentConfig1, &gPollenFragmentConfig2, &gPollenFragmentConfig3, &gPollenFragmentConfig4,
};

struct PollenFragmentPlacement
{
    ObjPlacement base;
    u8 unk18;
    s8 pollenType;
    u8 unk1A[10];
};

typedef struct PollenFragmentExtra
{
    int ownerObj; /* 0x00: owner captured on first update */
    f32 speed;    /* 0x04: steering speed factor */
    f32 timer;    /* 0x08: lifetime/strength timer */
    union {
        struct {
            f32 velX; /* 0x0C */
            f32 velY; /* 0x10 */
            f32 velZ; /* 0x14 */
        };
        Vec velocity;
    };
    ModelLightStruct* modelLight; /* 0x18 */
    PollenFragmentConfig* def; /* 0x1C */
    f32 deathTimer;         /* 0x20 */
    f32 lifetimeTimer;      /* 0x24 */
} PollenFragmentExtra;

#define POLLENFRAGMENT_HIT_VOLUME_SLOT 0x16

int pollenfragment_getExtraSize(void)
{
    return sizeof(PollenFragmentExtra);
}

int pollenfragment_getObjectTypeId(void)
{
    return 0x0;
}

void pollenfragment_free(GameObject* obj)
{
    PollenFragmentExtra* state = obj->extra;
    if (state->modelLight != NULL)
    {
        ModelLightStruct_free(state->modelLight);
        state->modelLight = NULL;
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pollenfragment_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    PollenFragmentExtra* state = obj->extra;
    if (timerIsActive(&state->deathTimer) != 0)
        return;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void pollenfragment_hitDetect(GameObject* obj)
{
    PollenFragmentExtra* extra;
    int hitType;
    GameObject* hitObject;

    extra = obj->extra;
    if (timerIsActive(&extra->deathTimer) == 0)
    {
        hitType = ObjHits_GetPriorityHit(obj, &hitObject, 0, 0);
        if (hitType == 0xe || hitType == 0xf)
        {
            if ((extra->def)->explodeSfxId != -1)
            {
                spawnExplosion((GameObject*)obj, 30.0f, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(
                    obj, (u16)(extra->def)->explodeSfxId, 3);
            }
            ObjHits_DisableObject(obj);
            s16toFloat(&extra->deathTimer, 0x78);
        }
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->contactFlags != 0)
        {
            ObjHits_DisableObject(obj);
            extra->timer = 0.0f;
            if ((extra->def)->explodeSfxId != -1)
            {
                spawnExplosion((GameObject*)obj, 30.0f, 0, 1, 0, 1, 0, 1, 0);
                Sfx_PlayFromObjectLimited(
                    obj, (u16)(extra->def)->explodeSfxId, 3);
            }
            s16toFloat(&extra->deathTimer, 0x78);
        }
    }
}

void pollenfragment_update(GameObject* obj)
{
    PollenFragmentExtra* extra;
    GameObject* nearObj;
    PollenFragmentConfig* def;
    GameObject* hit;
    int i;
    f32 horizDamping;
    f32 t;
    Vec dir;
    Vec sc;
    Vec pos;

    extra = obj->extra;
    if (getCurSeqNo() != 0)
    {
        Obj_FreeObject(obj);
        return;
    }
    if (timerIsActive(&extra->deathTimer) != 0)
    {
        if (timerCountDown(&extra->deathTimer) != 0)
        {
            Obj_FreeObject(obj);
        }
        return;
    }
    if (timerCountDown(&extra->lifetimeTimer) != 0)
    {
        s16toFloat(&extra->deathTimer, 0x78);
    }
    if (obj->ownerObj != NULL)
    {
        extra->ownerObj = (int)obj->ownerObj;
        obj->ownerObj = NULL;
    }
    if ((extra->def)->timed)
    {
        extra->timer -= timeDelta;
        if (extra->timer <= 0.0f)
        {
            if (obj->anim.alpha == 0xff)
            {
                i = 2;
                do
                {
                    (*gPartfxInterface)
                        ->spawnObject((void*)obj, (int)(extra->def)->burstFxId, NULL, 1, -1,
                                      NULL);
                } while (i-- != 0);
            }
            extra->timer = 0.0f;
            if (obj->anim.alpha >= framesThisStep << 3)
            {
                obj->anim.alpha -= framesThisStep << 3;
            }
            else
            {
                obj->anim.alpha = 0;
                Obj_FreeObject(obj);
                return;
            }
        }
    }
    if ((extra->def)->auraFxId != -1)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, (int)(extra->def)->auraFxId, NULL, 1, -1, NULL);
    }
    nearObj = (GameObject*)((u8*)objGetNearestTypeTo((int)(extra->def)->targetGroup, obj, 0));
    if (nearObj != NULL &&
        (!(def = extra->def)->timed || extra->timer < 210.0f))
    {
        if (def->usePath)
        {
            ObjPath_GetPointWorldPosition(nearObj, 0, &pos.x, &pos.y, &pos.z, 0);
        }
        else
        {
            f32 prod;
            f32 quarter = 0.25f;
            pos.x = nearObj->anim.worldPosX;
            prod = nearObj->anim.hitboxScale * nearObj->anim.rootMotionScale;
            pos.y = prod * quarter + nearObj->anim.worldPosY;
            pos.z = nearObj->anim.worldPosZ;
        }
        PSVECSubtract(&pos, &obj->anim.worldPos, &dir);
        PSVECMag(&dir);
        PSVECNormalize(&dir, &dir);
        PSVECSubtract(&dir, &extra->velocity, &sc);
        extra->velX = dir.x;
        extra->velY = dir.y;
        extra->velZ = dir.z;
        PSVECScale(&sc, &sc, 30.0f);
        PSVECAdd(&dir, &sc, &dir);
        obj->anim.velocityX =
            obj->anim.velocityX +
            ((30.0f + extra->timer) * (dir.x * extra->speed)) /
                210.0f;
        obj->anim.velocityZ =
            obj->anim.velocityZ +
            ((30.0f + extra->timer) * (dir.z * extra->speed)) /
                210.0f;
        if (!(extra->def)->noVertical)
        {
            obj->anim.velocityY =
                obj->anim.velocityY + ((30.0f + extra->timer) *
                                                      (2.0f * (dir.y * extra->speed))) /
                                                         210.0f;
        }
    }
    obj->anim.velocityX = obj->anim.velocityX * (horizDamping = 0.97f);
    obj->anim.velocityZ = obj->anim.velocityZ * horizDamping;
    obj->anim.velocityY *= 0.95f;
    if ((extra->def)->noVertical)
    {
        t = 0.04f * timeDelta;
        obj->anim.velocityY =
            obj->anim.velocityY - (t * extra->timer) / 300.0f;
    }
    if ((extra->def)->smoothTurn)
    {
        Obj_SmoothTurnAnglesTowardVelocity(obj, &obj->anim.velocity, 10, 0.0f,
                                           1.0f);
        obj->anim.rotZ = obj->anim.rotZ + framesThisStep * 0x500;
    }
    else if (obj->anim.romDefNo == POLLEN_FRAGMENT_OBJECT_ID)
    {
        t = 5.0f * gPollenFragmentSpinRateX;
        obj->anim.rotX = t * (f32)(u32)framesThisStep + (f32)(int)obj->anim.rotX;
        obj->anim.rotY =
            gPollenFragmentSpinRateY * (f32)(u32)framesThisStep + (f32)(int)obj->anim.rotY;
    }
    Sfx_KeepAliveLoopedObjectSound(obj, (u16)(extra->def)->loopSfxId);
    objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
            obj->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot(&obj->anim, POLLENFRAGMENT_HIT_VOLUME_SLOT, 1, 0);
    ObjHits_EnableObject(obj);
    hit = (GameObject*)((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
    if (hit != NULL && hit->anim.romDefNo != obj->anim.romDefNo &&
        hit != (void*)extra->ownerObj)
    {
        extra->timer = 0.0f;
        ObjHits_DisableObject(obj);
        if ((extra->def)->explodeSfxId != -1)
        {
            spawnExplosion(obj, 30.0f, 0, 1, 0, 1, 0, 1, 0);
            Sfx_PlayFromObjectLimited(
                obj, (u16)(extra->def)->explodeSfxId, 3);
        }
        s16toFloat(&extra->deathTimer, 0x78);
    }
}

void pollenfragment_init(GameObject* obj, PollenFragmentPlacement* setup)
{
    s8 pollenType;
    u32 randomValue;
    int spawnCount;
    PollenFragmentExtra* state;

    state = obj->extra;
    if (setup->pollenType == 1)
    {
        state->timer = 155.0f;
    }
    else
    {
        randomValue = randomGetRange(0xb4, 300);
        state->timer = (f32)(int)randomValue;
    }
    pollenType = setup->pollenType;
    pollenType = (pollenType < 0) ? 0 : ((pollenType > 5u) ? 5 : pollenType);
    setup->pollenType = pollenType;
    state->def = gPollenFragmentConfigs[setup->pollenType];
    if (state->def->spawnSfxId != 0)
    {
        Sfx_PlayFromObjectLimited(obj, (u16)state->def->spawnSfxId, 3);
    }
    spawnCount = 4;
    do
    {
        (*gPartfxInterface)->spawnObject((void*)obj, state->def->initFxId, NULL, 1, -1, NULL);
    } while (spawnCount-- != 0);
    if (!state->def->timed)
    {
        state->timer = 60.0f;
    }
    ObjHits_SetTargetMask(obj, 4);
    state->modelLight = NULL;
    state->speed = state->def->steerSpeed;
    state->ownerObj = 0;
    s16toFloat(&state->lifetimeTimer, 0xe10);
    storeZeroToFloatParam(&state->deathTimer);
}

void pollenfragment_release(void)
{
}

void pollenfragment_initialise(void)
{
}

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise, (ObjectDescriptorCallback)pollenfragment_release, 0,
    (ObjectDescriptorCallback)pollenfragment_init, (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect, (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free, (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};
