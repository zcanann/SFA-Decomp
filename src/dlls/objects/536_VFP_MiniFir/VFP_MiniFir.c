/*
 * vfpminifire (DLL 0x218, VFP_MiniFire) - a short-lived fiery ember /
 * spark projectile in the Volcano Force Point Temple.
 *
 * On the first update it ray-casts straight down to record the ground
 * height beneath it (baseY becomes the fall distance to the floor). Each
 * tick it applies gravity, integrates its velocity into position, and
 * spawns smoke/spark particle puffs (randomly, and biased along its
 * motion). When it strikes something or drops below the recorded floor
 * it fires a burst of flame particles, fades its alpha out, and frees
 * itself once it falls past the floor.
 */
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "game/objects/object_setup.h"
#include "main/object_render.h"
#include "main/dll/expgfx_interface.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_0218_vfpminifire.h"
#include "main/rcp_dolphin_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

#define VFPMINIFIRE_PERSIST_EFFECT 0x38c
#define VFPMINIFIRE_SMOKE_EFFECT   0x38a
#define VFPMINIFIRE_SPARK_EFFECT   0x38b
#define VFPMINIFIRE_BURST_EFFECT   0x38e
#define VFPMINIFIRE_EFFECT_FLAGS   0x80001
#define VFPMINIFIRE_BURST_COUNT    10

int VFP_MiniFire_getExtraSize(void)
{
    return 0xc;
}

int VFP_MiniFire_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_MiniFire_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void VFP_MiniFire_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    if (vis == 0 || obj->anim.alpha == 0)
    {
        return;
    }
    Rcp_SetRenderFlags(8);
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    Rcp_ClearRenderFlags(8);
}

void VFP_MiniFire_hitDetect(void)
{
}

void VFP_MiniFire_update(GameObject* obj)
{
    /* The sampled offsets are intentionally signed. */
    VfpMinifireState* state = obj->extra;
    PartFxSpawnParams args;
    ObjHitsPriorityState* linkedGfx;
    int i;

    if (state->baseY == 0.0f)
    {
        trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, (f32*)state, 0);
        state->baseY = obj->anim.localPosY - state->baseY;
    }

    if (obj->anim.velocityY > -15.0f) {
        obj->anim.velocityY += -0.03f;
    }

    obj->anim.localPosX += obj->anim.velocityX * timeDelta;
    obj->anim.localPosY += obj->anim.velocityY * timeDelta;
    obj->anim.localPosZ += obj->anim.velocityZ * timeDelta;

    args.posX = 0.0f;
    args.posY = 0.0f;
    args.posZ = 0.0f;
    args.scale = 1.0f;
    args.rotZ = 0;
    args.rotY = 0;
    args.rotX = 0;
    if (randomGetRange(0, 4) == 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS, -1, NULL);
    }

    {
        f32 dx = obj->anim.localPosX - obj->anim.previousLocalPosX;
        f32 dy = obj->anim.localPosY - obj->anim.previousLocalPosY;
        f32 dz = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
        args.posX = dx / 3.0f;
        args.posY = dy / 3.0f;
        args.posZ = dz / 3.0f;
    }
    if (randomGetRange(0, 4) == 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS, -1, NULL);
    }

    args.posX *= 2.0f;
    args.posY *= 2.0f;
    args.posZ *= 2.0f;
    if (randomGetRange(0, 4) == 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS, -1, NULL);
    }
    if (randomGetRange(0, 2) == 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, VFPMINIFIRE_SPARK_EFFECT, &args, 1, -1, NULL);
    }

    linkedGfx = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if ((void*)linkedGfx != NULL)
    {
        linkedGfx->hitVolumePriority = 0xb;
        linkedGfx->hitVolumeId = 1;
        linkedGfx->objectHitMask = 0x10;
        linkedGfx->skeletonHitMask = 0x10;
    }
    if (((void*)linkedGfx != NULL && linkedGfx->lastHitObject != 0) ||
        (obj->anim.localPosY < state->baseY && state->burstStarted == 0)) {
        state->burstStarted = 1;
        i = VFPMINIFIRE_BURST_COUNT;
        Sfx_StopObjectChannel(obj, 0x7f);
        for (; i != 0; i--)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, VFPMINIFIRE_BURST_EFFECT, &args, 1, -1, NULL);
        }
    }

    if (state->burstStarted != 0)
    {
        s16 alpha = obj->anim.alpha - (s16)timeDelta;
        if (alpha < 0)
        {
            alpha = 0;
        }
        obj->anim.alpha = alpha;
    }

    if (obj->anim.localPosY < state->baseY - 360.0f) {
        Obj_FreeObject(obj);
    }
}

void VFP_MiniFire_init(GameObject* obj, u8* init)
{
    obj->anim.velocityY = -15.0f;
    obj->anim.localPosY = 400.0f + ((ObjPlacement*)init)->posY;
    obj->anim.rootMotionScale *= 2.0f;
    (*gPartfxInterface)->spawnObject(obj, VFPMINIFIRE_PERSIST_EFFECT, NULL, 2, -1, NULL);
    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_103);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_MiniFire_release(void)
{
}

void VFP_MiniFire_initialise(void)
{
}

ObjectDescriptor gVFP_MiniFireObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_MiniFire_initialise,
    (ObjectDescriptorCallback)VFP_MiniFire_release,
    0,
    (ObjectDescriptorCallback)VFP_MiniFire_init,
    (ObjectDescriptorCallback)VFP_MiniFire_update,
    (ObjectDescriptorCallback)VFP_MiniFire_hitDetect,
    (ObjectDescriptorCallback)VFP_MiniFire_render,
    (ObjectDescriptorCallback)VFP_MiniFire_free,
    (ObjectDescriptorCallback)VFP_MiniFire_getObjectTypeId,
    VFP_MiniFire_getExtraSize,
};
