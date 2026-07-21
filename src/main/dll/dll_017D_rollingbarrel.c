#include "main/audio/sfx_ids.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_group.h"
#include "main/dll/IM/IMspacecraft.h"
#include "main/objhits.h"
#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"
typedef struct
{
    int a, b;
} RollingBarrelInitPair;

#define ROLLINGBARREL_OBJFLAG_PARENT_SLACK 0x1000

s16 gRollingBarrelExplodingCount;
const RollingBarrelInitPair gRollingBarrelCurveInitPair = { 21, 0 };

void RollingBarrel_explode(GameObject* obj, int unusedExplosionVariant)
{
    RollingBarrelState* state = (obj)->extra;
    u32 debrisType;
    GameObject* player;
    f32 dist;
    f32 falloff;
    gRollingBarrelExplodingCount += 1;
    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c_106);
    if (gRollingBarrelExplodingCount > 1)
    {
        debrisType = randomGetRange(0, 1) & 0xff;
        spawnExplosion(obj, (f32)(int)randomGetRange(0x32, 0x3c), 1, 1, 0, debrisType, 0, 0, 0);
    }
    else
    {
        debrisType = randomGetRange(0, 1) & 0xff;
        spawnExplosion(obj, (f32)(int)randomGetRange(0x32, 0x3c), 1, 1, 0, debrisType, 0, 1, 0);
    }
    state->state = ROLLINGBARREL_STATE_EXPLODED_WAIT;
    state->timer = 0.0f;
    (obj)->anim.flags = (s16)((obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                              (s32)(3.0f * (f32)(u32)(obj)->anim.modelInstance->primaryHitboxRadius));
    player = Obj_GetPlayerObject();
    if ((player->objectFlags & ROLLINGBARREL_OBJFLAG_PARENT_SLACK) == 0)
    {
        dist = Vec_distance(&(obj)->anim.worldPosX, &player->anim.worldPosX);
        if (dist <= 500.0f)
        {
            falloff = 1.0f - dist / 500.0f;
            CameraShake_Start(5.0f * falloff, 10.0f * falloff, 4.0f);
            doRumble(15.0f * falloff);
        }
    }
}

int RollingBarrel_getExtraSize(void)
{
    return sizeof(RollingBarrelState);
}
int RollingBarrel_getObjectTypeId(void)
{
    return 0x0;
}

void RollingBarrel_free(GameObject* obj)
{
    RollingBarrelState* state = obj->extra;
    int count;
    u32* groupObjects = ObjGroup_GetObjects(ROLLINGBARREL_GROUP_ID, &count);
    int i;
    u32 groupObject;
    for (i = 0; i < count; i++)
    {
        groupObject = groupObjects[i];
        if (groupObject == (u32)obj)
        {
            ObjGroup_RemoveObject((int)obj, ROLLINGBARREL_GROUP_ID);
            break;
        }
    }
    if (state->state == ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        gRollingBarrelExplodingCount -= 1;
    }
}

void RollingBarrel_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    RollingBarrelState* state = obj->extra;
    if (visible == 0 || state->state >= ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        return;
    }

    objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
}

void RollingBarrel_hitDetect(void)
{
}

void RollingBarrel_update(GameObject* obj)
{
    RollingBarrelState* state;
    RollingBarrelMapData* mapData;
    f32 floorY;
    f32 distanceSquared;
    int blocked;
    int hitObject;
    int hitSphereIndex;
    u32 hitVolume;
    int hitPriority;
    u32 explosionVariant;
    u8 stateId;

    state = (obj)->extra;
    hitObject = 0;
    mapData = (RollingBarrelMapData*)obj->anim.placementData;
    blocked = 0;
    distanceSquared = 0.0f;
    stateId = state->state;

    switch (stateId)
    {
    case ROLLINGBARREL_STATE_ROLLING:
    {
        if (mapData->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
        {
            f32 vmax = 3.0f;
            while (blocked == 0 && distanceSquared < vmax * timeDelta)
            {
                blocked = Curve_AdvanceAlongPath(&state->curve.curve, state->curveSpeed);
                if (blocked == 0 && state->curve.atSegmentEnd != 0)
                {
                    (*gRomCurveInterface)->goNextPoint(&state->curve);
                }
                {
                    f32 dx = state->curve.posX - (obj)->anim.previousLocalPosX;
                    f32 dz = state->curve.posZ - (obj)->anim.previousLocalPosZ;
                    distanceSquared = dx * dx + dz * dz;
                }
            }
        }
        else
        {
            blocked = Curve_AdvanceAlongPath(&state->curve.curve, state->curveSpeed);
            if (blocked == 0 && state->curve.atSegmentEnd != 0)
            {
                (*gRomCurveInterface)->goNextPoint(&state->curve);
            }
        }

        state->hitVolumeSlot = 10;
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, (obj)->anim.modelInstance->primaryHitboxRadius);

        if (mapData->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
        {
            floorY = 5.0f + state->curve.posY;
        }
        else
        {
            floorY = state->curve.posY;
        }

        state->verticalSpeed = -0.1f * timeDelta + state->verticalSpeed;
        (obj)->anim.localPosY = state->verticalSpeed * timeDelta + (obj)->anim.localPosY;

        if ((obj)->anim.localPosY < floorY)
        {
            if (mapData->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE &&
                (obj)->anim.localPosY < -2680.0f)
            {
                blocked = 1;
            }
            if (blocked == 0 && state->verticalSpeed * state->verticalSpeed > 3.0f)
            {
                Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_mfin2_c, 6);
            }
            state->verticalSpeed *= -0.6f;
            (obj)->anim.localPosY = 2.0f * floorY - (obj)->anim.localPosY;
        }
        (obj)->anim.localPosX = state->curve.posX;
        (obj)->anim.localPosZ = state->curve.posZ;
        obj->anim.rotX = (s16)getAngle(state->curve.tangentX, state->curve.tangentZ);

        if (state->pitchRising != 0)
        {
            (obj)->anim.rotZ = (s16)(32.0f * timeDelta + (f32)(int)(obj)->anim.rotZ);
            if ((obj)->anim.rotZ > 0x5000)
            {
                state->pitchRising = 0;
            }
        }
        else
        {
            (obj)->anim.rotZ = (s16) - (32.0f * timeDelta - (f32)(int)(obj)->anim.rotZ);
            if ((obj)->anim.rotZ < 0x3a00)
            {
                state->pitchRising = 1;
            }
        }

        {
            f32 rotYStep = 512.0f * timeDelta;
            (obj)->anim.rotY = (s16)(rotYStep * state->curveSpeed + (f32)(int)(obj)->anim.rotY);
        }
        hitPriority = ObjHits_GetPriorityHit(obj, &hitObject, &hitSphereIndex, &hitVolume);

        if (blocked != 0 || (void*)hitObject == (void*)Obj_GetPlayerObject() || (u32)(hitPriority - 0xe) <= 1u ||
            hitPriority == 0x13)
        {
            if (blocked == 0)
            {
                state->hitVolumeSlot = 0;
            }
            else
            {
                state->hitVolumeSlot = 5;
            }
            explosionVariant = randomGetRange(0, 2);
            RollingBarrel_explode(obj, explosionVariant);
        }
    }
    break;
    case ROLLINGBARREL_STATE_EXPLODED_WAIT:
        state->timer += timeDelta;
        if (state->timer >= 30.0f)
        {
            state->state = ROLLINGBARREL_STATE_RESPAWN_WAIT;
            state->timer -= 30.0f;
        }
        break;
    case ROLLINGBARREL_STATE_RESPAWN_WAIT:
        state->timer += timeDelta;
        if (state->timer >= 30.0f)
        {
            state->hitVolumeSlot = 0;
            state->state = ROLLINGBARREL_STATE_CLEANUP;
            state->timer -= 30.0f;
            ObjGroup_AddObject((int)obj, ROLLINGBARREL_GROUP_ID);
            gRollingBarrelExplodingCount -= 1;
        }
        break;
    case ROLLINGBARREL_STATE_CLEANUP:
        state->timer += timeDelta;
        if (state->timer >= 3000.0f)
        {
            Obj_FreeObject(obj);
            return;
        }
        break;
    }

    if (state->hitVolumeSlot != 0)
    {
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, state->hitVolumeSlot, 1, 0);
    }
    else
    {
        ObjHits_DisableObject(obj);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, state->hitVolumeSlot, 0, 0);
    }
}

void RollingBarrel_init(GameObject* obj, RollingBarrelMapData* params)
{
    RollingBarrelState* state = obj->extra;
    int tmp[2];

    *(RollingBarrelInitPair*)tmp = gRollingBarrelCurveInitPair;
    params->respawnParam = -1;
    obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
    obj->anim.rotZ = 0x4000;

    obj->anim.localPosX = params->x;
    obj->anim.worldPosX = params->x;
    obj->anim.localPosY = params->y;
    obj->anim.worldPosY = params->y;
    obj->anim.localPosZ = params->z;
    obj->anim.worldPosZ = params->z;

    state->verticalSpeed = params->verticalSpeed / 10.0f;
    state->curveSpeed = params->curveSpeed / 10.0f;
    state->state = ROLLINGBARREL_STATE_ROLLING;
    state->pitchRising = 1;
    state->timer = 0.0f;

    (*gRomCurveInterface)->initCurve(&state->curve, (void*)obj, 100.0f, tmp, -1);
}

void RollingBarrel_release(void)
{
}

void RollingBarrel_initialise(void)
{
    gRollingBarrelExplodingCount = 0x0;
}

ObjectDescriptor gRollingBarrelObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)RollingBarrel_initialise,
    (ObjectDescriptorCallback)RollingBarrel_release,
    0,
    (ObjectDescriptorCallback)RollingBarrel_init,
    (ObjectDescriptorCallback)RollingBarrel_update,
    (ObjectDescriptorCallback)RollingBarrel_hitDetect,
    (ObjectDescriptorCallback)RollingBarrel_render,
    (ObjectDescriptorCallback)RollingBarrel_free,
    (ObjectDescriptorCallback)RollingBarrel_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)RollingBarrel_getExtraSize,
};
