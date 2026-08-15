/*
 * ARWBombColl (DLL 671) - the in-flight pickups and rings collected by
 * the Arwing in the on-rails sections. A pickup fades in once the Arwing is
 * close ahead, can oscillate along the X or Y axis (route modes 1/3 and
 * 4/5), spins, and watches for the Arwing passing through it. The reward on
 * collection depends on the object's romDefNo (health, max-health, score,
 * ring, laser upgrade, bomb, and the 0x6D8-0x6DB collectibles) and on the
 * pickup's "mode" (handled in Ring_onCollect). Rings also feed
 * the ring-count gate driven by arwlevelcon. Collision is checked two ways:
 * an axis-aligned proximity test (flag bit10) or a plane-crossing test that
 * compares the Arwing's current and previous Z against the pickup's Z.
 */
#include "main/audio/sfx_play_api.h"
#include "main/frame_timing.h"
#include "main/objfx.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define ARW_ARWING_BOMB_OBJ 0x605 /* retail OBJECTS.bin "ARWArwingBo", DLL 0x29C */

#define ARWBOMBCOLL_HIT_VOLUME_SLOT 0x13

static const f32 sRenderScale = 1.0f;
static const f32 sMinLifetime = 0.0f;
static const f32 sActivateDistanceZ = 3840.0f;
static const f32 sAlphaFadeRate = 3.0f;
static const f32 sSpinRate = 600.0f;
static const f32 sExplosionScale = 100.0f;

ObjectDescriptor gARWBombCollObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ARWBombColl_initialise,
    (ObjectDescriptorCallback)ARWBombColl_release,
    NULL,
    (ObjectDescriptorCallback)ARWBombColl_init,
    (ObjectDescriptorCallback)ARWBombColl_update,
    (ObjectDescriptorCallback)ARWBombColl_hitDetect,
    (ObjectDescriptorCallback)ARWBombColl_render,
    (ObjectDescriptorCallback)ARWBombColl_free,
    (ObjectDescriptorCallback)ARWBombColl_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)ARWBombColl_getExtraSize,
};

void arwbombcoll_setLifetime(GameObject* obj, int lifetime)
{
    ARWBombCollState* state = obj->extra;
    state->lifetime = lifetime;
}

int ARWBombColl_getExtraSize(void)
{
    return 8;
}

int ARWBombColl_getObjectTypeId(void)
{
    return 0;
}

void ARWBombColl_free(void)
{
}

void ARWBombColl_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, sRenderScale);
}

void ARWBombColl_hitDetect(void)
{
}

void ARWBombColl_update(GameObject* obj)
{
    GameObject* arw;
    ObjAnimComponent* objAnim;
    ArwBombFlags* flags;
    ARWBombCollState* state;
    GameObject* arwingCheck;
    f32 minLifetime;

    arw = getArwing();
    objAnim = &obj->anim;
    state = obj->extra;
    flags = &state->flags;

    {
        f32 lt = state->lifetime;
        if (lt > (minLifetime = sMinLifetime))
        {
            state->lifetime = lt - timeDelta;
            if (state->lifetime <= minLifetime)
            {
                Obj_FreeObject(obj);
                return;
            }
        }
    }

    if (arw != NULL && arwarwing_isExplodingOrWarping(arw) != 0)
    {
        flags->collected = 0;
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->collected != 0 ||
        (((arwingCheck = getArwing()) != NULL
              ? (obj->anim.localPosZ - arwingCheck->anim.localPosZ <
                 sActivateDistanceZ)
              : 0) == 0))
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        objAnim->alpha = 0;
    }
    else
    {
        {
            int alpha;

            alpha = (int)(sAlphaFadeRate * timeDelta + (f32)(u32)objAnim->alpha);
            if (alpha > 0xff)
            {
                alpha = 0xff;
            }
            objAnim->alpha = alpha;
            obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            obj->anim.rotX = sSpinRate * timeDelta + (f32) * &obj->anim.rotX;
            ObjHits_SetHitVolumeSlot(&obj->anim, ARWBOMBCOLL_HIT_VOLUME_SLOT, 0, 0);
            if (flags->shotOpen != 0)
            {
                if (((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
                    (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
                {
                    arwarwing_addScore(arw, 0x19);
                    flags->collected = 1;
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                }
            }
            else
            {
                GameObject* hit;
                if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0 && hit != NULL &&
                    (hit->anim.romDefNo == 0x604 || hit->anim.romDefNo == ARW_ARWING_BOMB_OBJ))
                {
                    arwarwing_addScore(arw, 0xf);
                    flags->shotOpen = 1;
                    Obj_SetActiveModelIndex(obj, 1);
                    spawnExplosion(obj, sExplosionScale, 1, 0, 0, 0, 0, 0, 2);
                }
                if (((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
                    (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
                {
                    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                    spawnExplosion(obj, sExplosionScale, 1, 0, 0, 0, 0, 0, 2);
                }
            }
            if (arw != NULL && flags->collected != 0)
            {
                switch (obj->anim.romDefNo)
                {
                case 0x609:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_ring_pickup);
                    arwarwing_upgradeLaserLevel(arw);
                    break;
                case 0x608:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_largeenergy_pickup);
                    arwarwing_addBomb(arw);
                    break;
                case 0x60a:
                    break;
                case 0x6d8:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
                    arwarwing_incrementPickup6D8Count(arw);
                    break;
                case 0x6d9:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
                    arwarwing_incrementPickup6D9Count(arw);
                    break;
                case 0x6db:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
                    arwarwing_incrementPickup6DBCount(arw);
                    break;
                case 0x6da:
                    Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
                    arwarwing_incrementPickup6DACount(arw);
                    break;
                }
            }
        }
    }
}

void ARWBombColl_init(GameObject* obj, ARWBombCollSetup* setup)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ARWBombCollSetup* mapData = setup;

    obj->anim.rotX = (s16)(mapData->rotXByte << 8);
    objAnim->alpha = 0;
}

void ARWBombColl_release(void)
{
}

void ARWBombColl_initialise(void)
{
}
