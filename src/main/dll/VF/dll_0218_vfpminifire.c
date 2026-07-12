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
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_0218_vfpminifire.h"

#define VFPMINIFIRE_OBJFLAG_HITDETECT_DISABLED 0x2000

#define VFPMINIFIRE_PERSIST_EFFECT 0x38c
#define VFPMINIFIRE_SMOKE_EFFECT   0x38a
#define VFPMINIFIRE_SPARK_EFFECT   0x38b
#define VFPMINIFIRE_BURST_EFFECT   0x38e
#define VFPMINIFIRE_EFFECT_FLAGS   0x80001
#define VFPMINIFIRE_BURST_COUNT    10

#define VFPMINIFIRE_SPAWN(obj, id, args, flags)                                                                        \
    (*gPartfxInterface)->spawnObject((void*)(obj), (id), (args), (flags), -1, NULL)

extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);

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

void VFP_MiniFire_render(int obj, int p2, int p3, int p4, int p5, s8 vis)
{
    if (vis == 0 || ((GameObject*)obj)->anim.alpha == 0)
    {
        return;
    }
    fn_80053ED0(8);
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, 1.0f);
    fn_80053EBC(8);
}

void VFP_MiniFire_hitDetect(void)
{
}

void VFP_MiniFire_update(GameObject* obj)
{
    /* local override: this TU treats randomGetRange's result as signed
       (vf_shared declares it u32); the int return is load-bearing. */
    VfpMinifireState* state = (obj)->extra;
    VfpMinifirePartfxArgs args;
    int linkedGfx;
    int i;

    if (0.0f == state->baseY)
    {
        hitDetectFn_800658a4((int)obj, (obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, (f32*)state,
                             0);
        state->baseY = (obj)->anim.localPosY - state->baseY;
    }

    if ((obj)->anim.velocityY > -15.0f)
    {
        (obj)->anim.velocityY += -0.03f;
    }

    (obj)->anim.localPosX += (obj)->anim.velocityX * timeDelta;
    (obj)->anim.localPosY += (obj)->anim.velocityY * timeDelta;
    (obj)->anim.localPosZ += (obj)->anim.velocityZ * timeDelta;

    args.x = 0.0f;
    args.y = 0.0f;
    args.z = 0.0f;
    args.scale = 1.0f;
    args.rz = 0;
    args.ry = 0;
    args.rx = 0;
    if ((int)randomGetRange(0, 4) == 0)
    {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }

    {
        f32 dx = (obj)->anim.localPosX - (obj)->anim.previousLocalPosX;
        f32 dy = (obj)->anim.localPosY - (obj)->anim.previousLocalPosY;
        f32 dz = (obj)->anim.localPosZ - (obj)->anim.previousLocalPosZ;
        args.x = dx / 3.0f;
        args.y = dy / 3.0f;
        args.z = dz / 3.0f;
    }
    if ((int)randomGetRange(0, 4) == 0)
    {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }

    args.x *= 2.0f;
    args.y *= 2.0f;
    args.z *= 2.0f;
    if ((int)randomGetRange(0, 4) == 0)
    {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SMOKE_EFFECT, &args, VFPMINIFIRE_EFFECT_FLAGS);
    }
    if ((int)randomGetRange(0, 2) == 0)
    {
        VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_SPARK_EFFECT, &args, 1);
    }

    linkedGfx = *(int*)&(obj)->anim.hitReactState;
    if ((void*)linkedGfx != NULL)
    {
        *(u8*)&((ObjHitsPriorityState*)linkedGfx)->hitVolumePriority = 0xb;
        *(u8*)&((ObjHitsPriorityState*)linkedGfx)->hitVolumeId = 1;
        *(int*)&((ObjHitsPriorityState*)linkedGfx)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)linkedGfx)->skeletonHitMask = 0x10;
    }
    if (((void*)linkedGfx != NULL && *(void**)&((ObjHitsPriorityState*)linkedGfx)->lastHitObject != NULL) ||
        ((obj)->anim.localPosY < state->baseY && state->burstStarted == 0))
    {
        state->burstStarted = 1;
        i = VFPMINIFIRE_BURST_COUNT;
        Sfx_StopObjectChannel((int)obj, 0x7f);
        for (; i != 0; i--)
        {
            VFPMINIFIRE_SPAWN(obj, VFPMINIFIRE_BURST_EFFECT, &args, 1);
        }
    }

    if (state->burstStarted != 0)
    {
        s16 alpha = (obj)->anim.alpha - (s16)timeDelta;
        if (alpha < 0)
        {
            alpha = 0;
        }
        (obj)->anim.alpha = alpha;
    }

    if ((obj)->anim.localPosY < state->baseY - 360.0f)
    {
        Obj_FreeObject(obj);
    }
}

void VFP_MiniFire_init(int* obj, u8* init)
{
    ((GameObject*)obj)->anim.velocityY = -15.0f;
    ((GameObject*)obj)->anim.localPosY = 400.0f + *(f32*)((char*)init + 0xc);
    ((GameObject*)obj)->anim.rootMotionScale *= 2.0f;
    (*gPartfxInterface)->spawnObject(obj, VFPMINIFIRE_PERSIST_EFFECT, NULL, 2, -1, NULL);
    Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_103);
    ((GameObject*)obj)->objectFlags |= VFPMINIFIRE_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_MiniFire_release(void)
{
}

void VFP_MiniFire_initialise(void)
{
}
