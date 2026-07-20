/* DLL 0x00E4 (flamethrowerspe) - Flame thrower special effect [0x80170004-0x801702D4). */
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll_000A_expgfx.h"
#include "main/maketex_timer_api.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/dll/firepipe_effect_api.h"

f32 lbl_803DBD60 = 2.0f;
int lbl_803DBD64 = 0x23;
f32 lbl_803DBD68 = 1.0f;
f32 lbl_803DBD6C = 8.0f;


/* object group this object joins while active */
#define FLAMETHROWERSPE_OBJGROUP 7

/* FlamethrowerSpeState.phase values */
#define FLAMETHROWERSPE_PHASE_LAUNCH 1 /* compute launch velocity, then -> ACTIVE */
#define FLAMETHROWERSPE_PHASE_ACTIVE 2 /* fly + shrink until the lifetime timer expires */

extern f32 lbl_803E33A0;

u32 lbl_803209C0[] = {
    0x0000004F,
    0xFFC40000,
    0x0000001F,
    0x0000004F,
    0x00C4FF00,
    0x00000005,
    0x0000004F,
    0x00C4FF00,
    0x0000001E,
};

void flamethrowerspe_modelMtxFn(void)
{
}

void flamethrowerspe_func0B(GameObject* obj)
{
    s32 v = 0x1;
    ((FlamethrowerSpeState*)obj->extra)->phase = v;
}

void flamethrowerspe_setScale(GameObject* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3)
{
    obj->anim.localPosX = f1;
    obj->anim.localPosY = f2;
    obj->anim.localPosZ = f3;
    obj->anim.rotY = a;
    obj->anim.rotX = b;
}

int flamethrowerspe_getExtraSize(void)
{
    return 0x14;
}
int flamethrowerspe_getObjectTypeId(void)
{
    return 0x0;
}

void flamethrowerspe_free(void)
{
}

void flamethrowerspe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    f32 scale = 1.0f;
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, scale);
}

void flamethrowerspe_hitDetect(void)
{
}

void flamethrowerspe_update(GameObject* obj)
{
    FlamethrowerSpeState* state = obj->extra;
    FlamethrowerSpePlacement* placement = (FlamethrowerSpePlacement*)obj->anim.placementData;
    switch (state->phase)
    {
    case FLAMETHROWERSPE_PHASE_LAUNCH:
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityZ =
            lbl_803DBD68 * (0.10000000149011612f * (state->sizeScale *
                                                    (0.11999999731779099f *
                                                     (f32)(s32)randomGetRange(0x64, 0x96))));
        vecRotateZXY(&obj->anim.rotX, &obj->anim.velocityX);
        state->sphereRadius = lbl_803DBD6C * state->sizeScale;
        s16toFloat(&state->lifeTimer, lbl_803DBD64);
        state->phase = FLAMETHROWERSPE_PHASE_ACTIVE;
        break;
    case FLAMETHROWERSPE_PHASE_ACTIVE:
        if (timerCountDown(&state->lifeTimer) != 0)
        {
            ObjHits_DisableObject(obj);
            firepipe_releaseEffectObject(obj);
            return;
        }
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj,
                                lbl_803209C0[(s8)placement->hitVolumeProfile * 3 + 2], 1, 0);
        {
            f32 dt = (f32)(f64)timeDelta;
            objMove(obj, obj->anim.velocityX * dt, obj->anim.velocityY * dt,
                    obj->anim.velocityZ * dt);
        }
        ObjHitbox_SetSphereRadius(
            (ObjAnimComponent*)obj,
            (int)(state->sphereRadius * (((f32)lbl_803DBD64 - state->lifeTimer) / lbl_803DBD64)));
        break;
    }
}

void flamethrowerspe_init(GameObject* obj, FlamethrowerSpePlacement* placement)
{
    FlamethrowerSpeState* state = obj->extra;
    storeZeroToFloatParam(&state->lifeTimer);
    {
        f32 r = (f32)placement->scaleParam / lbl_803E33A0;
        state->sizeScale = r * lbl_803DBD60;
    }
    obj->anim.velocityY = 0.0f;
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    state->phase = FLAMETHROWERSPE_PHASE_LAUNCH;
    ObjHits_DisableObject(obj);
}

void flamethrowerspe_release(void)
{
}

void flamethrowerspe_initialise(void)
{
}

ObjectDescriptor13 gFlameThrowerSpeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)flamethrowerspe_initialise,
    (ObjectDescriptorCallback)flamethrowerspe_release,
    0,
    (ObjectDescriptorCallback)flamethrowerspe_init,
    (ObjectDescriptorCallback)flamethrowerspe_update,
    (ObjectDescriptorCallback)flamethrowerspe_hitDetect,
    (ObjectDescriptorCallback)flamethrowerspe_render,
    (ObjectDescriptorCallback)flamethrowerspe_free,
    (ObjectDescriptorCallback)flamethrowerspe_getObjectTypeId,
    flamethrowerspe_getExtraSize,
    (ObjectDescriptorCallback)flamethrowerspe_setScale,
    (ObjectDescriptorCallback)flamethrowerspe_func0B,
    (ObjectDescriptorCallback)flamethrowerspe_modelMtxFn,
};
