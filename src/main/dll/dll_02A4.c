/*
 * DLL 0x2A4 - a short-lived spinning debris object spawned around the
 * on-rails Arwing flight sections.
 *
 * fn_8023134C / fn_8023137C are the launch helpers the enemy generator's
 * spawn modes use to hand a freshly loaded ship its fade lifetime and
 * direction vector.
 *
 * The object itself (init/update/render) seeds random start rotations and
 * random per-axis spin rates, then each frame integrates the rotation,
 * drifts along its anim velocity, and fades out a timer in the first word
 * of its state block; when the timer reaches zero it frees itself.
 */
#include "main/frame_timing.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/object.h"
#include "main/dll/ARW/dll_02A3.h"
#include "main/dll/ARW/dll_02A4.h"
#include "main/object_descriptor.h"
#include "main/object_render_legacy.h"

/* random start-rotation range and per-axis spin-rate range */
#define ROT_RANGE_MAX 0xffff
#define SPIN_RATE_MAG 0x14

void fn_8023134C(GameObject* obj, int lifetime)
{
    Dll2A3State* state = obj->extra;
    state->lifetime = lifetime;
}

void fn_8023137C(GameObject* obj, Dll2A3Velocity* velocity)
{
    obj->anim.velocityX = velocity->x;
    obj->anim.velocityY = velocity->y;
    obj->anim.velocityZ = velocity->z;
}

int dll_2A4_getExtraSize_ret_12(void)
{
    return sizeof(Dll2A4State);
}

int dll_2A4_getObjectTypeId(void)
{
    return 0x0;
}

void dll_2A4_free_nop(void)
{
}

void dll_2A4_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7138);
}

void dll_2A4_hitDetect_nop(void)
{
}

void dll_2A4_update(GameObject* obj)
{
    Dll2A4State* state = obj->extra;

    if (state->fadeTimer > lbl_803E713C)
    {
        state->fadeTimer -= timeDelta;
        if (state->fadeTimer <= lbl_803E713C)
        {
            state->fadeTimer = lbl_803E713C;
            Obj_FreeObject(obj);
            return;
        }
    }

    obj->anim.rotX = (s16)((f32)state->spinRateX * timeDelta + (f32)obj->anim.rotX);
    obj->anim.rotY = (s16)((f32)state->spinRateY * timeDelta + (f32)obj->anim.rotY);
    obj->anim.rotZ = (s16)((f32)state->spinRateZ * timeDelta + (f32)obj->anim.rotZ);

    objMove((GameObject*)obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
            obj->anim.velocityZ * timeDelta);
}

void dll_2A4_init(GameObject* obj)
{
    Dll2A4State* state = obj->extra;

    obj->anim.rotX = randomGetRange(0, ROT_RANGE_MAX);
    obj->anim.rotY = randomGetRange(0, ROT_RANGE_MAX);
    obj->anim.rotZ = randomGetRange(0, ROT_RANGE_MAX);
    state->spinRateX = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateY = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
    state->spinRateZ = randomGetRange(-SPIN_RATE_MAG, SPIN_RATE_MAG);
}

void dll_2A4_release_nop(void)
{
}

void dll_2A4_initialise_nop(void)
{
}

ObjectDescriptor dll_2A4 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_2A4_initialise_nop, (ObjectDescriptorCallback)dll_2A4_release_nop, 0,
    (ObjectDescriptorCallback)dll_2A4_init, (ObjectDescriptorCallback)dll_2A4_update,
    (ObjectDescriptorCallback)dll_2A4_hitDetect_nop, (ObjectDescriptorCallback)dll_2A4_render,
    (ObjectDescriptorCallback)dll_2A4_free_nop, (ObjectDescriptorCallback)dll_2A4_getObjectTypeId,
    dll_2A4_getExtraSize_ret_12,
};
