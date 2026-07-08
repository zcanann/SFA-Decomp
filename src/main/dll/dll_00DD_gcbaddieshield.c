/*
 * gcbaddieshield (DLL 0xDD) - the spinning shield effect object.
 *
 * A short-lived spinning, fading billboard: init seeds a lifetime counter
 * (state[0]) from the placement data, update spins it on rotX/rotZ each
 * frame scaled by timeDelta, fades alpha out over the final stretch, and
 * frees itself once the counter runs out; render draws the model while
 * obj->unkF4 == 0.
 */
#include "main/dll/xyzanimator.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/frame_timing.h"

extern f32 lbl_803E31F8;
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E320C;
extern f32 lbl_803E3210;
extern void objRenderModelAndHitVolumes(int* obj, int p2, int p3, int p4, int p5, f32 scale);
extern void Obj_FreeObject(int* obj);

int GCbaddieShield_getExtraSize(void)
{
    return 0x8;
}
int GCbaddieShield_getObjectTypeId(void)
{
    return 0x0;
}

void GCbaddieShield_free(void)
{
}

void GCbaddieShield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E31F8);
            break;
        default:
            break;
        }
    }
}

void GCbaddieShield_hitDetect(void)
{
}

void GCbaddieShield_update(int* obj)
{
    f32* state = ((GameObject*)obj)->extra;
    state[0] = state[0] - timeDelta;
    if (state[0] <= lbl_803E31FC)
    {
        Obj_FreeObject(obj);
        return;
    }
    ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + (s32)(lbl_803E3200 * timeDelta));
    ((GameObject*)obj)->anim.rotZ = (s16)(((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3204 * timeDelta));
    if (state[0] <= lbl_803E3208)
    {
        ((GameObject*)obj)->anim.alpha = (u8)(s32)(lbl_803E320C * (state[0] * lbl_803E3210));
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
}

void GCbaddieShield_init(int* obj, void* initData)
{
    int lifetime = *(s16*)((char*)initData + 0x1a);
    f32* state = ((GameObject*)obj)->extra;
    state[0] = lifetime;
}

void GCbaddieShield_release(void)
{
}

void GCbaddieShield_initialise(void)
{
}

ObjectDescriptor gGCbaddieShieldObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)GCbaddieShield_initialise,
    (ObjectDescriptorCallback)GCbaddieShield_release,
    0,
    (ObjectDescriptorCallback)GCbaddieShield_init,
    (ObjectDescriptorCallback)GCbaddieShield_update,
    (ObjectDescriptorCallback)GCbaddieShield_hitDetect,
    (ObjectDescriptorCallback)GCbaddieShield_render,
    (ObjectDescriptorCallback)GCbaddieShield_free,
    (ObjectDescriptorCallback)GCbaddieShield_getObjectTypeId,
    GCbaddieShield_getExtraSize,
};
