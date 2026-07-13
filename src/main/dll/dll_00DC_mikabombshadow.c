/*
 * mikabombshadow (DLL 0x00DC) - the Mika bomb's ground-shadow blob.
 *
 * init snaps the shadow onto the ground plane under the bomb (via
 * fn_80065684), caches the drop height in the extra slot and seeds the
 * model's shadow scale; update rescales/refades the shadow each frame from
 * the owner bomb's current height above ground; render forwards to the
 * shared shadow renderer while a shadow-cast slot is bound.
 */
#include "main/dll/dll_00DC_mikabombshadow_api.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/frame_timing.h"

__declspec(section ".sdata2") f32 lbl_803E31C0 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E31C4 = 4.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E31C8 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 gMikaBombGravityAccel = 0.01f;
__declspec(section ".sdata2") f32 gMikaBombMinFallVelocity = -2.5f;
__declspec(section ".sdata2") f32 lbl_803E31D4 = -1.0f;
__declspec(section ".sdata2") f32 lbl_803E31D8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E31DC = 14.0f;
__declspec(section ".sdata2") f32 lbl_803E31E0 = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E31E4 = 16384.0f;
extern void objShadowFn_80062498(int* obj, int p2, int p3, u8 frames);
extern int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e);

int MikaBombShadow_getExtraSize(void)
{
    return 0x4;
}
int MikaBombShadow_getObjectTypeId(void)
{
    return 0x0;
}

void MikaBombShadow_free(void)
{
}

void MikaBombShadow_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        if (((GameObject*)obj)->anim.modelState->shadowCastSlot != NULL)
        {
            objShadowFn_80062498(obj, 0, 0, framesThisStep);
        }
    }
}

void MikaBombShadow_hitDetect(void)
{
}

void MikaBombShadow_update(int* obj)
{
    int* owner;
    f32 fz = lbl_803E31D8;
    f32 scaleFactor;
    f32 alpha;

    owner = ((GameObject*)obj)->ownerObj;
    scaleFactor = fz - (((GameObject*)owner)->anim.localPosY - ((GameObject*)obj)->anim.localPosY) /
                           *(f32*)((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.modelState->shadowScale = lbl_803E31DC * scaleFactor + fz;
    alpha = scaleFactor * lbl_803E31E0;
    if (alpha > fz)
        alpha = fz;
    ((GameObject*)obj)->anim.modelState->shadowAlphaStep = lbl_803E31E4 * alpha;
}

void MikaBombShadow_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    f32 out;
    fn_80065684((int)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &out, 0);
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    ((GameObject*)obj)->anim.rotY = 0x4000;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.modelState->flags |= (u64)OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD;
    *(f32*)state = out;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - out;
    ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0;
    ((GameObject*)obj)->anim.modelState->shadowScale = lbl_803E31D8;
}

void MikaBombShadow_release(void)
{
}

void MikaBombShadow_initialise(void)
{
}

ObjectDescriptor gMikaBombShadowObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)MikaBombShadow_initialise,
    (ObjectDescriptorCallback)MikaBombShadow_release,
    0,
    (ObjectDescriptorCallback)MikaBombShadow_init,
    (ObjectDescriptorCallback)MikaBombShadow_update,
    (ObjectDescriptorCallback)MikaBombShadow_hitDetect,
    (ObjectDescriptorCallback)MikaBombShadow_render,
    (ObjectDescriptorCallback)MikaBombShadow_free,
    (ObjectDescriptorCallback)MikaBombShadow_getObjectTypeId,
    MikaBombShadow_getExtraSize,
};
