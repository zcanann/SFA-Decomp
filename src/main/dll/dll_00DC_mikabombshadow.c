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
#include "main/track_dolphin_api.h"

const f32 gMikaBombRenderScale = 1.0f;
const f32 gMikaBombFadeRate = 4.0f;
const f32 gMikaBombZero = 0.0f;
const f32 gMikaBombGravityAccel = 0.01f;
const f32 gMikaBombMinFallVelocity = -2.5f;
const f32 gMikaBombInitialVelocityY = -1.0f;

typedef struct MikaBombShadowState
{
    f32 groundOffset;
} MikaBombShadowState;

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

void MikaBombShadow_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        if (obj->anim.modelState->shadowCastSlot != NULL)
        {
            objShadowFn_80062498(obj, 0, 0, framesThisStep);
        }
    }
}

void MikaBombShadow_hitDetect(void)
{
}

void MikaBombShadow_update(GameObject* obj)
{
    GameObject* bomb;
    MikaBombShadowState* state;
    f32 fz = 1.0f;
    f32 scaleFactor;
    f32 alpha;

    bomb = obj->ownerObj;
    state = obj->extra;
    scaleFactor = fz - (bomb->anim.localPosY - obj->anim.localPosY) / state->groundOffset;
    obj->anim.modelState->shadowScale = 14.0f * scaleFactor + fz;
    alpha = scaleFactor;
    alpha *= 1.5f;
    if (alpha > fz)
        alpha = fz;
    obj->anim.modelState->shadowAlphaStep = 16384.0f * alpha;
}

void MikaBombShadow_init(GameObject* obj)
{
    MikaBombShadowState* state = obj->extra;
    f32 out;
    fn_80065684(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &out, 0);
    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
    obj->anim.rotY = 0x4000;
    obj->anim.rotX = 0;
    obj->anim.rotZ = 0;
    obj->anim.modelState->flags |= (u64)OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD;
    state->groundOffset = out;
    obj->anim.localPosY = obj->anim.localPosY - out;
    obj->anim.modelState->shadowAlphaStep = 0;
    obj->anim.modelState->shadowScale = 1.0f;
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
