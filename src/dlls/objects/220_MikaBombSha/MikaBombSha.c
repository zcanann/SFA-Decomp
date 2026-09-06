/*
 * MikaBombShadow object (DLL slot 220).
 *
 * Projects the Mika bomb's shadow onto the ground and scales its model and
 * opacity based on the bomb's height.
 */
#include "dlls/objects/220_MikaBombShadow.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/track_dolphin_api.h"

const f32 gMikaBombRenderScale = 1.0f;
const f32 gMikaBombFadeRate = 4.0f;
const f32 gMikaBombZero = 0.0f;
const f32 gMikaBombGravityAccel = 0.01f;
const f32 gMikaBombMinFallVelocity = -2.5f;
const f32 gMikaBombInitialVelocityY = -1.0f;

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

int MikaBombShadow_getExtraSize(void) {
    return sizeof(MikaBombShadowState);
}

int MikaBombShadow_getObjectTypeId(void) {
    return 0;
}

void MikaBombShadow_free(GameObject* obj) {
    (void)obj;
}

void MikaBombShadow_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    (void)fwdArg2;
    (void)fwdArg3;
    (void)fwdArg4;
    (void)fwdArg5;

    if (visible != 0) {
        if (obj->anim.modelState->shadowCastSlot != NULL) {
            (void)objShadowRender(obj, 0, 0, framesThisStep);
        }
    }
}

void MikaBombShadow_hitDetect(GameObject* obj) {
}

void MikaBombShadow_update(GameObject* obj) {
    GameObject* bomb = obj->ownerObj;
    MikaBombShadowState* state = obj->extra;
    f32 scaleFactor = 1.0f - (bomb->anim.localPosY - obj->anim.localPosY) / state->groundOffset;
    obj->anim.modelState->shadowScale = 14.0f * scaleFactor + 1.0f;

    scaleFactor *= 1.5f;
    if (scaleFactor > 1.0f) {
        scaleFactor = 1.0f;
    }

    obj->anim.modelState->shadowAlphaStep = 16384.0f * scaleFactor;
}

void MikaBombShadow_init(GameObject* obj) {
    MikaBombShadowState* state = obj->extra;
    f32 groundDistance;

    (void)trackGetHeightAboveGround(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &groundDistance,
                                    0);
    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
    obj->anim.rotY = 0x4000;
    obj->anim.rotX = 0;
    obj->anim.rotZ = 0;
    obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD;
    state->groundOffset = groundDistance;
    obj->anim.localPosY -= groundDistance;
    obj->anim.modelState->shadowAlphaStep = 0;
    obj->anim.modelState->shadowScale = 1.0f;
}

void MikaBombShadow_release(void) {
}

void MikaBombShadow_initialise(void) {
}
