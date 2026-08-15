/*
 * StaticCamer (DLL 0x25A) - static camera object.
 *
 * A passive scene camera placement. init negates the placement's three
 * orientation shorts into the object's rotX/rotY/rotZ, caches a byte
 * setup value and a byte-derived float into the object's extra
 * (StaticCameraState), then (unless deferred) registers the object in
 * object group 7. free unregisters from the same group. render forwards
 * to the shared object render thunk; hitDetect/update/release/initialise
 * are no-ops. The object carries no per-frame logic and reserves 8 bytes
 * of extra state.
 */
#include "main/object_render.h"
#include "main/dll/dll_025A_staticcamera.h"
#include "main/objtype.h"

int StaticCamera_getExtraSize(void)
{
    return sizeof(StaticCameraState);
}
int StaticCamera_getObjectTypeId(void)
{
    return 0x0;
}

void StaticCamera_free(GameObject* obj)
{
    objFreeObjectType(obj, STATIC_CAMERA_OBJECT_GROUP);
}

void StaticCamera_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void StaticCamera_hitDetect(void)
{
}

void StaticCamera_update(void)
{
}

void StaticCamera_init(GameObject* obj, StaticCameraPlacement* params, int deferAdd)
{
    StaticCameraState* state;

    obj->anim.rotX = -params->objectRotation.rotX;
    obj->anim.rotY = -params->objectRotation.rotY;
    obj->anim.rotZ = -params->objectRotation.rotZ;
    state = obj->extra;
    state->setupParam = params->setupParam;
    state->fov = (f32)(u32)params->fov;
    state->unk1 = 0;
    if (deferAdd == 0)
    {
        objAddObjectType(obj, STATIC_CAMERA_OBJECT_GROUP);
    }
}

void StaticCamera_release(void)
{
}

void StaticCamera_initialise(void)
{
}

ObjectDescriptor gStaticCameraObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)StaticCamera_initialise,
    (ObjectDescriptorCallback)StaticCamera_release,
    0,
    (ObjectDescriptorCallback)StaticCamera_init,
    (ObjectDescriptorCallback)StaticCamera_update,
    (ObjectDescriptorCallback)StaticCamera_hitDetect,
    (ObjectDescriptorCallback)StaticCamera_render,
    (ObjectDescriptorCallback)StaticCamera_free,
    (ObjectDescriptorCallback)StaticCamera_getObjectTypeId,
    StaticCamera_getExtraSize,
};
