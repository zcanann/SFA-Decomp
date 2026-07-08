/*
 * DLL 0x25A - static camera object.
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
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
#include "main/dll/dll_025A_staticcamera.h"

#define STATICCAMERA_OBJGROUP 7

int StaticCamera_getExtraSize(void)
{
    return sizeof(StaticCameraState);
}
int StaticCamera_getObjectTypeId(void)
{
    return 0x0;
}

void StaticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, STATICCAMERA_OBJGROUP);
}

void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
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

    obj->anim.rotX = -params->rotX;
    obj->anim.rotY = -params->rotY;
    obj->anim.rotZ = -params->rotZ;
    state = obj->extra;
    state->setupParam = params->setupParam;
    state->unk4 = (f32)(u32)params->unkByte1A;
    state->unk1 = 0;
    if (deferAdd == 0)
    {
        ObjGroup_AddObject((int)obj, STATICCAMERA_OBJGROUP);
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
