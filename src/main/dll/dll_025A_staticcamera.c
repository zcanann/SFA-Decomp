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

#define STATICCAMERA_OBJGROUP 7

typedef struct StaticCameraState
{
    u8 setupParam;          /* 0x00: from placement byte 0x19 */
    u8 unk1;                /* 0x01: cleared at init */
    u8 pad2[2];
    f32 unk4;               /* 0x04: placement byte 0x1a as float */
} StaticCameraState;

typedef struct StaticCameraPlacement
{
    u8 pad00[0x19];
    u8 setupParam;          /* 0x19 */
    u8 unkByte1A;           /* 0x1A: stored into extra as float */
    u8 pad1B;
    s16 rotX;               /* 0x1C: negated into anim.rotX */
    s16 rotY;               /* 0x1E: negated into anim.rotY */
    s16 rotZ;               /* 0x20: negated into anim.rotZ */
} StaticCameraPlacement;

STATIC_ASSERT(offsetof(StaticCameraPlacement, setupParam) == 0x19);
STATIC_ASSERT(offsetof(StaticCameraPlacement, unkByte1A) == 0x1A);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotX) == 0x1C);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotY) == 0x1E);
STATIC_ASSERT(offsetof(StaticCameraPlacement, rotZ) == 0x20);

void StaticCamera_hitDetect(void)
{
}

void StaticCamera_update(void)
{
}

void StaticCamera_release(void)
{
}

void StaticCamera_initialise(void)
{
}

int StaticCamera_getExtraSize(void) { return sizeof(StaticCameraState); }
int StaticCamera_getObjectTypeId(void) { return 0x0; }

void StaticCamera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{

    extern f32 lbl_803E31E8;
    s32 v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E31E8);
    }
}

void StaticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, STATICCAMERA_OBJGROUP);
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

ObjectDescriptor gStaticCameraObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
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
