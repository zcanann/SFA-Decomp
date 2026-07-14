/*
 * softbody (DLL 0x2AD) - a decorative wobbling/swaying object whose
 * animation move is driven by a pair of shared, free-running phase
 * accumulators (lbl_803DDDA0 / lbl_803DDD9C). The first non-disabled
 * instance to update becomes the global "phase driver" (lbl_803DDD98)
 * and advances both phases by timeDelta each frame, wrapping each at
 * lbl_803E7288; every softbody then samples one of the two phases to
 * pick its current animation move. Which phase is used depends on the
 * object's seqId: moves in [0x6AF,0x6B2) use the first phase, all
 * others use the second.
 *
 * init applies the placement's packed 1/256-turn rotations and optional
 * scale (also scaling the hit sphere); the object has no per-instance
 * extra state (getExtraSize returns 0).
 */
#include "main/dll/dll_02AD_softbody.h"

f32 lbl_803DDDA0;
f32 lbl_803DDD9C;
GameObject* lbl_803DDD98;
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

__declspec(section ".sdata2") f32 lbl_803E7288 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E728C = 0.001f;
__declspec(section ".sdata2") f32 lbl_803E7290 = 0.005f;
__declspec(section ".sdata2") f32 lbl_803E7294 = 255.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E7298 = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E729C = 0.0f;
#pragma explicit_zero_data off

#define SOFTBODY_OBJECT_FLAGS_INIT 0x2000

/* seqId range whose moves are driven by the first shared phase */
#define SOFTBODY_MOVE_PHASE_A_FIRST 0x6af
#define SOFTBODY_MOVE_PHASE_A_END   0x6b2

int SoftBody_getExtraSize(void)
{
    return 0;
}

int SoftBody_getObjectTypeId(void)
{
    return 0;
}

void SoftBody_free(GameObject* obj)
{
    if (obj == lbl_803DDD98)
    {
        lbl_803DDD98 = NULL;
    }
}

void SoftBody_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7288);
    }
}

void SoftBody_hitDetect(void)
{
}

void SoftBody_update(GameObject* obj)
{
    GameObject* object = obj;
    SoftBodySetup* setup = (SoftBodySetup*)object->anim.placementData;

    if (lbl_803DDD98 == NULL && setup->phaseDriverDisabled == 0)
    {
        lbl_803DDD98 = obj;
    }

    if (obj == lbl_803DDD98)
    {
        f32 phase;

        phase = lbl_803E728C * timeDelta + lbl_803DDDA0;
        lbl_803DDDA0 = phase;
        while (phase > *(f32*)&lbl_803E7288)
        {
            phase -= *(f32*)&lbl_803E7288;
        }
        lbl_803DDDA0 = phase;
        phase = lbl_803E7290 * timeDelta + lbl_803DDD9C;
        lbl_803DDD9C = phase;
        while (phase > *(f32*)&lbl_803E7288)
        {
            phase -= *(f32*)&lbl_803E7288;
        }
        lbl_803DDD9C = phase;
    }

    switch (object->anim.seqId)
    {
    case SOFTBODY_MOVE_PHASE_A_FIRST:
    case SOFTBODY_MOVE_PHASE_A_FIRST + 1:
    case SOFTBODY_MOVE_PHASE_A_FIRST + 2:
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803DDDA0, 0);
        break;
    default:
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803DDD9C, 0);
        break;
    }
}

void SoftBody_init(GameObject* obj, SoftBodySetup* setup)
{
    GameObject* object = obj;
    SoftBodySetup* setupData = setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / lbl_803E7294;
        if (object->anim.rootMotionScale == lbl_803E7298)
        {
            object->anim.rootMotionScale = lbl_803E7288;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags |= SOFTBODY_OBJECT_FLAGS_INIT;
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E7298, 0);
    if (object->anim.hitReactState != NULL)
    {
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (s16)((f32)((ObjHitsPriorityState*)object->anim.hitReactState)->primaryRadius *
                                        object->anim.rootMotionScale));
    }
}

void SoftBody_release(void)
{
}

void SoftBody_initialise(void)
{
    lbl_803DDD98 = NULL;
    lbl_803DDDA0 = lbl_803E7298;
    lbl_803DDD9C = lbl_803E7298;
}

ObjectDescriptor gSoftBodyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SoftBody_initialise,
    (ObjectDescriptorCallback)SoftBody_release,
    0,
    (ObjectDescriptorCallback)SoftBody_init,
    (ObjectDescriptorCallback)SoftBody_update,
    (ObjectDescriptorCallback)SoftBody_hitDetect,
    (ObjectDescriptorCallback)SoftBody_render,
    (ObjectDescriptorCallback)SoftBody_free,
    (ObjectDescriptorCallback)SoftBody_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)SoftBody_getExtraSize,
};
