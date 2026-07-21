/*
 * softbody (DLL 0x2AD) - a decorative wobbling/swaying object whose
 * animation move is driven by a pair of shared, free-running phase
 * accumulators. The first non-disabled instance to update becomes the
 * global phase driver
 * and advances both phases by timeDelta each frame, wrapping each at
 * 1.0f; every softbody then samples one of the two phases to
 * pick its current animation move. Which phase is used depends on the
 * object's seqId: moves in [0x6AF,0x6B2) use the first phase, all
 * others use the second.
 *
 * init applies the placement's packed 1/256-turn rotations and optional
 * scale (also scaling the hit sphere); the object has no per-instance
 * extra state (getExtraSize returns 0).
 */
#include "main/dll/dll_02AD_softbody.h"

f32 gSoftBodySlowPhase;
f32 gSoftBodyFastPhase;
GameObject* gSoftBodyPhaseDriver;
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

#define SOFTBODY_OBJECT_FLAGS_INIT 0x2000
#define SOFTBODY_SLOW_PHASE_RATE   0.001f
#define SOFTBODY_FAST_PHASE_RATE   0.005f
#define SOFTBODY_PHASE_WRAP        1.0f
#define SOFTBODY_ROTATION_SHIFT    8
#define SOFTBODY_SCALE_DIVISOR     255.0f

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
    if (obj == gSoftBodyPhaseDriver)
    {
        gSoftBodyPhaseDriver = NULL;
    }
}

void SoftBody_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void SoftBody_hitDetect(void)
{
}

void SoftBody_update(GameObject* obj)
{
    GameObject* object = obj;
    SoftBodySetup* setup = (SoftBodySetup*)object->anim.placementData;

    if (gSoftBodyPhaseDriver == NULL && setup->phaseDriverDisabled == 0)
    {
        gSoftBodyPhaseDriver = obj;
    }

    if (obj == gSoftBodyPhaseDriver)
    {
        gSoftBodySlowPhase = SOFTBODY_SLOW_PHASE_RATE * timeDelta + gSoftBodySlowPhase;
        while (gSoftBodySlowPhase > SOFTBODY_PHASE_WRAP)
        {
            gSoftBodySlowPhase -= SOFTBODY_PHASE_WRAP;
        }
        gSoftBodyFastPhase = SOFTBODY_FAST_PHASE_RATE * timeDelta + gSoftBodyFastPhase;
        while (gSoftBodyFastPhase > SOFTBODY_PHASE_WRAP)
        {
            gSoftBodyFastPhase -= SOFTBODY_PHASE_WRAP;
        }
    }

    switch (object->anim.seqId)
    {
    case SOFTBODY_MOVE_PHASE_A_FIRST:
    case SOFTBODY_MOVE_PHASE_A_FIRST + 1:
    case SOFTBODY_MOVE_PHASE_A_FIRST + 2:
        ObjAnim_SetCurrentMove((int)obj, 0, gSoftBodySlowPhase, 0);
        break;
    default:
        ObjAnim_SetCurrentMove((int)obj, 0, gSoftBodyFastPhase, 0);
        break;
    }
}

void SoftBody_init(GameObject* obj, SoftBodySetup* setup)
{
    GameObject* object = obj;
    SoftBodySetup* setupData = setup;

    object->anim.rotZ = (s16)(setupData->rotZ << SOFTBODY_ROTATION_SHIFT);
    object->anim.rotY = (s16)(setupData->rotY << SOFTBODY_ROTATION_SHIFT);
    object->anim.rotX = (s16)(setupData->rotX << SOFTBODY_ROTATION_SHIFT);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / SOFTBODY_SCALE_DIVISOR;
        if (!object->anim.rootMotionScale)
        {
            object->anim.rootMotionScale = 1.0f;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags |= SOFTBODY_OBJECT_FLAGS_INIT;
    ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
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
    gSoftBodyPhaseDriver = NULL;
    gSoftBodySlowPhase = 0.0f;
    gSoftBodyFastPhase = 0.0f;
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
