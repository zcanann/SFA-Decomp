/*
 * WM_Planets (DLL 0x0210) - orbiting planet models.
 *
 * Each planet circles its spawn point while rotating at independently
 * randomized rates.
 */
#include "dlls/object_descriptor.h"
#include "main/dll/WM/dll_0210_wmplanets.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"

const u32 gWmPlanetsZeroVecTemplate[4] = {0, 0, 0, 0};

int WM_Planets_getExtraSize(void)
{
    return sizeof(WmPlanetsState);
}

int WM_Planets_getObjectTypeId(void)
{
    return 0x0;
}

void WM_Planets_free(void)
{
}

void WM_Planets_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    if (vis != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void WM_Planets_hitDetect(void)
{
}

void WM_Planets_update(GameObject* obj)
{
    WmPlanetsState* state;
    WmPlanetsVector vec;
    MatrixTransform rotate;

    state = obj->extra;
    /* Initialize from the zero-vector template. */
    {
        typedef struct Vec3Words
        {
            int w[3];
        } Vec3Words;
        *(Vec3Words*)&vec.word[0] = *(Vec3Words*)&gWmPlanetsZeroVecTemplate[0];
    }
    vec.f[2] = state->orbitRadius;

    state->orbitYaw += state->orbitYawStep;

    rotate.x = 0.0f;
    rotate.y = 0.0f;
    rotate.z = 0.0f;
    rotate.scale = 1.0f;
    rotate.rotZ = 0;
    rotate.rotY = 0;
    rotate.rotX = state->orbitYaw;
    vecRotateZXY(&rotate.rotX, vec.f);

    rotate.x = 0.0f;
    rotate.y = 0.0f;
    rotate.z = 0.0f;
    rotate.scale = 1.0f;
    rotate.rotZ = 0;
    rotate.rotY = state->orbitPitch;
    rotate.rotX = 0;
    vecRotateZXY(&rotate.rotX, vec.f);

    obj->anim.localPosX = vec.f[0] + state->baseX;
    obj->anim.localPosY = vec.f[1] + state->baseY;
    obj->anim.localPosZ = vec.f[2] + state->baseZ;
    obj->anim.rotX = (s16)(obj->anim.rotX + state->yawStep * (s32)timeDelta);
}

void WM_Planets_init(GameObject* obj, WmPlanetsMapData* mapData)
{
    WmPlanetsState* inner = obj->extra;
    f32 a = 0.1f * obj->anim.modelInstance->rootMotionScaleBase;
    obj->anim.rootMotionScale = a * (1.0f + (f32)(s32)mapData->scaleByte);
    if (mapData->base.objectId != 0)
    {
        inner->orbitRadius = -(f32)(s32)(mapData->radiusByte << 4);
    }
    else
    {
        inner->orbitRadius = 0.0f;
    }
    inner->orbitYawStep = randomGetRange(0x64, 0xc8);
    inner->yawStep = randomGetRange(0xc8, 0x190);
    inner->orbitYaw = 0;
    inner->orbitPitch = randomGetRange(0, 0x960);
    inner->baseX = obj->anim.localPosX;
    inner->baseY = obj->anim.localPosY;
    inner->baseZ = obj->anim.localPosZ;
    Obj_SetActiveModelIndex(obj, mapData->modelIndex);
    obj->anim.localPosZ = mapData->base.posZ + inner->orbitRadius;
}

void WM_Planets_release(void)
{
}

void WM_Planets_initialise(void)
{
}

ObjectDescriptor gWM_PlanetsObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)WM_Planets_initialise,
    (ObjectDescriptorCallback)WM_Planets_release,
    0,
    (ObjectDescriptorCallback)WM_Planets_init,
    (ObjectDescriptorCallback)WM_Planets_update,
    (ObjectDescriptorCallback)WM_Planets_hitDetect,
    (ObjectDescriptorCallback)WM_Planets_render,
    (ObjectDescriptorCallback)WM_Planets_free,
    (ObjectDescriptorCallback)WM_Planets_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)WM_Planets_getExtraSize,
};
