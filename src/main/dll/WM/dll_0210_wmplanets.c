/*
 * wmplanets (DLL 0x210) - the orbiting planet models above Krazoa
 * Palace (map 'warlock' = Dinosaur Planet's Warlock Mountain, hence
 * the WM dll prefix). Serves two retail object defs: 899 'WM_Planets'
 * (romlist type 0x561) and 898 'WM_PlanetsS' (type 0x569); no romlist
 * on any of the 124 retail maps places either - instances are spawned
 * at runtime. (The related defs 923 'WM_Planet'/924 'WM_PlanetMo' use
 * DLL 0x12A, not this one.)
 * Each planet circles its spawn point: update spins a (0, 0, radius)
 * arm by the orbit yaw (random per-frame step from init), tilts it by
 * a fixed random pitch, re-bases the model on the result, and turns
 * the model's own yaw at its own random rate. init derives the model
 * scale from the placement scale byte, the orbit radius from the
 * placement radius byte (* 16, negated), and selects the model bank.
 */
#include "main/object_render.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/dll/WM/dll_0210_wmplanets.h"
#include "main/object_descriptor.h"

#pragma force_active on
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5F98 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5F9C = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E5FA0 = 0.1f;
#pragma explicit_zero_data off
#pragma force_active reset

__declspec(section ".rodata") u32 lbl_802C2500[4] = {0, 0, 0, 0};

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
        objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, lbl_803E5F98); /* 1.0f */
    }
}

void WM_Planets_hitDetect(void)
{
}

void WM_Planets_update(GameObject* obj)
{
    WmPlanetsState* state;
    WmPlanetsVector vec;
    WmPlanetsRotationWork rotate;

    state = obj->extra;
    /* whole-struct copy of the zero vector (#31: paired lwz/stw, not
       three lfs/stfs) */
    {
        typedef struct Vec3Words
        {
            int w[3];
        } Vec3Words;
        *(Vec3Words*)&vec.word[0] = *(Vec3Words*)&lbl_802C2500[0];
    }
    vec.f[2] = state->orbitRadius;

    state->orbitYaw += state->orbitYawStep;

    rotate.zeroX = lbl_803E5F9C; /* 0.0f */
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98; /* 1.0f */
    rotate.roll = 0;
    rotate.pitch = 0;
    rotate.yaw = state->orbitYaw;
    vecRotateZXY(&rotate.yaw, vec.f);

    rotate.zeroX = lbl_803E5F9C;
    rotate.zeroY = lbl_803E5F9C;
    rotate.zeroZ = lbl_803E5F9C;
    rotate.scale = lbl_803E5F98;
    rotate.roll = 0;
    rotate.pitch = state->orbitPitch;
    rotate.yaw = 0;
    vecRotateZXY(&rotate.yaw, vec.f);

    obj->anim.localPosX = vec.f[0] + state->baseX;
    obj->anim.localPosY = vec.f[1] + state->baseY;
    obj->anim.localPosZ = vec.f[2] + state->baseZ;
    obj->anim.rotX = (s16)(obj->anim.rotX + state->yawStep * (s32)timeDelta);
}

void WM_Planets_init(GameObject* obj, WmPlanetsMapData* mapData)
{
    WmPlanetsState* inner = obj->extra;
    f32 a = lbl_803E5FA0 * obj->anim.modelInstance->rootMotionScaleBase; /* 0.1f * */
    obj->anim.rootMotionScale = a * (lbl_803E5F98 + (f32)(s32)mapData->scaleByte);
    if (*(s16*)mapData != 0)
    {
        inner->orbitRadius = -(f32)(s32)(mapData->radiusByte << 4);
    }
    else
    {
        inner->orbitRadius = lbl_803E5F9C; /* 0.0f */
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
