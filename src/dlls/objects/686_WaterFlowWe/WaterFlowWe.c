/*
 * WaterFlowWe (DLL 686) - water-flow weed: a foliage object that
 * sways to a water current.
 *
 * Each tick calcCurrentVector sums the influence of two source groups:
 * the foliage-current group (0x14) - only members whose currentFlags
 * have the ENABLED bit set contribute - and the object-current source
 * group (0x50). A source affects the weed only when it is within a
 * vertical band and inside its planar radius; its strength falls off
 * linearly with distance and is projected through sin/cos of the
 * source angle. The averaged current is low-pass filtered, clamped to
 * a maximum magnitude, scaled by timeDelta, and used to point the
 * weed (rotX) downstream.
 *
 * One weed instance (gWaterFlowPhaseDriver, claimed by the first non-disabled
 * phaseDriver) advances two shared wrapping phase accumulators
 * (gWaterFlowIdlePhase / gWaterFlowFlowPhase) that select the weed's idle vs. flowing
 * animation move via ObjAnim_SetCurrentMove.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_02AE_waterflowwe.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/objtype.h"
#include "main/vecmath.h"

f32 gWaterFlowIdlePhase;
f32 gWaterFlowFlowPhase;
GameObject* gWaterFlowPhaseDriver;

#define WATERFLOWWE_FOLIAGE_GROUP               0x14
#define WATERFLOWWE_OBJECT_CURRENT_GROUP        0x50
#define WATERFLOWWE_FOLIAGE_CURRENT_ENABLED     0x02
#define WATERFLOWWE_OBJECT_CURRENT_ANGLE_OFFSET 0x84d0
#define WATERFLOWWE_ZERO                        0.0f
#define WATERFLOWWE_BAND_MAX                    200.0f
#define WATERFLOWWE_BAND_MIN                    -200.0f
#define WATERFLOWWE_RADIUS_PER_CELL             1.5f
#define WATERFLOWWE_STRENGTH_SCALE              10.0f
#define WATERFLOWWE_PI                          3.1415927f
#define WATERFLOWWE_ANGLE_FULL_SCALE            32768.0f
#define WATERFLOWWE_FILTER_COEFF                0.05f
#define WATERFLOWWE_DECAY_COEFF                 0.99f
#define WATERFLOWWE_MAX_MAGNITUDE               0.85f
#define WATERFLOWWE_ONE                         1.0f
#define WATERFLOWWE_IDLE_PHASE_RATE             0.001f
#define WATERFLOWWE_FLOW_PHASE_RATE             0.005f
#define WATERFLOWWE_SCALE_DIVISOR               255.0f

void waterflowwe_calcCurrentVector(GameObject* obj, f32* vx, f32* vz)
{
    GameObject* object = obj;
    int hasCurrent;
    WaterFlowWeState* current = object->extra;
    int count;
    int i;
    GameObject* other;
    GameObject** objects;
    f32 currentX;
    f32 currentZ;
    f32 dx;
    f32 dz;
    f32 dy;
    f32 distance;
    f32 radius;
    f32 strength;
    f32 angle;

    currentX = currentZ = WATERFLOWWE_ZERO;
    strength = currentX;
    angle = currentX;
    objects = (GameObject**)objGetAllOfType(WATERFLOWWE_FOLIAGE_GROUP, &count);
    hasCurrent = 0;
    for (i = 0; i < count; i++)
    {
        other = objects[i];
        if ((((FoliageCurrentSetup*)other->anim.placementData)->currentFlags & WATERFLOWWE_FOLIAGE_CURRENT_ENABLED) !=
            0)
        {
            hasCurrent = 1;
            dy = other->anim.localPosY - object->anim.localPosY;
            if ((dy <= WATERFLOWWE_BAND_MAX) && (dy >= WATERFLOWWE_BAND_MIN))
            {
                dx = other->anim.localPosX - object->anim.localPosX;
                dz = other->anim.localPosZ - object->anim.localPosZ;
                distance = sqrtf(dx * dx + dz * dz);
                radius = WATERFLOWWE_RADIUS_PER_CELL *
                         (f32)(u32)((FoliageCurrentSetup*)other->anim.placementData)->currentRadius;
                if (distance < radius)
                {
                    strength = (radius - distance) / radius;
                    strength = strength * (WATERFLOWWE_STRENGTH_SCALE * other->anim.rootMotionScale);
                    currentX +=
                        strength * mathSinf((WATERFLOWWE_PI * other->anim.rotX) / WATERFLOWWE_ANGLE_FULL_SCALE);
                    currentZ +=
                        strength * mathCosf((WATERFLOWWE_PI * other->anim.rotX) / WATERFLOWWE_ANGLE_FULL_SCALE);
                }
            }
        }
    }

    objects = (GameObject**)objGetAllOfType(WATERFLOWWE_OBJECT_CURRENT_GROUP, &count);
    for (i = 0; i < count; i++)
    {
        f32 objectStrength;
        s16 currentAngle;

        other = objects[i];
        objectStrength =
            (f32)(u32)((ObjectCurrentSourceSetup*)other->anim.placementData)->strengthTenths /
            WATERFLOWWE_STRENGTH_SCALE;

        hasCurrent = 1;
        dy = other->anim.localPosY - object->anim.localPosY;
        if ((dy <= WATERFLOWWE_BAND_MAX) && (dy >= WATERFLOWWE_BAND_MIN))
        {
            dx = other->anim.localPosX - object->anim.localPosX;
            dz = other->anim.localPosZ - object->anim.localPosZ;
            currentAngle = (s16)(getAngle(dx, dz) + WATERFLOWWE_OBJECT_CURRENT_ANGLE_OFFSET);
            distance = sqrtf(dx * dx + dz * dz);
            radius = (f32)(s32)(((ObjectCurrentSourceSetup*)other->anim.placementData)->radiusCells << 3);
            if (distance < radius)
            {
                strength = (radius - distance) / radius;
                strength = strength * objectStrength;
                angle = (WATERFLOWWE_PI * currentAngle) / WATERFLOWWE_ANGLE_FULL_SCALE;
                currentX += strength * mathSinf(angle);
                currentZ += strength * mathCosf(angle);
            }
        }
    }

    if (hasCurrent != 0)
    {
        currentX = currentX / hasCurrent;
        currentZ = currentZ / hasCurrent;
        {
            f32 filterCoeff = WATERFLOWWE_FILTER_COEFF;
            current->currentX = current->currentX - filterCoeff * currentX;
            current->currentZ = current->currentZ - filterCoeff * currentZ;
        }
        current->currentX *= WATERFLOWWE_DECAY_COEFF;
        current->currentZ *= WATERFLOWWE_DECAY_COEFF;
        distance = sqrtf(current->currentX * current->currentX + current->currentZ * current->currentZ);
        if (distance > WATERFLOWWE_MAX_MAGNITUDE)
        {
            strength = WATERFLOWWE_MAX_MAGNITUDE / distance;
            current->currentX = current->currentX * strength;
            current->currentZ = current->currentZ * strength;
        }
        *vx = current->currentX * timeDelta;
        *vz = current->currentZ * timeDelta;
    }
    else
    {
        f32 zero = WATERFLOWWE_ZERO;
        *vx = zero;
        *vz = zero;
    }
}

int waterflowwe_getExtraSize(void)
{
    return sizeof(WaterFlowWeState);
}

int waterflowwe_getObjectTypeId(void)
{
    return 0;
}

void waterflowwe_free(GameObject* obj)
{
    if (obj == gWaterFlowPhaseDriver)
    {
        gWaterFlowPhaseDriver = 0;
    }
}

void waterflowwe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, WATERFLOWWE_ONE);
    }
}

void waterflowwe_hitDetect(void)
{
}

void waterflowwe_update(GameObject* obj)
{
    GameObject* object = obj;
    WaterFlowWeSetup* setup = (WaterFlowWeSetup*)object->anim.placementData;
    f32 vx, vz;

    waterflowwe_calcCurrentVector(obj, &vx, &vz);
    object->anim.rotX = (s16)(getAngle(vx, vz) + 0x4000);
    if (gWaterFlowPhaseDriver == NULL && setup->phaseDriverDisabled == 0)
    {
        gWaterFlowPhaseDriver = obj;
    }
    if (obj == gWaterFlowPhaseDriver)
    {
        f32 phase;

        phase = WATERFLOWWE_IDLE_PHASE_RATE * timeDelta + gWaterFlowIdlePhase;
        gWaterFlowIdlePhase = phase;
        while (phase > WATERFLOWWE_ONE)
        {
            phase -= WATERFLOWWE_ONE;
        }
        gWaterFlowIdlePhase = phase;
        phase = WATERFLOWWE_FLOW_PHASE_RATE * timeDelta + gWaterFlowFlowPhase;
        gWaterFlowFlowPhase = phase;
        while (phase > WATERFLOWWE_ONE)
        {
            phase -= WATERFLOWWE_ONE;
        }
        gWaterFlowFlowPhase = phase;
    }
    if (WATERFLOWWE_ZERO == vx && WATERFLOWWE_ZERO == vz)
    {
        ObjAnim_SetCurrentMove(obj, 1, gWaterFlowIdlePhase, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0, gWaterFlowIdlePhase, 0);
    }
}

void waterflowwe_init(GameObject* obj, WaterFlowWeSetup* setup)
{
    GameObject* object = obj;
    WaterFlowWeSetup* setupData = setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / WATERFLOWWE_SCALE_DIVISOR;
        if (!object->anim.rootMotionScale)
        {
            object->anim.rootMotionScale = WATERFLOWWE_ONE;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags = (u16)(object->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    ObjAnim_SetCurrentMove(obj, 0, WATERFLOWWE_ZERO, 0);
}

void waterflowwe_release(void)
{
}

void waterflowwe_initialise(void)
{
    gWaterFlowPhaseDriver = 0;
    gWaterFlowIdlePhase = WATERFLOWWE_ZERO;
    gWaterFlowFlowPhase = WATERFLOWWE_ZERO;
}

ObjectDescriptor gWaterFlowWeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)waterflowwe_initialise,
    (ObjectDescriptorCallback)waterflowwe_release,
    0,
    (ObjectDescriptorCallback)waterflowwe_init,
    (ObjectDescriptorCallback)waterflowwe_update,
    (ObjectDescriptorCallback)waterflowwe_hitDetect,
    (ObjectDescriptorCallback)waterflowwe_render,
    (ObjectDescriptorCallback)waterflowwe_free,
    (ObjectDescriptorCallback)waterflowwe_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)waterflowwe_getExtraSize,
};
