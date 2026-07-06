/*
 * waterflowwe (DLL 0x2AE) - water-flow weed: a foliage object that
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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define WATERFLOWWE_FOLIAGE_GROUP 0x14
#define WATERFLOWWE_OBJECT_CURRENT_GROUP 0x50
#define WATERFLOWWE_OBJECT_FLAGS_INIT 0x2000
#define WATERFLOWWE_FOLIAGE_CURRENT_ENABLED 0x02
#define WATERFLOWWE_OBJECT_CURRENT_ANGLE_OFFSET 0x84d0

typedef struct WaterFlowWeState
{
    f32 currentX;
    f32 currentZ;
} WaterFlowWeState;

typedef struct WaterFlowWeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[3];
    u8 phaseDriverDisabled;
} WaterFlowWeSetup;

typedef struct FoliageCurrentSetup
{
    ObjPlacement base;
    u8 pad18;
    u8 currentRadius;
    u8 currentFlags;
} FoliageCurrentSetup;

typedef struct ObjectCurrentSourceSetup
{
    ObjPlacement base;
    u8 pad18[0x29 - 0x18];
    u8 radiusCells;
    u8 pad2A[0x32 - 0x2A];
    u8 strengthTenths;
} ObjectCurrentSourceSetup;

STATIC_ASSERT(sizeof(WaterFlowWeState) == 0x8);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(WaterFlowWeSetup, phaseDriverDisabled) == 0x1f);
STATIC_ASSERT(sizeof(WaterFlowWeSetup) == 0x20);
STATIC_ASSERT(offsetof(FoliageCurrentSetup, currentRadius) == 0x19);
STATIC_ASSERT(offsetof(FoliageCurrentSetup, currentFlags) == 0x1a);
STATIC_ASSERT(offsetof(ObjectCurrentSourceSetup, radiusCells) == 0x29);
STATIC_ASSERT(offsetof(ObjectCurrentSourceSetup, strengthTenths) == 0x32);

extern const f32 gWaterFlowBandMax;
extern const f32 gWaterFlowBandMin;
extern const f32 gWaterFlowRadiusPerCell;
extern const f32 gWaterFlowStrengthScale;
extern const f32 gWaterFlowPi;
extern const f32 gWaterFlowAngleFullScale;
extern const f32 gWaterFlowFilterCoeff;
extern const f32 gWaterFlowDecayCoeff;
extern const f32 gWaterFlowMaxMagnitude;

void waterflowwe_calcCurrentVector(int obj, f32* vx, f32* vz)
{
    GameObject* object = (GameObject*)obj;
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

    currentX = currentZ = lbl_803E72B0;
    objects = (GameObject**)ObjGroup_GetObjects(WATERFLOWWE_FOLIAGE_GROUP, &count);
    hasCurrent = 0;
    for (i = 0; i < count; i++)
    {
        other = objects[i];
        if ((((FoliageCurrentSetup*)other->anim.placementData)->currentFlags & WATERFLOWWE_FOLIAGE_CURRENT_ENABLED) !=
            0)
        {
            hasCurrent = 1;
            dy = other->anim.localPosY - object->anim.localPosY;
            if ((dy <= gWaterFlowBandMax) && (dy >= gWaterFlowBandMin))
            {
                dx = other->anim.localPosX - object->anim.localPosX;
                dz = other->anim.localPosZ - object->anim.localPosZ;
                distance = sqrtf(dx * dx + dz * dz);
                radius = gWaterFlowRadiusPerCell * (f32)(u32)((FoliageCurrentSetup*)other->anim.placementData)->currentRadius;
                if (distance < radius)
                {
                    strength = (radius - distance) / radius;
                    strength = strength * (gWaterFlowStrengthScale * other->anim.rootMotionScale);
                    currentX += strength * mathSinf((gWaterFlowPi * other->anim.rotX) / gWaterFlowAngleFullScale);
                    currentZ += strength * mathCosf((gWaterFlowPi * other->anim.rotX) / gWaterFlowAngleFullScale);
                }
            }
        }
    }

    objects = (GameObject**)ObjGroup_GetObjects(WATERFLOWWE_OBJECT_CURRENT_GROUP, &count);
    for (i = 0; i < count; i++)
    {
        f32 objectStrength;
        s16 currentAngle;

        other = objects[i];
        objectStrength = (f32)(u32)((ObjectCurrentSourceSetup*)other->anim.placementData)->strengthTenths / gWaterFlowStrengthScale;

        hasCurrent = 1;
        dy = other->anim.localPosY - object->anim.localPosY;
        if ((dy <= gWaterFlowBandMax) && (dy >= gWaterFlowBandMin))
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
                angle = (gWaterFlowPi * currentAngle) / gWaterFlowAngleFullScale;
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
            f32 k = gWaterFlowFilterCoeff;
            current->currentX = current->currentX - k * currentX;
            current->currentZ = current->currentZ - k * currentZ;
        }
        current->currentX = current->currentX * gWaterFlowDecayCoeff;
        current->currentZ = current->currentZ * gWaterFlowDecayCoeff;
        distance = sqrtf(current->currentX * current->currentX + current->currentZ * current->currentZ);
        if (distance > gWaterFlowMaxMagnitude)
        {
            strength = gWaterFlowMaxMagnitude / distance;
            current->currentX = current->currentX * strength;
            current->currentZ = current->currentZ * strength;
        }
        *vx = current->currentX * timeDelta;
        *vz = current->currentZ * timeDelta;
    }
    else
    {
        f32 z = lbl_803E72B0;
        *vx = z;
        *vz = z;
    }
}

int waterflowwe_getExtraSize(void) { return sizeof(WaterFlowWeState); }

int waterflowwe_getObjectTypeId(void) { return 0; }

void waterflowwe_init(int obj, u8* setup)
{
    GameObject* object = (GameObject*)obj;
    WaterFlowWeSetup* setupData = (WaterFlowWeSetup*)setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0)
    {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / gWaterFlowScaleDivisor;
        if (object->anim.rootMotionScale == lbl_803E72B0)
        {
            object->anim.rootMotionScale = lbl_803E72E8;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags = (u16)(object->objectFlags | WATERFLOWWE_OBJECT_FLAGS_INIT);
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72B0, 0);
}

void waterflowwe_free(int obj)
{
    if ((u32)obj == gWaterFlowPhaseDriver)
    {
        gWaterFlowPhaseDriver = 0;
    }
}

void waterflowwe_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E72E8);
    }
}

void waterflowwe_hitDetect(void)
{
}

void waterflowwe_update(int obj)
{
    GameObject* object = (GameObject*)obj;
    WaterFlowWeSetup* setup = (WaterFlowWeSetup*)object->anim.placementData;
    f32 vx, vz;

    waterflowwe_calcCurrentVector(obj, &vx, &vz);
    object->anim.rotX = (s16)(getAngle(vx, vz) + 0x4000);
    if ((u32)gWaterFlowPhaseDriver == 0 && setup->phaseDriverDisabled == 0)
    {
        gWaterFlowPhaseDriver = obj;
    }
    if ((u32)obj == gWaterFlowPhaseDriver)
    {
        f32 a;

        a = gWaterFlowIdlePhaseRate * timeDelta + gWaterFlowIdlePhase;
        gWaterFlowIdlePhase = a;
        while (a > *(f32*)&lbl_803E72E8)
        {
            a -= *(f32*)&lbl_803E72E8;
        }
        gWaterFlowIdlePhase = a;
        a = gWaterFlowFlowPhaseRate * timeDelta + gWaterFlowFlowPhase;
        gWaterFlowFlowPhase = a;
        while (a > *(f32*)&lbl_803E72E8)
        {
            a -= *(f32*)&lbl_803E72E8;
        }
        gWaterFlowFlowPhase = a;
    }
    if (lbl_803E72B0 == vx && lbl_803E72B0 == vz)
    {
        ObjAnim_SetCurrentMove(obj, 1, gWaterFlowIdlePhase, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0, gWaterFlowIdlePhase, 0);
    }
}

void waterflowwe_release(void)
{
}

void waterflowwe_initialise(void)
{
    gWaterFlowPhaseDriver = 0;
    gWaterFlowIdlePhase = lbl_803E72B0;
    gWaterFlowFlowPhase = lbl_803E72B0;
}
