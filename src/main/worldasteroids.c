#include "main/worldasteroids.h"
#include "main/fcos16_approx_api.h"
#include "main/fsin16_approx_api.h"
#include "main/object_render.h"
#include "main/object_api.h"
#include "main/vecmath.h"

extern f32 gWorldAsteroidsRenderScale;
extern f32 gWorldAsteroidsZero;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 gWorldAsteroidsOrbitRadiusVariation;
extern f32 gWorldAsteroidsOrbitRadiusBase;

typedef f32 (*WorldAsteroidsTrigFn)(u16 angle);

static inline f32 worldasteroids_s32AsFloat(s32 value)
{
    return (f32)(s32)value;
}

int worldasteroids_getExtraSize(void)
{
    return sizeof(WorldAsteroidsState);
}

int worldasteroids_getObjectTypeId(void)
{
    return 0;
}

void worldasteroids_free(void)
{
    return;
}

void worldasteroids_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gWorldAsteroidsRenderScale);
    }
}

void worldasteroids_hitDetect(void)
{
    return;
}

void worldasteroids_update(GameObject* obj)
{
    GameObject* anchor;
    WorldAsteroidsState* state;
    f32 orbitScale;
    f32 orbitSin;
    f32 orbitCos;
    f32 radius;
    f32 orbitProduct;

    state = (WorldAsteroidsState*)obj->extra;
    anchor = ObjList_FindObjectById(WORLD_ASTEROIDS_CENTER_OBJECT_ID);
    obj->anim.rotX += state->rotStepX;
    obj->anim.rotY += state->rotStepY;
    obj->anim.rotZ += state->rotStepZ;
    state->orbitAngle += WORLD_ASTEROIDS_ORBIT_STEP_SCALE / state->orbitRadius;
    orbitCos = fcos16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitSin = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitScale = radius * orbitSin;
    obj->anim.localPosX = orbitScale * orbitCos + anchor->anim.localPosX;
    orbitSin = fsin16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitScale = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitProduct = radius * orbitScale;
    obj->anim.localPosY =
        orbitProduct * orbitSin + (anchor->anim.localPosY + worldasteroids_s32AsFloat(state->heightOffset));
    orbitCos = fcos16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    obj->anim.localPosZ = radius * orbitCos + anchor->anim.localPosZ;
    return;
}

void worldasteroids_init(GameObject* obj)
{
    int baseAngle;
    s16 randomValue;
    int radiusSeed;
    WorldAsteroidsState* state;
    f32 orbitShape;

    state = (WorldAsteroidsState*)obj->extra;
    baseAngle = randomGetRange(-0x7fff, 0x7fff);
    orbitShape = ((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    if (orbitShape < gWorldAsteroidsZero)
    {
        orbitShape = -((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    }
    else
    {
        orbitShape = ((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    }
    randomGetRange(0, (int)(lbl_803E65E8 * orbitShape + lbl_803E65E4));
    orbitShape = ((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    if (orbitShape < gWorldAsteroidsZero)
    {
        orbitShape = -((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    }
    else
    {
        orbitShape = ((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle);
    }
    radiusSeed = (int)(gWorldAsteroidsOrbitRadiusVariation * orbitShape);
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepZ = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepY = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepX = randomValue;
    randomValue = randomGetRange(-0x7fff, 0x7fff);
    state->orbitAngle = randomValue;
    state->orbitRadius =
        worldasteroids_s32AsFloat(radiusSeed) * ((WorldAsteroidsTrigFn)fsin16Approx)(baseAngle) +
        gWorldAsteroidsOrbitRadiusBase;
    state->heightOffset =
        worldasteroids_s32AsFloat(radiusSeed) * ((WorldAsteroidsTrigFn)fcos16Approx)(baseAngle);
    return;
}

void worldasteroids_release(void)
{
    return;
}

void worldasteroids_initialise(void)
{
    return;
}

ObjectDescriptor gWorldAsteroidsObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)worldasteroids_initialise,
    (ObjectDescriptorCallback)worldasteroids_release,
    0,
    (ObjectDescriptorCallback)worldasteroids_init,
    (ObjectDescriptorCallback)worldasteroids_update,
    (ObjectDescriptorCallback)worldasteroids_hitDetect,
    (ObjectDescriptorCallback)worldasteroids_render,
    (ObjectDescriptorCallback)worldasteroids_free,
    (ObjectDescriptorCallback)worldasteroids_getObjectTypeId,
    worldasteroids_getExtraSize,
};
