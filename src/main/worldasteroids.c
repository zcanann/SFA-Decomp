#include "main/worldasteroids.h"
#include "main/engine_shared.h"

extern WorldAsteroidsObject* ObjList_FindObjectById(int objectId);
extern void objRenderFn_8003b8f4(double scale);
extern f32 fsin16Approx(u16 angle);
extern f32 fcos16Approx(u16 angle);
extern f32 lbl_803E65D0;
extern f32 lbl_803E65E0;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 lbl_803E65EC;
extern f32 lbl_803E65F0;

static inline f32 worldasteroids_s32AsFloat(s32 value)
{
    return (f32)(s32)
    value;
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

void worldasteroids_render(u32 obj, u32 p2, u32 p3,
                           u32 p4, u32 p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E65D0);
    }
}

void worldasteroids_hitDetect(void)
{
    return;
}

void worldasteroids_update(WorldAsteroidsObject* obj)
{
    WorldAsteroidsObject* anchor;
    WorldAsteroidsState* state;
    f32 orbitScale;
    f32 orbitSin;
    f32 orbitCos;
    f32 radius;
    f32 orbitProduct;

    state = obj->state;
    anchor = ObjList_FindObjectById(WORLD_ASTEROIDS_CENTER_OBJECT_ID);
    obj->rotX += state->rotStepX;
    obj->rotY += state->rotStepY;
    obj->rotZ += state->rotStepZ;
    state->orbitAngle += WORLD_ASTEROIDS_ORBIT_STEP_SCALE / state->orbitRadius;
    orbitCos = fcos16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitSin = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitScale = radius * orbitSin;
    obj->posX = orbitScale * orbitCos + anchor->posX;
    orbitSin = fsin16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitScale = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitProduct = radius * orbitScale;
    obj->posY = orbitProduct * orbitSin + (anchor->posY +
        worldasteroids_s32AsFloat(state->heightOffset));
    orbitCos = fcos16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    obj->posZ = radius * orbitCos + anchor->posZ;
    return;
}

void worldasteroids_init(WorldAsteroidsObject* obj)
{
    int baseAngle;
    s16 randomValue;
    int radiusSeed;
    WorldAsteroidsState* state;
    f32 orbitShape;

    state = obj->state;
    baseAngle = randomGetRange(-0x7fff, 0x7fff);
    orbitShape = fsin16Approx(baseAngle);
    if (orbitShape < lbl_803E65E0)
    {
        orbitShape = -fsin16Approx(baseAngle);
    }
    else
    {
        orbitShape = fsin16Approx(baseAngle);
    }
    randomGetRange(0, (int)(lbl_803E65E8 * orbitShape + lbl_803E65E4));
    orbitShape = fsin16Approx(baseAngle);
    if (orbitShape < lbl_803E65E0)
    {
        orbitShape = -fsin16Approx(baseAngle);
    }
    else
    {
        orbitShape = fsin16Approx(baseAngle);
    }
    radiusSeed = (int)(lbl_803E65EC * orbitShape);
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepZ = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepY = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepX = randomValue;
    randomValue = randomGetRange(-0x7fff, 0x7fff);
    state->orbitAngle = randomValue;
    state->orbitRadius =
        worldasteroids_s32AsFloat(radiusSeed) * fsin16Approx(baseAngle) + lbl_803E65F0;
    state->heightOffset =
        worldasteroids_s32AsFloat(radiusSeed) * fcos16Approx(baseAngle);
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
