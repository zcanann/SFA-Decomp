/*
 * WORLDAstero (DLL 0x1D4) - orbiting world-map asteroids.
 *
 * Each asteroid spins independently while revolving around the world-map
 * center object on a tilted orbit.
 */
#include "dlls/objects/468_WORLDAstero.h"

#include "main/fcos16_approx_api.h"
#include "main/fsin16_approx_api.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define WORLD_ASTEROIDS_CENTER_OBJECT_ID   0x42FE7
#define WORLD_ASTEROIDS_ORBIT_TILT_ANGLE   3000
#define WORLD_ASTEROIDS_ORBIT_STEP_SCALE   0x9C4
#define WORLD_ASTEROIDS_ROTATION_SPEED_MIN -300
#define WORLD_ASTEROIDS_ROTATION_SPEED_MAX 300

extern f32 gWorldAsteroidsRenderScale;
extern f32 gWorldAsteroidsOrbitRadiusVariation;
extern f32 gWorldAsteroidsOrbitRadiusBase;

static inline f32 worldasteroids_s32AsFloat(s32 value) {
    return (f32)value;
}

int worldasteroids_getExtraSize(void) {
    return sizeof(WorldAsteroidsState);
}

int worldasteroids_getObjectTypeId(void) {
    return 0;
}

void worldasteroids_free(void) {
}

void worldasteroids_render(GameObject* obj, u32 renderArg2, u32 renderArg3, u32 renderArg4, u32 renderArg5,
                           s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, gWorldAsteroidsRenderScale);
    }
}

void worldasteroids_hitDetect(void) {
}

void worldasteroids_update(GameObject* obj) {
    GameObject* centerObject;
    WorldAsteroidsState* state;
    f32 orbitScale;
    f32 orbitSin;
    f32 orbitCos;
    f32 radius;
    f32 orbitProduct;

    state = (WorldAsteroidsState*)obj->extra;
    centerObject = ObjList_FindObjectById(WORLD_ASTEROIDS_CENTER_OBJECT_ID);
    obj->anim.rotX += state->rotStepX;
    obj->anim.rotY += state->rotStepY;
    obj->anim.rotZ += state->rotStepZ;
    state->orbitAngle += WORLD_ASTEROIDS_ORBIT_STEP_SCALE / state->orbitRadius;
    orbitCos = fcos16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitSin = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitScale = radius * orbitSin;
    obj->anim.localPosX = orbitScale * orbitCos + centerObject->anim.localPosX;
    orbitSin = fsin16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
    orbitScale = fsin16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    orbitProduct = radius * orbitScale;
    obj->anim.localPosY =
        orbitProduct * orbitSin + (centerObject->anim.localPosY + worldasteroids_s32AsFloat(state->heightOffset));
    orbitCos = fcos16Approx((u16)state->orbitAngle);
    radius = worldasteroids_s32AsFloat(state->orbitRadius);
    obj->anim.localPosZ = radius * orbitCos + centerObject->anim.localPosZ;
}

void worldasteroids_init(GameObject* obj) {
    int baseAngle;
    s16 randomValue;
    int radiusVariation;
    WorldAsteroidsState* state;
    f32 orbitShape;

    state = (WorldAsteroidsState*)obj->extra;
    baseAngle = randomGetRange(-0x7fff, 0x7fff);
    orbitShape = fsin16Approx(baseAngle);
    if (orbitShape < 0.0f) {
        orbitShape = -fsin16Approx(baseAngle);
    } else {
        orbitShape = fsin16Approx(baseAngle);
    }
    randomGetRange(0, (int)(33.0f * orbitShape + 7.0f));
    orbitShape = fsin16Approx(baseAngle);
    if (orbitShape < 0.0f) {
        orbitShape = -fsin16Approx(baseAngle);
    } else {
        orbitShape = fsin16Approx(baseAngle);
    }
    radiusVariation = (int)(gWorldAsteroidsOrbitRadiusVariation * orbitShape);
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepZ = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepY = randomValue;
    randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN, WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
    state->rotStepX = randomValue;
    randomValue = randomGetRange(-0x7fff, 0x7fff);
    state->orbitAngle = randomValue;
    state->orbitRadius =
        worldasteroids_s32AsFloat(radiusVariation) * fsin16Approx(baseAngle) + gWorldAsteroidsOrbitRadiusBase;
    state->heightOffset = worldasteroids_s32AsFloat(radiusVariation) * fcos16Approx(baseAngle);
}

void worldasteroids_release(void) {
}

void worldasteroids_initialise(void) {
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
