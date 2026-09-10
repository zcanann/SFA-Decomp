/*
 * WaterFlowWe (DLL 686) responds to CCRiverFlow current sources and active
 * Whirlpool baddies. Current contributions are summed: hasCurrent is a
 * presence flag, so the retained division is always by one. The persistent
 * current state is damped, clamped and scaled by timeDelta to choose a heading.
 *
 * One eligible instance advances the shared animation phases. Both animation
 * branches use gWaterFlowIdlePhase; gWaterFlowFlowPhase is advanced and reset
 * but otherwise unused.
 */
#include "dlls/objects/686_WaterFlowWe.h"
#include "dlls/objects/201_Baddie.h"
#include "dlls/objects/372_CCriverflow.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/vecmath.h"

f32 gWaterFlowIdlePhase;
f32 gWaterFlowFlowPhase;
GameObject* gWaterFlowPhaseDriver;

#define WATERFLOWWE_WHIRLPOOL_ANGLE_OFFSET 0x84d0
#define WATERFLOWWE_ZERO                   0.0f
#define WATERFLOWWE_BAND_MAX               200.0f
#define WATERFLOWWE_BAND_MIN               -200.0f
#define WATERFLOWWE_RADIUS_PER_CELL        1.5f
#define WATERFLOWWE_STRENGTH_SCALE         10.0f
#define WATERFLOWWE_PI                     3.1415927f
#define WATERFLOWWE_ANGLE_FULL_SCALE       32768.0f
#define WATERFLOWWE_FILTER_COEFF           0.05f
#define WATERFLOWWE_DECAY_COEFF            0.99f
#define WATERFLOWWE_MAX_MAGNITUDE          0.85f
#define WATERFLOWWE_ONE                    1.0f
#define WATERFLOWWE_IDLE_PHASE_RATE        0.001f
#define WATERFLOWWE_FLOW_PHASE_RATE        0.005f
#define WATERFLOWWE_SCALE_DIVISOR          255.0f

void waterflowwe_calcCurrentVector(GameObject* obj, f32* vx, f32* vz) {
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
    objects = (GameObject**)objGetAllOfType(CC_RIVER_FLOW_OBJECT_GROUP, &count);
    hasCurrent = 0;
    for (i = 0; i < count; i++) {
        other = objects[i];
        if ((((CCRiverFlowPlacement*)other->anim.placementData)->currentFlags &
             CC_RIVER_FLOW_FLAG_PLAYER_AND_WATERFLOWWE) != 0) {
            hasCurrent = 1;
            dy = other->anim.localPosY - object->anim.localPosY;
            if ((dy <= WATERFLOWWE_BAND_MAX) && (dy >= WATERFLOWWE_BAND_MIN)) {
                dx = other->anim.localPosX - object->anim.localPosX;
                dz = other->anim.localPosZ - object->anim.localPosZ;
                distance = sqrtf(dx * dx + dz * dz);
                radius = WATERFLOWWE_RADIUS_PER_CELL *
                         (f32)(u32)((CCRiverFlowPlacement*)other->anim.placementData)->currentRadius;
                if (distance < radius) {
                    strength = (radius - distance) / radius;
                    strength *= (WATERFLOWWE_STRENGTH_SCALE * other->anim.rootMotionScale);
                    currentX += strength * mathSinf((WATERFLOWWE_PI * other->anim.rotX) / WATERFLOWWE_ANGLE_FULL_SCALE);
                    currentZ += strength * mathCosf((WATERFLOWWE_PI * other->anim.rotX) / WATERFLOWWE_ANGLE_FULL_SCALE);
                }
            }
        }
    }

    objects = (GameObject**)objGetAllOfType(BADDIE_WHIRLPOOL_OBJECT_GROUP, &count);
    for (i = 0; i < count; i++) {
        f32 objectStrength;
        s16 currentAngle;

        other = objects[i];
        objectStrength = (f32)(u32)((EnemyPlacement*)other->anim.placementData)->whirlpoolStrengthTenths /
                         WATERFLOWWE_STRENGTH_SCALE;

        hasCurrent = 1;
        dy = other->anim.localPosY - object->anim.localPosY;
        if ((dy <= WATERFLOWWE_BAND_MAX) && (dy >= WATERFLOWWE_BAND_MIN)) {
            dx = other->anim.localPosX - object->anim.localPosX;
            dz = other->anim.localPosZ - object->anim.localPosZ;
            currentAngle = (s16)(getAngle(dx, dz) + WATERFLOWWE_WHIRLPOOL_ANGLE_OFFSET);
            distance = sqrtf(dx * dx + dz * dz);
            radius = (f32)(s32)(((EnemyPlacement*)other->anim.placementData)->whirlpoolRadius << 3);
            if (distance < radius) {
                strength = (radius - distance) / radius;
                strength *= objectStrength;
                angle = (WATERFLOWWE_PI * currentAngle) / WATERFLOWWE_ANGLE_FULL_SCALE;
                currentX += strength * mathSinf(angle);
                currentZ += strength * mathCosf(angle);
            }
        }
    }

    if (hasCurrent != 0) {
        currentX /= hasCurrent;
        currentZ /= hasCurrent;
        {
            f32 filterCoeff = WATERFLOWWE_FILTER_COEFF;
            current->currentX = current->currentX - filterCoeff * currentX;
            current->currentZ = current->currentZ - filterCoeff * currentZ;
        }
        current->currentX *= WATERFLOWWE_DECAY_COEFF;
        current->currentZ *= WATERFLOWWE_DECAY_COEFF;
        distance = sqrtf(current->currentX * current->currentX + current->currentZ * current->currentZ);
        if (distance > WATERFLOWWE_MAX_MAGNITUDE) {
            strength = WATERFLOWWE_MAX_MAGNITUDE / distance;
            current->currentX *= strength;
            current->currentZ *= strength;
        }
        *vx = current->currentX * timeDelta;
        *vz = current->currentZ * timeDelta;
    } else {
        f32 zero = WATERFLOWWE_ZERO;
        *vx = zero;
        *vz = zero;
    }
}

int waterflowwe_getExtraSize(void) {
    return sizeof(WaterFlowWeState);
}

int waterflowwe_getObjectTypeId(void) {
    return 0;
}

void waterflowwe_free(GameObject* obj) {
    if (obj == gWaterFlowPhaseDriver) {
        gWaterFlowPhaseDriver = 0;
    }
}

void waterflowwe_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, WATERFLOWWE_ONE);
    }
}

void waterflowwe_hitDetect(void) {
}

void waterflowwe_update(GameObject* obj) {
    GameObject* object = obj;
    WaterFlowWePlacementPrefix* setup = (WaterFlowWePlacementPrefix*)object->anim.placementData;
    f32 vx, vz;

    waterflowwe_calcCurrentVector(obj, &vx, &vz);
    object->anim.rotX = (s16)(getAngle(vx, vz) + 0x4000);
    if (gWaterFlowPhaseDriver == NULL && setup->phaseDriverDisabled == 0) {
        gWaterFlowPhaseDriver = obj;
    }
    if (obj == gWaterFlowPhaseDriver) {
        f32 phase;

        phase = WATERFLOWWE_IDLE_PHASE_RATE * timeDelta + gWaterFlowIdlePhase;
        gWaterFlowIdlePhase = phase;
        while (phase > WATERFLOWWE_ONE) {
            phase -= WATERFLOWWE_ONE;
        }
        gWaterFlowIdlePhase = phase;
        phase = WATERFLOWWE_FLOW_PHASE_RATE * timeDelta + gWaterFlowFlowPhase;
        gWaterFlowFlowPhase = phase;
        while (phase > WATERFLOWWE_ONE) {
            phase -= WATERFLOWWE_ONE;
        }
        gWaterFlowFlowPhase = phase;
    }
    if (WATERFLOWWE_ZERO == vx && WATERFLOWWE_ZERO == vz) {
        ObjAnim_SetCurrentMove(obj, 1, gWaterFlowIdlePhase, 0);
    } else {
        ObjAnim_SetCurrentMove(obj, 0, gWaterFlowIdlePhase, 0);
    }
}

void waterflowwe_init(GameObject* obj, WaterFlowWePlacementPrefix* setup) {
    GameObject* object = obj;
    WaterFlowWePlacementPrefix* setupData = setup;

    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    if (setupData->scale != 0) {
        object->anim.rootMotionScale = (f32)(u32)setupData->scale / WATERFLOWWE_SCALE_DIVISOR;
        if (!object->anim.rootMotionScale) {
            object->anim.rootMotionScale = WATERFLOWWE_ONE;
        }
        object->anim.rootMotionScale *= object->anim.modelInstance->rootMotionScaleBase;
    }
    object->objectFlags = (u16)(object->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    ObjAnim_SetCurrentMove(obj, 0, WATERFLOWWE_ZERO, 0);
}

void waterflowwe_release(void) {
}

void waterflowwe_initialise(void) {
    gWaterFlowPhaseDriver = 0;
    gWaterFlowIdlePhase = WATERFLOWWE_ZERO;
    gWaterFlowFlowPhase = WATERFLOWWE_ZERO;
}

ObjectDescriptor gWaterFlowWeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    waterflowwe_initialise,
    waterflowwe_release,
    0,
    (ObjectDescriptorCallback)waterflowwe_init,
    (ObjectDescriptorCallback)waterflowwe_update,
    waterflowwe_hitDetect,
    (ObjectDescriptorCallback)waterflowwe_render,
    (ObjectDescriptorCallback)waterflowwe_free,
    (ObjectDescriptorCallback)waterflowwe_getObjectTypeId,
    waterflowwe_getExtraSize,
};
