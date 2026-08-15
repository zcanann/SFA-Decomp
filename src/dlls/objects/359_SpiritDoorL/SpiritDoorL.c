/* Spirit-door lock and orbit controller. */
#include "dlls/objects/359_SpiritDoorL.h"
#include "dolphin/mtx/vec.h"

#include "dlls/objects/343_SpiritDoorS.h"

#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0051_cameramodecannon.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/model_light.h"
#include "main/object_render.h"
#include "main/object_transform.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/objtype.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

#define SPIRIT_DOOR_LOCK_LOOP_SFX  0x423
#define SPIRIT_DOOR_LOCK_HALF_TURN 0x8000
#define SPIRIT_DOOR_LOCK_FULL_TURN 0x10000

typedef struct SpiritDoorLockOrbitWords {
    u32 x;
    u32 y;
    u32 z;
} SpiritDoorLockOrbitWords;

s16 gSpiritDoorLockSpinSpeed = -256;
s32 gSpiritDoorLockTexScrollSpeed = 40;
s32 gSpiritDoorLockTexScrollWrap = 39;

const u32 gSpiritDoorLockOrbitOffsetBase[4] = {0, 0, 0x40E00000, 0};

extern const f32 lbl_803E4430;
extern const f32 gSpiritDoorLockDefaultScale;
extern const f32 gSpiritDoorLockApproachRange;
extern const f32 gSpiritDoorLockScaleFactor;
extern const f32 gSpiritDoorLockScaleDecay;
extern const f32 gSpiritDoorLockSpinDownRate;
extern const f32 gSpiritDoorLockOrbitOffsetY;
extern const f32 gSpiritDoorLockOrbitMaxDist;

int SpiritDoorLock_getExtraSize(void) {
    return sizeof(SpiritDoorLockState);
}

int SpiritDoorLock_getObjectTypeId(void) {
    return 0;
}

void SpiritDoorLock_free(GameObject* obj) {
    SpiritDoorLockState* state = obj->extra;

    if (state->light != NULL) {
        modelLightStruct_freeSlot(&state->light);
    }
}

void SpiritDoorLock_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    s32 v = visible;

    if (v != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, gSpiritDoorLockDefaultScale);
    }
}

void SpiritDoorLock_hitDetect(void) {
}

void SpiritDoorLock_update(GameObject* obj) {
    SpiritDoorLockState* state;
    const SpiritDoorLockPlacement* placement;
    GameObject* player;
    int orbitCount;
    f32 orbitOffset[3];
    f32 worldOffset[3];

    *(SpiritDoorLockOrbitWords*)orbitOffset = *(const SpiritDoorLockOrbitWords*)gSpiritDoorLockOrbitOffsetBase;

    state = obj->extra;
    placement = (const SpiritDoorLockPlacement*)obj->anim.placementData;

    player = Obj_GetPlayerObject();

    if (mainGetBit(GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED) == 0) {
        if (Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX) < gSpiritDoorLockApproachRange) {
            if (state->active != 0) {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            mainSetBits(GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED, 1);
        }
    }

    if (state->active == 0) {
        if (mainGetBit(placement->doneGameBit) == 0) {
            state->active = mainGetBit(placement->activeGameBit);
            if (state->active != 0) {
                f32 modelScale = obj->anim.modelInstance->rootMotionScaleBase * (f32)(s32)placement->scale;
                obj->anim.rootMotionScale = modelScale * gSpiritDoorLockScaleFactor;
                if (state->light == NULL) {
                    state->light = modelLightStruct_createPointLight(obj, 0xff, 0, 0x4d, 0);
                }
            }
        } else {
            if (obj->anim.alpha == 255) {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
            if (obj->anim.alpha != 0) {
                obj->anim.alpha -= 1;
                if (state->light != NULL) {
                    u32 attenuation = (u32)obj->anim.alpha >> 2;
                    modelLightStruct_setDistanceAttenuation(state->light, (f32)(s32)attenuation,
                                                            (f32)(s32)(attenuation + 10));
                }
                obj->anim.rootMotionScale *= gSpiritDoorLockScaleDecay;
                obj->anim.rotZ = (f32)(int)obj->anim.rotZ - gSpiritDoorLockSpinDownRate * timeDelta;
            } else {
                if (state->light != NULL) {
                    modelLightStruct_freeSlot(&state->light);
                }
            }
        }
    } else {
        int cameraMode;
        GameObject** orbitObjects;
        ObjTextureRuntimeSlot* texture;
        s16 angleStep;
        s16 angle;
        int i;

        cameraMode = (*gCameraInterface)->getMode();
        if (cameraMode != CAMERA_MODE_CANNON_RESOURCE_ID) {
            Sfx_KeepAliveLoopedObjectSound(obj, SPIRIT_DOOR_LOCK_LOOP_SFX);
        }
        orbitObjects = (GameObject**)objGetAllOfType(SPIRIT_DOOR_SPIRIT_OBJECT_GROUP, &orbitCount);
        angleStep = SPIRIT_DOOR_LOCK_FULL_TURN / state->orbitCount;
        angle = state->spinAngle;
        orbitOffset[1] = gSpiritDoorLockOrbitOffsetY;
        for (i = 0; i < orbitCount; i++) {
            if (Vec_distance(&obj->anim.worldPosX, &orbitObjects[i]->anim.worldPosX) > gSpiritDoorLockOrbitMaxDist) {
                continue;
            }
            obj->anim.rotZ = angle;
            Obj_TransformLocalVectorByWorldMatrix(obj, orbitOffset, worldOffset);
            PSVECAdd(&obj->anim.localPos, (Vec*)worldOffset, &orbitObjects[i]->anim.localPos);
            orbitObjects[i]->anim.rotX = obj->anim.rotX;
            orbitObjects[i]->anim.rotZ = (s16)(angle + SPIRIT_DOOR_LOCK_HALF_TURN);
            orbitObjects[i]->anim.rootMotionScale = obj->anim.rootMotionScale;
            angle += angleStep;
        }
        state->spinAngle += gSpiritDoorLockSpinSpeed;
        obj->anim.rotZ = 0;
        if (orbitCount == 0) {
            state->active = 0;
            mainSetBits(placement->doneGameBit, 1);
            ObjHits_DisableObject(obj);
        }
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->offsetT = texture->offsetT + gSpiritDoorLockTexScrollSpeed * framesThisStep;
            texture->offsetS = texture->offsetS + gSpiritDoorLockTexScrollSpeed * framesThisStep;
            if ((s32)texture->offsetT > (s32)(gSpiritDoorLockTexScrollWrap << 8)) {
                texture->offsetT = texture->offsetT - (gSpiritDoorLockTexScrollWrap << 8);
            }
            if ((s32)texture->offsetS > (s32)(gSpiritDoorLockTexScrollWrap << 8)) {
                texture->offsetS = texture->offsetS - (gSpiritDoorLockTexScrollWrap << 8);
            }
        }
        if (obj->anim.alpha < 0xff) {
            obj->anim.alpha += 1;
        }
    }
}

void SpiritDoorLock_init(GameObject* obj, const SpiritDoorLockPlacement* placement, int startHidden) {
    SpiritDoorLockState* state = obj->extra;
    f32 scale;
    int isDefaultScale;

    obj->anim.rotX = (s16)(placement->yaw << 8);
    state->orbitCount = placement->orbitCount;
    state->active = 0;

    scale = placement->scale * gSpiritDoorLockScaleFactor;
    isDefaultScale = (scale != lbl_803E4430);
    isDefaultScale = !isDefaultScale;
    if (isDefaultScale) {
        scale = gSpiritDoorLockDefaultScale;
    }
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase * scale;
    state->spinAngle = 0;

    ObjHits_DisableObject(obj);
    state->flags.unknown80 = 0;

    if (startHidden == 0) {
        obj->anim.alpha = 0;
        state->light = modelLightStruct_createPointLight(obj, 0xff, 0, 0x4d, 0);
    }
}

void SpiritDoorLock_release(void) {
}

void SpiritDoorLock_initialise(void) {
}

ObjectDescriptor gSpiritDoorLockObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SpiritDoorLock_initialise,
    (ObjectDescriptorCallback)SpiritDoorLock_release,
    0,
    (ObjectDescriptorCallback)SpiritDoorLock_init,
    (ObjectDescriptorCallback)SpiritDoorLock_update,
    (ObjectDescriptorCallback)SpiritDoorLock_hitDetect,
    (ObjectDescriptorCallback)SpiritDoorLock_render,
    (ObjectDescriptorCallback)SpiritDoorLock_free,
    (ObjectDescriptorCallback)SpiritDoorLock_getObjectTypeId,
    SpiritDoorLock_getExtraSize,
};
