/* CloudRunner Fortress patrol-robot searchlight behavior. */

#include "dlls/objects/336_GCRobotLigh.h"

#include "dolphin/mtx/vec.h"
#include "main/dll/player_api.h"
#include "main/model_light.h"
#include "main/obj_link.h"
#include "main/object_transform.h"
#include "main/objhits.h"
#include "main/sky.h"
#include "main/track_bbox_api.h"
#include "main/voxmaps.h"
#include "sys/objects.h"

#define GCROBOTLIGHTBEAM_HIT_VOLUME_SLOT       0x17
#define GCROBOTLIGHTBEAM_PLAYER_AIM_HEIGHT     10.0f
#define GCROBOTLIGHTBEAM_BBOX_RADIUS           1.0f
#define GCROBOTLIGHTBEAM_BBOX_FLAGS            4
#define GCROBOTLIGHTBEAM_BBOX_MASK             -1
#define GCROBOTLIGHTBEAM_ATTENUATION_RANGE     12.0f
#define GCROBOTLIGHTBEAM_AMBIENT_COLOR_SCALE   0.7f
#define GCROBOTLIGHTBEAM_POINT_LIGHT_INTENSITY 0xFA
#define GCROBOTLIGHTBEAM_POINT_LIGHT_ALPHA     0xFF
#define GCROBOTLIGHTBEAM_OBJECT_ALPHA          0x80

f32 gGcRobotLightBeamAttenuationNear = 50.0f;
f32 gGcRobotLightBeamTraceDistance = 150.0f;

int gcRobotLightBeam_isPlayerCaught(GameObject* obj) {
    return ((GcRobotLightBeamState*)obj->extra)->statusFlags.playerCaught;
}

f32 gGcRobotLightBeamLocalDirection[3] = {0.0f, -0.757f, -0.2f};

int gcRobotLightBeam_getExtraSize(void) {
    return sizeof(GcRobotLightBeamState);
}

int gcRobotLightBeam_getObjectTypeId(void) {
    return 0;
}

void gcRobotLightBeam_free(GameObject* obj) {
    GcRobotLightBeamState* state = obj->extra;

    if (state->pointLight != NULL) {
        modelLightStruct_freeSlot(&state->pointLight);
    }
    if (obj->ownerObj != NULL) {
        ObjLink_DetachChild((GameObject*)obj->ownerObj, obj);
    }
}

void gcRobotLightBeam_render(void) {
}

void gcRobotLightBeam_hitDetect(GameObject* obj) {
    GameObject* hitObject;
    f32 playerPosition[3];
    TrackLineIntersectResult bboxHit;
    GcRobotLightBeamState* state = obj->extra;

    state->statusFlags.playerCaught = FALSE;
    if (obj->ownerObj == NULL) {
        return;
    }
    if (ObjHits_GetPriorityHit(obj, &hitObject, NULL, NULL) == 0) {
        hitObject = (GameObject*)((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject;
        if (hitObject == NULL) {
            return;
        }
    }
    if (hitObject != Obj_GetPlayerObject()) {
        return;
    }
    if (playerIsDisguised(hitObject) != 0) {
        return;
    }
    playerPosition[0] = hitObject->anim.localPosX;
    playerPosition[1] = GCROBOTLIGHTBEAM_PLAYER_AIM_HEIGHT + hitObject->anim.localPosY;
    playerPosition[2] = hitObject->anim.localPosZ;
    if (voxmaps_traceWorldLine(&obj->anim.localPosX, playerPosition) == 0) {
        return;
    }
    if (obj->userData1 != 0 ||
        trackGetLineIntersect(&obj->anim.localPosX, playerPosition, GCROBOTLIGHTBEAM_BBOX_RADIUS, 0, &bboxHit, obj,
                           GCROBOTLIGHTBEAM_BBOX_FLAGS, GCROBOTLIGHTBEAM_BBOX_MASK, 0, 0) == 0) {
        state->statusFlags.playerCaught = TRUE;
    }
}

void gcRobotLightBeam_update(GameObject* obj) {
    GcRobotLightBeamState* state;
    f32 worldDirection[3];
    f32 lightPosition[3];
    u8 red;
    u8 green;
    u8 blue;

    state = obj->extra;
    if (state->pointLight == NULL) {
        state->pointLight = modelLightStruct_createPointLight(obj, GCROBOTLIGHTBEAM_POINT_LIGHT_INTENSITY,
                                                              GCROBOTLIGHTBEAM_POINT_LIGHT_INTENSITY,
                                                              GCROBOTLIGHTBEAM_POINT_LIGHT_INTENSITY, TRUE);
        if (state->pointLight != NULL) {
            modelLightStruct_setDistanceAttenuation(state->pointLight, gGcRobotLightBeamAttenuationNear,
                                                    GCROBOTLIGHTBEAM_ATTENUATION_RANGE +
                                                        gGcRobotLightBeamAttenuationNear);
        }
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, GCROBOTLIGHTBEAM_HIT_VOLUME_SLOT, 0, 0);
    worldDirection[0] = gGcRobotLightBeamLocalDirection[0];
    worldDirection[1] = gGcRobotLightBeamLocalDirection[1];
    worldDirection[2] = gGcRobotLightBeamLocalDirection[2];
    Obj_TransformLocalVectorByWorldMatrix(obj, gGcRobotLightBeamLocalDirection, worldDirection);
    voxmaps_traceScaledVectorEnd(lightPosition, &obj->anim.localPosX, worldDirection, gGcRobotLightBeamTraceDistance);
    PSVECScale((Vec*)gGcRobotLightBeamLocalDirection, (Vec*)lightPosition,
               PSVECDistance(&obj->anim.localPos, (Vec*)lightPosition));
    skyGetSunColor(0, &red, &green, &blue);
    if (state->pointLight != NULL) {
        modelLightStruct_setDiffuseColor(state->pointLight, (s32)(GCROBOTLIGHTBEAM_AMBIENT_COLOR_SCALE * (f32)(u32)red),
                                         (s32)(GCROBOTLIGHTBEAM_AMBIENT_COLOR_SCALE * (f32)(u32)green),
                                         (s32)(GCROBOTLIGHTBEAM_AMBIENT_COLOR_SCALE * (f32)(u32)blue),
                                         GCROBOTLIGHTBEAM_POINT_LIGHT_ALPHA);
        modelLightStruct_setPosition(state->pointLight, lightPosition[0], lightPosition[1], lightPosition[2]);
    }
}

void gcRobotLightBeam_init(GameObject* obj) {
    GcRobotLightBeamState* state = obj->extra;

    state->pointLight = NULL;
    state->unknown4 = 0;
    ObjHits_EnableObject(obj);
    obj->anim.alpha = GCROBOTLIGHTBEAM_OBJECT_ALPHA;
}

void gcRobotLightBeam_release(void) {
}

void gcRobotLightBeam_initialise(void) {
}

ObjectDescriptor10WithPadding gGCRobotLightBeamObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)gcRobotLightBeam_initialise,
        (ObjectDescriptorCallback)gcRobotLightBeam_release,
        0,
        (ObjectDescriptorCallback)gcRobotLightBeam_init,
        (ObjectDescriptorCallback)gcRobotLightBeam_update,
        (ObjectDescriptorCallback)gcRobotLightBeam_hitDetect,
        (ObjectDescriptorCallback)gcRobotLightBeam_render,
        (ObjectDescriptorCallback)gcRobotLightBeam_free,
        (ObjectDescriptorCallback)gcRobotLightBeam_getObjectTypeId,
        gcRobotLightBeam_getExtraSize,
    },
    0,
};
