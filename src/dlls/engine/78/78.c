/*
 * DLL 78 / 0x4E - world-map camera mode.
 */
#include "main/dll/dll_004E_cameramodeworldmap.h"

#include "dlls/objects/466_WORLDplanet.h"
#include "dlls/objects/467.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "main/dll/dll_0000_gameui_hud_api.h"
#include "main/lightmap_api.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/screen_transition.h"
#include "main/vecmath.h"
#include "sys/objects.h"

int lbl_803DD58C;
CameraModeWorldMapState* gCameraModeWorldMapState;
f32 gWorldMapBriefingPortraitHeightOffsets[4] = {-3.0f, -3.5f, -3.5f, -3.0f};

void CameraModeWorldMap_copyToCurrent(void* value, CameraModeWorldMapAction action) {
    switch (action) {
    case CAMERA_MODE_WORLD_MAP_ACTION_SET_MODE:
        if (value == NULL) {
            return;
        }
        gCameraModeWorldMapState->mode = *(u8*)value;
        return;
    case CAMERA_MODE_WORLD_MAP_ACTION_SET_FOCUS:
    case CAMERA_MODE_WORLD_MAP_ACTION_SET_FOCUS_IMMEDIATE:
        if (value == NULL) {
            return;
        }
        gCameraModeWorldMapState->focusObjectId = *(int*)value;
        if (action == CAMERA_MODE_WORLD_MAP_ACTION_SET_FOCUS) {
            gCameraModeWorldMapState->focusBlendTimer = 20;
        } else {
            gCameraModeWorldMapState->focusBlendTimer = 1;
        }
        return;
    }
}

void CameraModeWorldMap_free(void) {
    mm_free(gCameraModeWorldMapState);
    gCameraModeWorldMapState = NULL;
}

void CameraModeWorldMap_update(CameraObject* camera) {
    GameObject* target;
    GameObject *mapOrigin, *indicator;
    u16 buttons;
    s16 pitchDelta;
    f32 markerOffsetX, markerOffsetZ;
    f32 orbitAngleRadians;
    f32 portraitAngleRadians;
    f32 cosValue;
    f32 focusOffsetX, focusOffsetZ;
    f32 requestedDistanceVelocity = 0.0f;

    target = (GameObject*)camera->anim.targetObj;
    mapOrigin = ObjList_FindObjectById(0x42fff);
    indicator = ObjList_FindObjectById(0x4325b);
    buttons = getButtonsHeld(0);
    getButtonsJustPressed(0);

    switch (gCameraModeWorldMapState->mode) {
    case CAMERA_MODE_WORLD_MAP_FREE_OVERVIEW:
        if (gCameraModeWorldMapState->previousMode != gCameraModeWorldMapState->mode) {
            gCameraModeWorldMapState->focusBlendTimer = 1;
            (*gScreenTransitionInterface)->start(0xc, SCREEN_TRANSITION_BLACK);
            gCameraModeWorldMapState->settleFrames = 2;
            gCameraModeWorldMapState->flags.transitionActive = 1;
        } else {
            s16 yawInput, pitchInput;
            if (gCameraModeWorldMapState->flags.transitionActive != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0) {
                GameObject* briefingPortrait;
                setWorldMapVoiceoverActive(0);
                (*gScreenTransitionInterface)->step(0xc, SCREEN_TRANSITION_BLACK);
                gCameraModeWorldMapState->flags.transitionActive = 0;
                briefingPortrait = ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                ((WorldObjState*)briefingPortrait->extra)->effectState = 0;
            }
            if (gCameraModeWorldMapState->flags.transitionActive == 0) {
                gCameraModeWorldMapState->settleFrames -= 1;
                if (gCameraModeWorldMapState->settleFrames < 1) {
                    gCameraModeWorldMapState->settleFrames = 1;
                }
                if (buttons & PAD_BUTTON_UP) {
                    requestedDistanceVelocity = -0.02f * gCameraModeWorldMapState->distance;
                }
                if (buttons & PAD_BUTTON_DOWN) {
                    requestedDistanceVelocity = 0.02f * gCameraModeWorldMapState->distance;
                }
                {
                    f32 requestedSpeed, currentSpeed, rate, velocity;
                    CameraModeWorldMapState* state;
                    if (requestedDistanceVelocity < 0.0f) {
                        requestedSpeed = -requestedDistanceVelocity;
                    } else {
                        requestedSpeed = requestedDistanceVelocity;
                    }
                    state = gCameraModeWorldMapState;
                    velocity = state->distanceVelocity;
                    if (velocity < 0.0f) {
                        currentSpeed = -velocity;
                    } else {
                        currentSpeed = velocity;
                    }
                    if (currentSpeed > requestedSpeed) {
                        rate = 0.3f;
                    } else {
                        rate = 0.08f;
                    }
                    state->distanceVelocity = rate * (requestedDistanceVelocity - velocity) + state->distanceVelocity;
                }
                gCameraModeWorldMapState->distance =
                    gCameraModeWorldMapState->distance + gCameraModeWorldMapState->distanceVelocity;
                if (gCameraModeWorldMapState->distance < 280.0f) {
                    gCameraModeWorldMapState->distance = 280.0f;
                }
                if (gCameraModeWorldMapState->distance > 700.0f) {
                    gCameraModeWorldMapState->distance = 700.0f;
                }
                yawInput = (s16)(padGetCX(0) * 3);
                pitchInput = (s16)(padGetCY(0) * 3);
                if (gCameraModeWorldMapState->focusBlendTimer != 0) {
                    GameObject* focusObject = ObjList_FindObjectById(gCameraModeWorldMapState->focusObjectId);
                    CameraModeWorldMapState* state;
                    s16 angleDelta;
                    f32 currentDistance;
                    f32 targetDistance;
                    focusOffsetX = focusObject->anim.worldPosX - mapOrigin->anim.worldPosX;
                    focusOffsetZ = focusObject->anim.worldPosZ - mapOrigin->anim.worldPosZ;
                    gCameraModeWorldMapState->targetAngle = (s16)(0x8000 - getAngle(focusOffsetX, focusOffsetZ));
                    angleDelta = (s16)((state = gCameraModeWorldMapState)->targetAngle - (u16)camera->anim.rotX);
                    if (angleDelta > 0x8000) {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000) {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotX = camera->anim.rotX + angleDelta / state->focusBlendTimer;
                    gCameraModeWorldMapState->targetAngle =
                        (s16)(0x47d0 - getAngle(sqrtf(focusOffsetX * focusOffsetX + focusOffsetZ * focusOffsetZ),
                                                focusObject->anim.worldPosY - mapOrigin->anim.worldPosY));
                    angleDelta = (s16)((state = gCameraModeWorldMapState)->targetAngle - (u16)camera->anim.rotY);
                    if (angleDelta > 0x8000) {
                        angleDelta = (s16)(angleDelta - 0xffff);
                    }
                    if (angleDelta < -0x8000) {
                        angleDelta += 0xffff;
                    }
                    camera->anim.rotY = camera->anim.rotY + angleDelta / state->focusBlendTimer;
                    targetDistance = 360.0f;
                    state = gCameraModeWorldMapState;
                    currentDistance = state->distance;
                    state->distance =
                        currentDistance + (f32)((s16)(s32)(targetDistance - currentDistance) / state->focusBlendTimer);
                    gCameraModeWorldMapState->focusBlendTimer -= 1;
                }
                camera->anim.rotX += yawInput;
                camera->anim.rotY += pitchInput;
                if (camera->anim.rotY > 12000) {
                    camera->anim.rotY = 12000;
                }
                if (camera->anim.rotY < -12000) {
                    camera->anim.rotY = -12000;
                }
                {
                    f32 csYaw, snYaw, csPit, snPit;
                    f32 distance;
                    f32 offsetX, errorX;
                    f32 offsetZ, errorZ;
                    f32 offsetY, errorY;
                    csYaw = -mathCosf(3.1415927f * camera->anim.rotX / 32768.0f);
                    snYaw = mathSinf(3.1415927f * camera->anim.rotX / 32768.0f);
                    csPit = mathCosf(3.1415927f * (f32)(camera->anim.rotY + 0x320) / 32768.0f);
                    snPit = mathSinf(3.1415927f * (f32)(camera->anim.rotY + 0x320) / 32768.0f);
                    distance = gCameraModeWorldMapState->distance;
                    offsetY = distance * snPit;
                    offsetZ = distance * csPit;
                    offsetX = offsetZ * snYaw;
                    offsetZ *= csYaw;
                    errorX = camera->anim.worldPosX - (target->anim.worldPosX + offsetX);
                    errorY = camera->anim.worldPosY - ((-30.0f + target->anim.worldPosY) + offsetY);
                    errorZ = camera->anim.worldPosZ - (target->anim.worldPosZ + offsetZ);
                    camera->anim.worldPosX = camera->anim.worldPosX - errorX / gCameraModeWorldMapState->settleFrames;
                    camera->anim.worldPosY = camera->anim.worldPosY - errorY / gCameraModeWorldMapState->settleFrames;
                    camera->anim.worldPosZ = camera->anim.worldPosZ - errorZ / gCameraModeWorldMapState->settleFrames;
                }
            }
        }
        break;
    case CAMERA_MODE_WORLD_MAP_LOCKED_PATH: {
        GameObject* portrait = ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
        if (gCameraModeWorldMapState->previousMode != gCameraModeWorldMapState->mode) {
            (*gScreenTransitionInterface)->start(0xc, SCREEN_TRANSITION_BLACK);
            gCameraModeWorldMapState->settleFrames = 2;
            gCameraModeWorldMapState->flags.transitionActive = 1;
        } else {
            if (gCameraModeWorldMapState->flags.transitionActive != 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0) {
                GameObject* briefingPortrait;
                setWorldMapVoiceoverActive(1);
                (*gScreenTransitionInterface)->step(0xc, SCREEN_TRANSITION_BLACK);
                gCameraModeWorldMapState->flags.transitionActive = 0;
                briefingPortrait = ObjList_FindObjectById(WORLDPLANET_BRIEFING_PORTRAIT_OBJECT_ID);
                ((WorldObjState*)briefingPortrait->extra)->effectState = 1;
            }
            if (gCameraModeWorldMapState->flags.transitionActive == 0) {
                int targetYaw;
                s16 angleDelta;
                u16 portraitYaw;
                gCameraModeWorldMapState->settleFrames -= 1;
                if (gCameraModeWorldMapState->settleFrames < 1) {
                    gCameraModeWorldMapState->settleFrames = 1;
                }
                targetYaw = (u16)-getAngle(mapOrigin->anim.worldPosX - target->anim.worldPosX,
                                           mapOrigin->anim.worldPosZ - target->anim.worldPosZ);
                angleDelta = (s16)((targetYaw - 0x308f) - (u16)camera->anim.rotX);
                if (angleDelta > 0x8000) {
                    angleDelta = (s16)(angleDelta - 0xffff);
                }
                if (angleDelta < -0x8000) {
                    angleDelta += 0xffff;
                }
                camera->anim.rotX = camera->anim.rotX + angleDelta / gCameraModeWorldMapState->settleFrames;
                angleDelta = (s16)(0x7d0 - (u16)camera->anim.rotY);
                if (angleDelta > 0x8000) {
                    angleDelta = (s16)(angleDelta - 0xffff);
                }
                if (angleDelta < -0x8000) {
                    angleDelta += 0xffff;
                }
                camera->anim.rotY = camera->anim.rotY + angleDelta / gCameraModeWorldMapState->settleFrames;
                {
                    f32 sinValue, fixedCosValue, fixedSinValue;
                    f32 offsetX, errorX;
                    f32 offsetZ, errorZ;
                    f32 offsetY, errorY;
                    orbitAngleRadians = 3.1415927f * (f32)(u16)(targetYaw - 0x39dc) / 32768.0f;
                    cosValue = -mathCosf(orbitAngleRadians);
                    sinValue = mathSinf(orbitAngleRadians);
                    fixedCosValue = mathCosf(0.1917476f);
                    fixedSinValue = mathSinf(0.1917476f);
                    offsetY = 70.0f * fixedSinValue;
                    offsetZ = 70.0f * fixedCosValue;
                    offsetX = offsetZ * sinValue;
                    offsetZ *= cosValue;
                    errorX = camera->anim.worldPosX - (target->anim.worldPosX + offsetX);
                    errorY = camera->anim.worldPosY - (25.0f + (target->anim.worldPosY + offsetY));
                    errorZ = camera->anim.worldPosZ - (target->anim.worldPosZ + offsetZ);
                    camera->anim.worldPosX = camera->anim.worldPosX - errorX / gCameraModeWorldMapState->settleFrames;
                    camera->anim.worldPosY = camera->anim.worldPosY - errorY / gCameraModeWorldMapState->settleFrames;
                    camera->anim.worldPosZ = camera->anim.worldPosZ - errorZ / gCameraModeWorldMapState->settleFrames;
                }
                portraitYaw = (u16)(camera->anim.rotX + 0x1388);
                if (isWidescreen() != 0) {
                    portraitYaw = (u16)(portraitYaw + 0x514);
                }
                {
                    f32 cosValue;
                    f32 sinValue;
                    f32 radius;
                    portraitAngleRadians = 3.1415927f * portraitYaw / 32768.0f;
                    cosValue = mathCosf(portraitAngleRadians);
                    sinValue = -mathSinf(portraitAngleRadians);
                    radius = 30.0f;
                    portrait->anim.localPosX = radius * sinValue + camera->anim.worldPosX;
                    portrait->anim.localPosY = camera->anim.worldPosY +
                                               gWorldMapBriefingPortraitHeightOffsets[(s8) * &portrait->anim.bankIndex];
                    portrait->anim.localPosZ = radius * cosValue + camera->anim.worldPosZ;
                    portrait->anim.rotX = (s16)(-0xbb8 - portraitYaw);
                }
            }
        }
        break;
    }
    }

    gCameraModeWorldMapState->previousMode = gCameraModeWorldMapState->mode;
    {
        GameObject* cameraMarker = ObjList_FindObjectById(0x431dc);
        markerOffsetX = cameraMarker->anim.worldPosX - camera->anim.worldPosX;
        markerOffsetZ = cameraMarker->anim.worldPosZ - camera->anim.worldPosZ;
        cameraMarker->anim.rotX = (s16)(getAngle(markerOffsetX, markerOffsetZ) + 0x8000);
        cameraMarker->anim.rotY =
            (s16)(0x8000 - getAngle(sqrtf(markerOffsetX * markerOffsetX + markerOffsetZ * markerOffsetZ),
                                    cameraMarker->anim.worldPosY - camera->anim.worldPosY));
        cameraMarker->anim.rootMotionScale = 10.7f + 200.0f / gCameraModeWorldMapState->distance;
        indicator->anim.rotX = cameraMarker->anim.rotX;
        indicator->anim.rotY = cameraMarker->anim.rotY;
        indicator->anim.rootMotionScale = cameraMarker->anim.rootMotionScale;
    }

    pitchDelta = (s16)(indicator->anim.rotX - 0x2198);
    if (pitchDelta > -0x2000 && pitchDelta < 0x2000) {
        f32 alpha;
        alpha = (0.0f > 255.0f * (mathCosf(3.1415927f * (f32)((indicator->anim.rotX - 0x2198) * 2) / 32768.0f) *
                                  mathCosf(3.1415927f * (f32)((indicator->anim.rotY - 0x4000) * 2) / 32768.0f)))
                    ? 0.0f
                    : 255.0f * (mathCosf(3.1415927f * (f32)((indicator->anim.rotX - 0x2198) * 2) / 32768.0f) *
                                mathCosf(3.1415927f * (f32)((indicator->anim.rotY - 0x4000) * 2) / 32768.0f));
        indicator->anim.alpha = alpha;
    } else {
        indicator->anim.alpha = 0;
    }

    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeWorldMap_init(CameraObject* camera) {
    register u32 zero;
    if (gCameraModeWorldMapState == NULL) {
        gCameraModeWorldMapState = (CameraModeWorldMapState*)mmAlloc(sizeof(CameraModeWorldMapState), 15, 0);
    }
    gCameraModeWorldMapState->distance = 700.0f;
    gCameraModeWorldMapState->distanceVelocity = 0.0f;
    zero = 0;
    gCameraModeWorldMapState->mode = zero;
    gCameraModeWorldMapState->previousMode = zero;
    gCameraModeWorldMapState->flags.transitionActive = 0;
    gCameraModeWorldMapState->settleFrames = 1;
    gCameraModeWorldMapState->focusBlendTimer = 0;
    gCameraModeWorldMapState->focusObjectId = 0;
    camera->fov = 60.0f;
    camera->anim.rotX = -32768;
}

void CameraModeWorldMap_release(void) {
}

void CameraModeWorldMap_initialise(void) {
}

CameraModeWorldMapDescriptor gCameraModeWorldMapDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeWorldMap_initialise,
    CameraModeWorldMap_release,
    NULL,
    CameraModeWorldMap_init,
    CameraModeWorldMap_update,
    CameraModeWorldMap_free,
    CameraModeWorldMap_copyToCurrent,
    NULL,
};
