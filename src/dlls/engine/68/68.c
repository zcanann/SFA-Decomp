/*
 * DLL 68 / 0x44 - viewfinder camera mode.
 */
#include "main/dll/dll_0044_cameramodeviewfinder.h"

#include "dlls/objects/488_SB_Galleon.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_interface.h"
#include "main/debug.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/dll/player_api.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/viewfinder.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/rcp_dolphin.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"

int lbl_803DD54C;
CameraModeViewfinderState* gCameraModeViewfinderState;

char sCameraModeViewfinderYDebugFormat[] = "y=%f\n";

const f32 gCameraModeViewfinderTargetHeight[1] = {35.0f};

void firstPersonPlaceCamera(GameObject* focus, int resetClamp) {
    register GameObject* self = focus;
    GameObject* galleon;
    int galleonState;
    f32 prevPosZ;
    f32 prevPosY;
    f32 prevPosX;
    f32 localOffset[3];

    if (self->anim.classId == 1) {
        cameraGetPrevPos2(self, &prevPosX, &prevPosY, &prevPosZ);
        if (((resetClamp != 0) || (gCameraModeViewfinderState->cameraPositionX != prevPosX)) ||
            (gCameraModeViewfinderState->cameraPositionZ != prevPosZ)) {
            gCameraModeViewfinderState->clampedPositionY = prevPosY;
        }
        gCameraModeViewfinderState->cameraPositionX = prevPosX;
        gCameraModeViewfinderState->cameraPositionY = prevPosY;
        gCameraModeViewfinderState->cameraPositionZ = prevPosZ;
    } else {
        gCameraModeViewfinderState->cameraPositionX = self->anim.worldPosX;
        gCameraModeViewfinderState->cameraPositionY = gCameraModeViewfinderTargetHeight[0] + self->anim.worldPosY;
        gCameraModeViewfinderState->cameraPositionZ = self->anim.worldPosZ;
        gCameraModeViewfinderState->clampedPositionY = gCameraModeViewfinderState->cameraPositionY;
    }
    galleon = getSbGalleon();
    if (galleon != NULL) {
        galleonState = SB_Galleon_getCameraState(galleon);
        if (galleonState == 2) {
            localOffset[0] = self->anim.worldPosX - galleon->anim.worldPosX;
            localOffset[1] = (gCameraModeViewfinderTargetHeight[0] + self->anim.worldPosY) - galleon->anim.worldPosY;
            localOffset[2] = self->anim.worldPosZ - galleon->anim.worldPosZ;
            vecRotateZXY(&galleon->anim.rotX, localOffset);
            gCameraModeViewfinderState->cameraPositionX = galleon->anim.worldPosX + localOffset[0];
            gCameraModeViewfinderState->cameraPositionY = galleon->anim.worldPosY + localOffset[1];
            gCameraModeViewfinderState->cameraPositionZ = galleon->anim.worldPosZ + localOffset[2];
        }
    }
    return;
}

void firstPersonExit(CameraObject* camera) {
    register CameraObject* self = camera;
    GameObject* target;
    f32 tangent;
    f32 dx;
    f32 dz;
    int targetYaw;
    f32 targetPos[3];
    s16 unusedRotation[2];

    target = (GameObject*)self->anim.targetObj;
    gCameraModeViewfinderState->positionXCurve.start = self->anim.worldPosX;
    tangent = 0.0f;
    gCameraModeViewfinderState->positionXCurve.startTangent = 0.0f;
    gCameraModeViewfinderState->positionXCurve.endTangent = tangent;
    gCameraModeViewfinderState->positionYCurve.start = self->anim.worldPosY;
    gCameraModeViewfinderState->positionYCurve.startTangent = tangent;
    gCameraModeViewfinderState->positionYCurve.endTangent = tangent;
    gCameraModeViewfinderState->positionZCurve.start = self->anim.worldPosZ;
    gCameraModeViewfinderState->positionZCurve.startTangent = tangent;
    gCameraModeViewfinderState->positionZCurve.endTangent = tangent;
    camcontrol_getTargetPosition(self, &target->anim, targetPos, unusedRotation);
    gCameraModeViewfinderState->positionXCurve.end = targetPos[0];
    gCameraModeViewfinderState->positionYCurve.end = targetPos[1];
    gCameraModeViewfinderState->positionZCurve.end = targetPos[2];
    dx = gCameraModeViewfinderState->positionXCurve.end - gCameraModeViewfinderState->positionXCurve.start;
    dz = gCameraModeViewfinderState->positionZCurve.end - gCameraModeViewfinderState->positionZCurve.start;
    gCameraModeViewfinderState->exitDistance = sqrtf(dx * dx + dz * dz);
    gCameraModeViewfinderState->transitionCurve.px = &gCameraModeViewfinderState->yawCurve.start;
    gCameraModeViewfinderState->transitionCurve.py = &gCameraModeViewfinderState->pitchCurve.start;
    gCameraModeViewfinderState->transitionCurve.pz = NULL;
    gCameraModeViewfinderState->transitionCurve.count = 4;
    gCameraModeViewfinderState->transitionCurve.dir = 0;
    gCameraModeViewfinderState->transitionCurve.eval = Curve_EvalHermite;
    gCameraModeViewfinderState->transitionCurve.coeffFn = Curve_BuildHermiteCoeffs;
    gCameraModeViewfinderState->yawCurve.start = (f32)(s32)self->anim.rotX;
    targetYaw = getAngle((double)(gCameraModeViewfinderState->positionXCurve.end - target->anim.worldPosX),
                         (double)(gCameraModeViewfinderState->positionZCurve.end - target->anim.worldPosZ));
    gCameraModeViewfinderState->yawCurve.end = (f32)(s32)(s16)(0x8000 - targetYaw);
    tangent = 0.0f;
    gCameraModeViewfinderState->yawCurve.startTangent = 0.0f;
    gCameraModeViewfinderState->yawCurve.endTangent = tangent;
    if (((gCameraModeViewfinderState->yawCurve.start - gCameraModeViewfinderState->yawCurve.end) > 32768.0f) ||
        ((gCameraModeViewfinderState->yawCurve.start - gCameraModeViewfinderState->yawCurve.end) < -32768.0f)) {
        if (gCameraModeViewfinderState->yawCurve.start < 0.0f) {
            gCameraModeViewfinderState->yawCurve.start += 65535.0f;
        } else if (gCameraModeViewfinderState->yawCurve.end < 0.0f) {
            gCameraModeViewfinderState->yawCurve.end += 65535.0f;
        }
    }
    gCameraModeViewfinderState->pitchCurve.start = (f32)(s32)self->anim.rotY;
    tangent = 0.0f;
    gCameraModeViewfinderState->pitchCurve.end = 0.0f;
    gCameraModeViewfinderState->pitchCurve.startTangent = tangent;
    gCameraModeViewfinderState->pitchCurve.endTangent = tangent;
    if (((gCameraModeViewfinderState->pitchCurve.start - gCameraModeViewfinderState->pitchCurve.end) > 32768.0f) ||
        ((gCameraModeViewfinderState->pitchCurve.start - gCameraModeViewfinderState->pitchCurve.end) < -32768.0f)) {
        if (gCameraModeViewfinderState->pitchCurve.start < 0.0f) {
            gCameraModeViewfinderState->pitchCurve.start += 65535.0f;
        } else if (gCameraModeViewfinderState->pitchCurve.end < 0.0f) {
            gCameraModeViewfinderState->pitchCurve.end += 65535.0f;
        }
    }
    curvesMove(&gCameraModeViewfinderState->transitionCurve);
}
void firstPersonDoControls(CameraObject* camera) {
    s16 pitchDelta;
    s8 stickX;
    s8 stickY;
    GameObject* focus;
    int spinI;
    f32 t;
    f32 zoom;
    f32 spin;
    f32 fovTarget;
    f32 zoom2;

    focus = (GameObject*)camera->anim.targetObj;
    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    t = (60.0f - camera->fov) / 50.0f;
    zoom = (t < 0.0f) ? 0.0f : ((t > 1.0f) ? 1.0f : t);
    spin = stickX * (6.0f - 4.0f * zoom);
    spin = interpolate(spin - gCameraModeViewfinderState->yawSpeed, 0.12f, timeDelta);
    gCameraModeViewfinderState->yawSpeed = gCameraModeViewfinderState->yawSpeed + spin;
    if ((gCameraModeViewfinderState->yawSpeed > -5.0f) && (gCameraModeViewfinderState->yawSpeed < 5.0f)) {
        gCameraModeViewfinderState->yawSpeed = 0.0f;
    }
    spinI = (int)(15360.0f * ((f32)stickY / 120.0f));
    camera->anim.rotX = gCameraModeViewfinderState->yawSpeed * timeDelta + (f32)camera->anim.rotX;
    spinI = spinI - (camera->anim.rotY & 0xffffU);
    pitchDelta = spinI;
    if (pitchDelta > 0x8000) {
        pitchDelta = pitchDelta - 0xffff;
    }
    if (pitchDelta < -0x8000) {
        pitchDelta = pitchDelta + 0xffff;
    }
    spin = interpolate((f32)pitchDelta, 1.0f / (32.0f * zoom + 16.0f), timeDelta);
    camera->anim.rotY = camera->anim.rotY + spin;
    if (camera->anim.rotY > 0x3c00) {
        camera->anim.rotY = 0x3c00;
    }
    if (camera->anim.rotY < -0x3c00) {
        camera->anim.rotY = -0x3c00;
    }
    focus->anim.rotX = 0x8000 - camera->anim.rotX;
    if (focus->anim.classId == 1) {
        objSetXRot(focus, focus->anim.rotX);
    }
    if (gCameraModeViewfinderState->cameraPositionY < gCameraModeViewfinderState->clampedPositionY) {
        gCameraModeViewfinderState->clampedPositionY = gCameraModeViewfinderState->cameraPositionY;
    }
    camera->anim.worldPosX = gCameraModeViewfinderState->cameraPositionX;
    camera->anim.worldPosY = gCameraModeViewfinderState->clampedPositionY;
    camera->anim.worldPosZ = gCameraModeViewfinderState->cameraPositionZ;
    if (gCameraModeViewfinderState->flags.zoomHudEnabled) {
        zoom2 = camera->fov;
        stickX = padGetCY(0);
        t = (f32)-stickX;
        t = 0.01f * t;
        zoom2 = t * timeDelta + zoom2;
        viewFinderSetZoom(Camera_GetFovY());
        fovTarget = (zoom2 < 5.0f) ? 5.0f : ((zoom2 > 60.0f) ? 60.0f : zoom2);
        if (gCameraModeViewfinderState->flags.sfxEnabled) {
            if ((fovTarget == camera->fov) && (gCameraModeViewfinderState->flags.zoomSfxPlaying)) {
                Sfx_StopFromObject(0, SFXTRIG_and_swipe1);
                gCameraModeViewfinderState->flags.zoomSfxPlaying = 0;
            }
            if ((fovTarget != camera->fov) && (!gCameraModeViewfinderState->flags.zoomSfxPlaying)) {
                Sfx_PlayFromObject(0, SFXTRIG_and_swipe1);
                gCameraModeViewfinderState->flags.zoomSfxPlaying = 1;
            }
        }
        camera->fov = fovTarget;
    }
}

int firstPersonEnter(CameraObject* camera, GameObject* focus) {
    f32 yawDelta;
    f32 startYaw;
    f32 targetYaw;
    GameObject* viewObject;
    int alpha;
    int transitionStarted;
    GameObject* heldObject;

    camera->anim.worldPosX = gCameraModeViewfinderState->cameraPositionX;
    camera->anim.worldPosY = gCameraModeViewfinderState->cameraPositionY;
    camera->anim.worldPosZ = gCameraModeViewfinderState->cameraPositionZ;
    camera->anim.rotY = 0;
    transitionStarted = 0;
    if (camera->blendProgress <= 0.0f) {
        transitionStarted = 1;
    }
    alpha = (int)(255.0f * camera->blendProgress);
    viewObject = (GameObject*)camera->anim.targetObj;
    if (alpha < 1) {
        alpha = 1;
    }
    if (viewObject != NULL) {
        viewObject->anim.alpha = alpha;
        if (Obj_GetPlayerObject() == viewObject) {
            Player_GetHeldObject(viewObject, &heldObject);
            if (heldObject != NULL) {
                heldObject->anim.alpha = alpha;
                if (heldObject->anim.alpha == 1) {
                    heldObject->anim.alpha = 0;
                }
            }
        }
    }
    if (transitionStarted != 0) {
        gCameraModeViewfinderState->transitionCurve.px = &gCameraModeViewfinderState->yawCurve.start;
        gCameraModeViewfinderState->transitionCurve.py = NULL;
        gCameraModeViewfinderState->transitionCurve.pz = NULL;
        gCameraModeViewfinderState->transitionCurve.count = 4;
        gCameraModeViewfinderState->transitionCurve.eval = Curve_EvalHermite;
        gCameraModeViewfinderState->transitionCurve.coeffFn = Curve_BuildHermiteCoeffs;
        gCameraModeViewfinderState->transitionCurve.dir = 0;
        gCameraModeViewfinderState->yawCurve.start = (f32)(s32)camera->anim.rotX;
        gCameraModeViewfinderState->yawCurve.end = (f32)(s16)(0x8000 - focus->anim.rotX);
        startYaw = gCameraModeViewfinderState->yawCurve.start;
        targetYaw = gCameraModeViewfinderState->yawCurve.end;
        yawDelta = startYaw - targetYaw;
        if (yawDelta < 1820.0f && yawDelta > -1820.0f) {
            gCameraModeViewfinderState->yawCurve.end = gCameraModeViewfinderState->yawCurve.start;
        } else if (yawDelta > 32768.0f || yawDelta < -32768.0f) {
            if (startYaw < 0.0f) {
                gCameraModeViewfinderState->yawCurve.start += 65535.0f;
            } else if (targetYaw < 0.0f) {
                gCameraModeViewfinderState->yawCurve.end += 65535.0f;
            }
        }
        {
            f32 k = 0.0f;
            gCameraModeViewfinderState->yawCurve.startTangent = k;
            gCameraModeViewfinderState->yawCurve.endTangent = k;
        }
        curvesMove(&gCameraModeViewfinderState->transitionCurve);
        return 1;
    }
    return 0;
}

void CameraModeViewfinder_copyToCurrent(const CameraModeViewfinderPose* pose) {
    CameraObject* current;

    current = (CameraObject*)(*gCameraInterface)->getCamera();
    if ((current != NULL) && (pose != NULL)) {
        current->anim.rotX = pose->rotationX;
        current->anim.rotY = pose->rotationY;
        current->anim.rotZ = pose->rotationZ;
        current->anim.localPosX = pose->positionX;
        current->anim.localPosY = pose->positionY;
        current->anim.localPosZ = pose->positionZ;
        current->anim.worldPosX = pose->positionX;
        current->anim.worldPosY = pose->positionY;
        current->anim.worldPosZ = pose->positionZ;
        current->fov = pose->fov;
    }
}

void CameraModeViewfinder_free(CameraObject* camera) {
    GameObject* player;
    GameObject* viewObj;
    GameObject* outBuf[3];

    ((GameObject*)camera->anim.targetObj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    Rcp_SetViewFinderHudEnabled(0);
    viewObj = (GameObject*)camera->anim.targetObj;
    if (viewObj != NULL) {
        viewObj->anim.alpha = 0xff;
        player = Obj_GetPlayerObject();
        if (player == viewObj) {
            Player_GetHeldObject(viewObj, outBuf);
            if (outBuf[0] != NULL) {
                outBuf[0]->anim.alpha = 0xff;
                if (outBuf[0]->anim.alpha == 1) {
                    outBuf[0]->anim.alpha = 0;
                }
            }
        }
    }
    Sfx_StopFromObject(0, SFXTRIG_and_swipe1);
    mm_free(gCameraModeViewfinderState);
    gCameraModeViewfinderState = NULL;
    viewFinderSetZoom(60.0f);
}

void CameraModeViewfinder_update(CameraObject* camera) {
    GameObject* fadeTarget;
    int brightness;
    int exitBlendFinished;
    GameObject* exitTarget;
    GameObject* focus;
    int curveFinished;
    int pitchDelta;
    f32 relativeX;
    f32 relativeY;
    f32 relativeZ;
    f32 relativeDistance;
    GameObject* fadeHeldObject;
    GameObject* exitHeldObject;

    focus = (GameObject*)camera->anim.targetObj;
    getButtonsJustPressed(0);
    firstPersonPlaceCamera(focus, 0);
    switch (gCameraModeViewfinderState->phase) {
    case CAMERA_MODE_VIEWFINDER_PHASE_ENTER_BLEND:
        gCameraModeViewfinderState->phase = firstPersonEnter(camera, (GameObject*)camera->anim.targetObj);
        break;
    case CAMERA_MODE_VIEWFINDER_PHASE_YAW_SETTLE:
        if (Curve_AdvanceAlongPath(&gCameraModeViewfinderState->transitionCurve, 1000.0f) != 0) {
            if (gCameraModeViewfinderState->flags.zoomHudEnabled) {
                Rcp_SetViewFinderHudEnabled(1);
            }
            gCameraModeViewfinderState->phase = CAMERA_MODE_VIEWFINDER_PHASE_ACTIVE;
        }
        camera->anim.rotX = gCameraModeViewfinderState->transitionCurve.sample[0];
        camera->unk13E = 1;
        break;
    case CAMERA_MODE_VIEWFINDER_PHASE_ACTIVE:
        if (gCameraModeViewfinderState->flags.zoomHudEnabled) {
            Rcp_SetViewFinderHudEnabled(1);
        }
        firstPersonDoControls(camera);
        if (getButtonsJustPressed(0) & (PAD_BUTTON_B | PAD_TRIGGER_Z)) {
            buttonDisable(0, PAD_BUTTON_B);
            firstPersonExit(camera);
            Rcp_SetViewFinderHudEnabled(0);
            gCameraModeViewfinderState->phase = CAMERA_MODE_VIEWFINDER_PHASE_EXIT_BLEND;
        }
        camera->unk13E = 0;
        break;
    case CAMERA_MODE_VIEWFINDER_PHASE_EXIT_BLEND:
        curveFinished = Curve_AdvanceAlongPath(&gCameraModeViewfinderState->transitionCurve, 1000.0f);
        camera->anim.rotX = gCameraModeViewfinderState->transitionCurve.sample[0];
        camera->anim.rotY = gCameraModeViewfinderState->transitionCurve.sample[1];
        if (curveFinished != 0) {
            gCameraModeViewfinderState->transitionCurve.px = &gCameraModeViewfinderState->positionXCurve.start;
            gCameraModeViewfinderState->transitionCurve.py = &gCameraModeViewfinderState->positionYCurve.start;
            gCameraModeViewfinderState->transitionCurve.pz = &gCameraModeViewfinderState->positionZCurve.start;
            gCameraModeViewfinderState->transitionCurve.count = 4;
            gCameraModeViewfinderState->transitionCurve.dir = 0;
            gCameraModeViewfinderState->transitionCurve.eval = Curve_EvalHermite;
            gCameraModeViewfinderState->transitionCurve.coeffFn = Curve_BuildHermiteCoeffs;
            curvesMove(&gCameraModeViewfinderState->transitionCurve);
            ((GameObject*)camera->anim.targetObj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            firstPersonZoomOutOnExit(0xf, 0xfe);
            gCameraModeViewfinderState->phase = CAMERA_MODE_VIEWFINDER_PHASE_FADE_BACK;
            if (gCameraModeViewfinderState->flags.sfxEnabled) {
                Sfx_PlayFromObject(0, gCameraModeViewfinderState->flags.zoomHudEnabled ? SFXTRIG_and_missilelaunch
                                                                                       : SFXTRIG_shop_pricedown);
            }
        }
        camera->unk13E = 1;
        break;
    case CAMERA_MODE_VIEWFINDER_PHASE_FADE_BACK:
        camera->anim.worldPosX = gCameraModeViewfinderState->positionXCurve.end;
        camera->anim.worldPosY = gCameraModeViewfinderState->positionYCurve.end;
        camera->anim.worldPosZ = gCameraModeViewfinderState->positionZCurve.end;
        {
            f32 fade = (1.0f - camera->blendProgress) - 0.2f;
            if (fade < 0.0f) {
                fade = 0.0f;
            }
            fade *= 1.25f;
            if (fade > 1.0f) {
                fade = 1.0f;
            }
            brightness = (int)(255.0f * fade);
        }
        fadeTarget = (GameObject*)camera->anim.targetObj;
        if (brightness < 1) {
            brightness = 1;
        }
        if (fadeTarget != NULL) {
            fadeTarget->anim.alpha = brightness;
            if (Obj_GetPlayerObject() == fadeTarget) {
                Player_GetHeldObject(fadeTarget, &fadeHeldObject);
                if (fadeHeldObject != NULL) {
                    fadeHeldObject->anim.alpha = brightness;
                    if (fadeHeldObject->anim.alpha == 1) {
                        fadeHeldObject->anim.alpha = 0;
                    }
                }
            }
        }
        exitBlendFinished = 0;
        if (camera->blendProgress <= 0.0f) {
            exitBlendFinished = 1;
        }
        (*gCameraInterface)
            ->getRelativePosition(camera, &relativeX, &relativeY, &relativeZ, &relativeDistance, 0.0f, 0);
        if (relativeDistance < 10.0f) {
            camera->anim.rotY = 0;
        } else {
            relativeY = camera->anim.worldPosY - (focus->anim.worldPosY + gCameraModeViewfinderTargetHeight[0]);
            pitchDelta = getAngle(relativeY, relativeDistance) & 0xffff;
            pitchDelta -= camera->anim.rotY & 0xffffU;
            if (pitchDelta > 0x8000) {
                pitchDelta = pitchDelta - 0xffff;
            }
            if (pitchDelta < -0x8000) {
                pitchDelta = pitchDelta + 0xffff;
            }
            camera->anim.rotY = *(s16*)&camera->anim.rotY + (int)((f32)pitchDelta * timeDelta) / 8;
        }
        if (exitBlendFinished != 0) {
            (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
            exitTarget = (GameObject*)camera->anim.targetObj;
            if (exitTarget != NULL) {
                exitTarget->anim.alpha = 0xff;
                if (Obj_GetPlayerObject() == exitTarget) {
                    Player_GetHeldObject(exitTarget, &exitHeldObject);
                    if (exitHeldObject != NULL) {
                        exitHeldObject->anim.alpha = 0xff;
                        if (exitHeldObject->anim.alpha == 1) {
                            exitHeldObject->anim.alpha = 0;
                        }
                    }
                }
            }
        }
        camera->unk13E = 1;
        break;
    case CAMERA_MODE_VIEWFINDER_PHASE_IDLE:
        break;
    }
    if (ObjHits_GetPriorityHit((GameObject*)camera->anim.targetObj, 0, 0, 0) != 0) {
        firstPersonExit(camera);
        camera->anim.worldPosX = gCameraModeViewfinderState->positionXCurve.end;
        camera->anim.worldPosY = gCameraModeViewfinderState->positionYCurve.end;
        camera->anim.worldPosZ = gCameraModeViewfinderState->positionZCurve.end;
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0);
    }
    logPrintf(sCameraModeViewfinderYDebugFormat, camera->anim.worldPosY);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   camera->anim.parent);
}

void CameraModeViewfinder_init(CameraObject* camera, int mode, CameraModeViewfinderSettings* settings) {
    GameObject* focus;
    s16 diff;
    s16 absDiff;
    s16 yawDelta;
    f32 dx;
    f32 dz;
    f32 dist;
    f32 spinRate;
    f32 rollRate;
    f32 cosv;
    f32 sinv;
    f32 zero;
    focus = (GameObject*)camera->anim.targetObj;
    if (gCameraModeViewfinderState == NULL) {
        gCameraModeViewfinderState = mmAlloc(sizeof(CameraModeViewfinderState), 0xf, 0);
    }
    memset(gCameraModeViewfinderState, 0, sizeof(CameraModeViewfinderState));
    gCameraModeViewfinderState->radius = settings->radius;
    gCameraModeViewfinderState->height = (f32)(u32)settings->height;
    gCameraModeViewfinderState->yOffset = settings->yOffset;
    gCameraModeViewfinderState->yawSpeed = 0.0f;
    diff = 0x8000 - camera->anim.rotX - focus->anim.rotX;
    if (diff < 0) {
        absDiff = -diff;
    } else {
        absDiff = diff;
    }
    spinRate = diff / 50.0f;
    rollRate = absDiff / 90.0f;
    gCameraModeViewfinderState->transitionCurve.px = &gCameraModeViewfinderState->positionXCurve.start;
    gCameraModeViewfinderState->transitionCurve.py = &gCameraModeViewfinderState->positionYCurve.start;
    gCameraModeViewfinderState->transitionCurve.pz = &gCameraModeViewfinderState->positionZCurve.start;
    gCameraModeViewfinderState->transitionCurve.count = 4;
    gCameraModeViewfinderState->transitionCurve.dir = 0;
    gCameraModeViewfinderState->transitionCurve.eval = Curve_EvalHermite;
    gCameraModeViewfinderState->transitionCurve.coeffFn = Curve_BuildHermiteCoeffs;
    dx = camera->anim.worldPosX - focus->anim.worldPosX;
    dz = camera->anim.worldPosZ - focus->anim.worldPosZ;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist != 0.0f) {
        dx = dx / dist;
        dz = dz / dist;
    }
    firstPersonPlaceCamera(focus, 1);
    cosv = -mathSinf((3.1415927f * focus->anim.rotX) / 32768.0f);
    sinv = -mathCosf((3.1415927f * focus->anim.rotX) / 32768.0f);
    gCameraModeViewfinderState->positionXCurve.start = camera->anim.worldPosX;
    gCameraModeViewfinderState->positionXCurve.end = gCameraModeViewfinderState->cameraPositionX;
    gCameraModeViewfinderState->positionXCurve.startTangent = -dz * spinRate;
    gCameraModeViewfinderState->positionXCurve.endTangent = cosv * rollRate;
    gCameraModeViewfinderState->positionYCurve.start = camera->anim.worldPosY;
    gCameraModeViewfinderState->positionYCurve.end = gCameraModeViewfinderState->cameraPositionY;
    zero = 0.0f;
    gCameraModeViewfinderState->positionYCurve.startTangent = zero;
    gCameraModeViewfinderState->positionYCurve.endTangent = zero;
    gCameraModeViewfinderState->positionZCurve.start = camera->anim.worldPosZ;
    gCameraModeViewfinderState->positionZCurve.end = gCameraModeViewfinderState->cameraPositionZ;
    gCameraModeViewfinderState->positionZCurve.startTangent = dx * spinRate;
    gCameraModeViewfinderState->positionZCurve.endTangent = sinv * rollRate;
    gCameraModeViewfinderState->positionXCurve.startTangent = zero;
    gCameraModeViewfinderState->positionXCurve.endTangent = zero;
    gCameraModeViewfinderState->positionYCurve.startTangent = zero;
    gCameraModeViewfinderState->positionYCurve.endTangent = zero;
    gCameraModeViewfinderState->positionZCurve.startTangent = zero;
    gCameraModeViewfinderState->positionZCurve.endTangent = zero;
    curvesMove(&gCameraModeViewfinderState->transitionCurve);
    yawDelta = camera->anim.rotX -
         (u16)(0x8000 - getAngle(camera->anim.worldPosX - gCameraModeViewfinderState->positionXCurve.end,
                                 camera->anim.worldPosZ - gCameraModeViewfinderState->positionZCurve.end));
    if (yawDelta > 0x8000) {
        yawDelta = yawDelta - 0xffff;
    }
    if (yawDelta < -0x8000) {
        yawDelta = yawDelta + 0xffff;
    }
    gCameraModeViewfinderState->yawCurve.start = yawDelta;
    zero = 0.0f;
    gCameraModeViewfinderState->yawCurve.end = zero;
    gCameraModeViewfinderState->yawCurve.startTangent = zero;
    gCameraModeViewfinderState->yawCurve.endTangent = zero;
    if (gCameraModeViewfinderState->yawCurve.start - gCameraModeViewfinderState->yawCurve.end > 32768.0f ||
        gCameraModeViewfinderState->yawCurve.start - gCameraModeViewfinderState->yawCurve.end < -32768.0f) {
        if (gCameraModeViewfinderState->yawCurve.start < 0.0f) {
            gCameraModeViewfinderState->yawCurve.start += 65535.0f;
        } else if (gCameraModeViewfinderState->yawCurve.end < 0.0f) {
            gCameraModeViewfinderState->yawCurve.end += 65535.0f;
        }
    }
    gCameraModeViewfinderState->pitchCurve.start = camera->anim.rotY;
    zero = 0.0f;
    gCameraModeViewfinderState->pitchCurve.end = zero;
    gCameraModeViewfinderState->pitchCurve.startTangent = zero;
    gCameraModeViewfinderState->pitchCurve.endTangent = zero;
    camera->unk13E = 1;
    if (mainGetBit(GAMEBIT_ITEM_Viewfinder_Got) != 0) {
        gCameraModeViewfinderState->flags.zoomHudEnabled = 1;
    }
    if (mode == 1) {
        gCameraModeViewfinderState->phase = CAMERA_MODE_VIEWFINDER_PHASE_IDLE;
    } else {
        gCameraModeViewfinderState->phase = CAMERA_MODE_VIEWFINDER_PHASE_ENTER_BLEND;
        gCameraModeViewfinderState->flags.sfxEnabled = 1;
        Sfx_PlayFromObject(0, gCameraModeViewfinderState->flags.zoomHudEnabled ? SFXTRIG_and_swipe2
                                                                               : SFXTRIG_shop_priceup);
    }
    gCameraModeViewfinderState->flags.zoomSfxPlaying = 0;
    gCameraModeViewfinderState->clampedPositionY = gCameraModeViewfinderState->cameraPositionY;
}

void CameraModeViewfinder_release(void) {
}

void CameraModeViewfinder_initialise(void) {
}

CameraModeViewfinderDescriptor gCameraModeViewfinderDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeViewfinder_initialise,
    CameraModeViewfinder_release,
    NULL,
    CameraModeViewfinder_init,
    CameraModeViewfinder_update,
    CameraModeViewfinder_free,
    CameraModeViewfinder_copyToCurrent,
    NULL,
};
