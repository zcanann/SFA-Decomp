/*
 * DLL 73 / 0x49 - combat camera mode.
 */
#include "main/dll/dll_0049_cameramodecombat.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/pad.h"
#include "main/camera.h"
#include "main/camera_interface.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/DR/dr_types.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"

enum CameraModeCombatRomDefNo {
    CAMERA_MODE_COMBAT_DIM_BOSS_ROM_DEF_NO = 0x200,
};

enum CameraModeCombatConstants {
    CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES = 0x1E,
    CAMERA_MODE_COMBAT_LETTERBOX_TARGET_OFFSET = 0x30
};

#define CAMERA_MODE_COMBAT_HIT_VOLUME_BLEND_STEP  0.02f
#define CAMERA_MODE_COMBAT_TARGET_HEIGHT          20.0f
#define CAMERA_MODE_COMBAT_DIM_BOSS_HEIGHT_BONUS  20.0f
#define CAMERA_MODE_COMBAT_TARGET_LEAD_SCALE      0.35f
#define CAMERA_MODE_COMBAT_LOOK_TARGET_Y_OFFSET   5.0f
#define CAMERA_MODE_COMBAT_DEFAULT_FOLLOW_DISTANCE 200.0f

s32 gCameraModeCombatPreviousYawDelta;
CameraModeCombatState* gCameraModeCombatState;

void CameraModeCombat_evaluateTargetPosition(CameraObject* camera, f32* outX, f32* outY, f32* outZ, f32* targetY) {
    ObjHitVolumeRuntimeTransform* hitVolumes;
    GameObject* target;
    u8 prevIdx;
    GameObject* focus;
    CameraModeCombatState* state;
    f32 lim;
    f32 t;

    target = (GameObject*)camera->targetObj;
    focus = (GameObject*)camera->anim.targetObj;
    hitVolumes = target->anim.hitVolumeTransforms;
    if ((u32)target->hitVolumeIndex != (prevIdx = (state = gCameraModeCombatState)->hitVolumeBlendTargetIndex)) {
        state->hitVolumeBlendStartIndex = prevIdx;
        gCameraModeCombatState->hitVolumeBlendWeight = 1.0f;
    }
    t = gCameraModeCombatState->hitVolumeBlendWeight;
    lim = 0.0f;
    if (t > lim) {
        gCameraModeCombatState->hitVolumeBlendWeight = t - CAMERA_MODE_COMBAT_HIT_VOLUME_BLEND_STEP * timeDelta;
        t = gCameraModeCombatState->hitVolumeBlendWeight;
        if (gCameraModeCombatState->hitVolumeBlendWeight < lim) {
            gCameraModeCombatState->hitVolumeBlendWeight = lim;
            gCameraModeCombatState->hitVolumeBlendStartIndex = target->hitVolumeIndex;
        }
        {
            u8 ci = gCameraModeCombatState->hitVolumeBlendStartIndex;
            float bx;
            float by;
            float bz;
            float dx = hitVolumes[ci].centerX - (bx = hitVolumes[target->hitVolumeIndex].centerX);
            float dy = hitVolumes[ci].centerY - (by = hitVolumes[target->hitVolumeIndex].centerY);
            float dz = hitVolumes[ci].centerZ - (bz = hitVolumes[target->hitVolumeIndex].centerZ);
            dx *= gCameraModeCombatState->hitVolumeBlendWeight;
            dy *= gCameraModeCombatState->hitVolumeBlendWeight;
            dz *= gCameraModeCombatState->hitVolumeBlendWeight;
            dx += bx;
            dy += by;
            dz += bz;
            *outX = dx - focus->anim.worldPosX;
            *outY = dy - *targetY;
            *outZ = dz - focus->anim.worldPosZ;
        }
    } else {
        *outX = hitVolumes[target->hitVolumeIndex].centerX - focus->anim.worldPosX;
        *outY = hitVolumes[target->hitVolumeIndex].centerY - *targetY;
        *outZ = hitVolumes[target->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
    }
    gCameraModeCombatState->hitVolumeBlendTargetIndex = target->hitVolumeIndex;
}

void CameraModeCombat_copyToCurrent(void) {
}

void CameraModeCombat_free(CameraObject* camera) {
    if (camera->targetObj != NULL) {
        (*gCameraInterface)->setTarget(0);
    }
    mm_free(gCameraModeCombatState);
    gCameraModeCombatState = NULL;
    Rcp_DisableBlurFilter();
    camera->smoothingFlags.b0 = 0;
}

static void CameraModeCombat_traceMove(f32* prevPos, CameraObject* camera, CamcontrolTraceWork* traceWork) {
    camcontrol_traceMove(prevPos, &camera->anim.worldPosX, &camera->anim.worldPosX, (u8*)traceWork, 3, 1, 1, 4.0f);
}

void CameraModeCombat_update(CameraObject* camera) {
    Vec movement;
    f32 prevZ;
    f32 prevY;
    f32 prevX;
    f32 dy;
    f32 ty;
    f32 dx;
    f32 dz;
    Vec desiredPosition;
    CamcontrolTraceWork traceWork;
    Camera* currentView = Camera_GetCurrent();
    GameObject* target;
    ObjHitVolumeRuntimeTransform* hitVolumes;
    GameObject* focus;
    f32 dist;
    f32 px;
    f32 py;
    f32 pz;
    f32 range;
    f32 step;
    f32 zoom;
    f32 mag;
    f32 speed;
    f32 lim;
    f32 sinAngle;
    f32 cosAngle;
    f32 t;
    f32 fa;
    f32 fb;
    int ang;
    int diff;
    u32 binAngleDelta;
    s16 classId;

    if (gCameraModeCombatState->invalidTarget != 0) {
        if (camera->targetObj != NULL) {
            if (((GameObject*)camera->targetObj)->anim.resetHitboxFlags & 0x40) {
                return;
            }
            if (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) {
                return;
            }
            (*gCameraInterface)->setTarget(0);
        }
        (*gCameraInterface)
            ->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES,
                      CAMCONTROL_QUEUE_SENTINEL);
    } else {
        focus = (GameObject*)camera->anim.targetObj;
        if (focus->anim.classId == 1 && playerCanUseCombatTargeting(focus) == 0) {
            if (camera->targetObj != NULL) {
                if (((GameObject*)camera->targetObj)->anim.resetHitboxFlags & 0x40) {
                    return;
                }
                if (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) {
                    return;
                }
                (*gCameraInterface)->setTarget(0);
            }
            (*gCameraInterface)
                ->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES,
                          CAMCONTROL_QUEUE_SENTINEL);
        } else {
            target = (GameObject*)camera->targetObj;
            if (target == NULL || (target->objectFlags & OBJECT_OBJFLAG_FREED) ||
                (target->anim.resetHitboxFlags & 0x28)) {
                if (target != NULL) {
                    if (target->anim.resetHitboxFlags & 0x40) {
                        return;
                    }
                    if (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) {
                        return;
                    }
                    (*gCameraInterface)->setTarget(0);
                }
                (*gCameraInterface)
                    ->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES,
                              CAMCONTROL_QUEUE_SENTINEL);
            } else {
                hitVolumes = target->anim.hitVolumeTransforms;
                if (hitVolumes != NULL) {
                    range = (f32)(s32)((u32)target->anim.modelInstance->hitVolumes[0].bounds[1] << 2);
                    if (((u16)getButtonsJustPressed(0) & PAD_BUTTON_B) && playerIsNotAttacking(focus) != 0) {
                        if (camera->targetObj != NULL) {
                            if (((GameObject*)camera->targetObj)->anim.resetHitboxFlags & 0x40) {
                                return;
                            }
                            if (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) {
                                return;
                            }
                            (*gCameraInterface)->setTarget(0);
                        }
                        (*gCameraInterface)
                            ->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES,
                                      CAMCONTROL_QUEUE_SENTINEL);
                    } else {
                        ty = CAMERA_MODE_COMBAT_TARGET_HEIGHT + focus->anim.worldPosY;
                        classId = target->anim.classId;
                        if (classId == 0x1c || classId == 0x6d || classId == 0x2a) {
                            if (target->anim.romDefNo == CAMERA_MODE_COMBAT_DIM_BOSS_ROM_DEF_NO) {
                                ty += CAMERA_MODE_COMBAT_DIM_BOSS_HEIGHT_BONUS;
                            }
                            if (target->anim.modelInstance->hitVolumeCount > 1) {
                                CameraModeCombat_evaluateTargetPosition(camera, &dx, &dy, &dz, &ty);
                            } else {
                                dx = hitVolumes[target->hitVolumeIndex].centerX - focus->anim.worldPosX;
                                dy = hitVolumes[target->hitVolumeIndex].centerY - ty;
                                dz = hitVolumes[target->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
                            }
                        } else {
                            ty = CAMERA_MODE_COMBAT_TARGET_HEIGHT + focus->anim.worldPosY;
                            dx = hitVolumes[target->hitVolumeIndex].centerX - focus->anim.worldPosX;
                            dy = hitVolumes[target->hitVolumeIndex].centerY - ty;
                            dz = hitVolumes[target->hitVolumeIndex].centerZ - focus->anim.worldPosZ;
                        }
                        fa = dx * dx;
                        fb = dz * dz;
                        dist = sqrtf(fa + fb);
                        camera->letterboxTargetOffset = CAMERA_MODE_COMBAT_LETTERBOX_TARGET_OFFSET;
                        camera->letterboxStep = 1;
                        if (dist > range) {
                            if (camera->targetObj != NULL) {
                                if (((GameObject*)camera->targetObj)->anim.resetHitboxFlags & 0x40) {
                                    return;
                                }
                                if (camera->targetFlags & CAMCONTROL_CAMERA_TARGET_FLAG_FORCE_COMBAT) {
                                    return;
                                }
                                (*gCameraInterface)->setTarget(0);
                            }
                            (*gCameraInterface)
                                ->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL,
                                          CAMERA_MODE_COMBAT_EXIT_BLEND_FRAMES, CAMCONTROL_QUEUE_SENTINEL);
                        } else {
                            cameraGetPrevPos2(focus, &prevX, &prevY, &prevZ);
                            px = CAMERA_MODE_COMBAT_TARGET_LEAD_SCALE * dx + focus->anim.worldPosX;
                            py = CAMERA_MODE_COMBAT_LOOK_TARGET_Y_OFFSET + ty;
                            pz = CAMERA_MODE_COMBAT_TARGET_LEAD_SCALE * dz + focus->anim.worldPosZ;
                            ang = getAngle(dx, dz);
                            binAngleDelta = (ang & 0xffff) + 0x8000;
                            diff = (int)camera->anim.rotX - ((0x8000 - binAngleDelta) & 0xffff);
                            if (diff > 0x8000) {
                                diff -= 0xffff;
                            }
                            if (diff < -0x8000) {
                                diff += 0xffff;
                            }
                            if (diff > 9000) {
                                step = interpolate((f32)(s32)(diff - 9000), 1.0f / 12.0f, timeDelta);
                                camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX - step);
                            } else if (diff < -9000) {
                                step = interpolate((f32)(s32)(diff + 9000), 1.0f / 12.0f, timeDelta);
                                camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX - step);
                            }
                            if (diff < 3000 && diff > 0) {
                                if (gCameraModeCombatPreviousYawDelta < 3000 && diff < 1000 &&
                                    gCameraModeCombatPreviousYawDelta > diff) {
                                    step = interpolate((f32)(s32)(-diff - 3000), 0.0078125f, timeDelta);
                                    camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX + step);
                                } else {
                                    step = interpolate((f32)(s32)(3000 - diff), 0.0078125f, timeDelta);
                                    camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX + step);
                                }
                            } else if (diff > -3000 && diff < 0) {
                                if (gCameraModeCombatPreviousYawDelta > -3000 && diff > -1000 &&
                                    gCameraModeCombatPreviousYawDelta < diff) {
                                    step = interpolate((f32)(s32)(3000 - diff), 0.0078125f, timeDelta);
                                    camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX + step);
                                } else {
                                    step = interpolate((f32)(s32)(-diff - 3000), 0.0078125f, timeDelta);
                                    camera->anim.rotX = (s16)((f32)(s32)camera->anim.rotX + step);
                                }
                            }
                            gCameraModeCombatPreviousYawDelta = diff;
                            if (diff < 0) {
                                diff = -diff;
                            }
                            if (diff > 9000) {
                                diff = 9000;
                            }
                            step = (f32)(s32)(9000 - diff);
                            zoom = step / 9000.0f;
                            step = interpolate(35.0f - gCameraModeCombatState->heightOffset, 0.04f, timeDelta);
                            gCameraModeCombatState->heightOffset += step;
                            fb = 1.0f - zoom;
                            fb = 0.8f + fb;
                            step = interpolate(fb / 1.8f - gCameraModeCombatState->zoomOffset, 0.1f, timeDelta);
                            gCameraModeCombatState->zoomOffset += step;
                            sinAngle = mathSinf((3.1415927f * (f32)(s32)camera->anim.rotX) / 32768.0f);
                            cosAngle = mathCosf((3.1415927f * (f32)(s32)camera->anim.rotX) / 32768.0f);
                            t = gCameraModeCombatState->followDistance * sinAngle;
                            desiredPosition.x = px + t;
                            t = gCameraModeCombatState->followDistance * cosAngle;
                            desiredPosition.z = pz - t;
                            dy *= 0.6f;
                            dy = ty - dy;
                            dy += gCameraModeCombatState->heightOffset;
                            step = interpolate(camera->anim.worldPosY - dy, 0.05f, timeDelta);
                            desiredPosition.y = camera->anim.worldPosY - step;
                            PSVECSubtract(&desiredPosition, &camera->anim.worldPos, &movement);
                            mag = PSVECMag(&movement);
                            if (mag > 0.0f) {
                                PSVECNormalize(&movement, &movement);
                            }
                            if (camera->blendProgress <= 0.0f) {
                                fa = focus->anim.previousWorldPosX - focus->anim.worldPosX;
                                fb = focus->anim.previousWorldPosZ - focus->anim.worldPosZ;
                                speed = sqrtf(fa * fa + fb * fb);
                                lim = speed * (3.0f * timeDelta);
                                if ((f64)lim < 0.5) {
                                    lim = 0.5f;
                                }
                                if (mag < 0.0f) {
                                    mag = 0.0f;
                                } else if (mag > lim) {
                                    mag = lim;
                                }
                            }
                            PSVECScale(&movement, &movement, (mag < 0.0f) ? 0.0f : ((mag > 20.0f) ? 20.0f : mag));
                            PSVECAdd(&camera->anim.worldPos, &movement, &camera->anim.worldPos);
                            CameraModeCombat_traceMove(&prevX, camera, &traceWork);
                            t = 0.1f * dz + focus->anim.worldPosZ;
                            fb = currentView->x - (0.1f * dx + focus->anim.worldPosX);
                            dy = currentView->y - py;
                            fa = currentView->z - t;
                            t = sqrtf(fb * fb + fa * fa);
                            ang = getAngle(dy, t) & 0xffff;
                            binAngleDelta = ang - ((int)camera->anim.rotY & 0xffffU);
                            if ((int)binAngleDelta > 0x8000) {
                                binAngleDelta -= 0xffff;
                            }
                            if ((int)binAngleDelta < -0x8000) {
                                binAngleDelta += 0xffff;
                            }
                            step = interpolate((f32)(s32)binAngleDelta, 0.125f, timeDelta);
                            camera->anim.rotY = (s16)((f32)(s32)camera->anim.rotY + step);
                            fa = 10.0f + dist;
                            if (fa < 70.0f) {
                                fa = 70.0f;
                            }
                            if (fa > 150.0f) {
                                fa = 150.0f;
                            }
                            fa -= gCameraModeCombatState->followDistance;
                            step = powfBitEstimate(0.04f, timeDelta);
                            fa *= step;
                            if (fa > 5.0f * timeDelta) {
                                fa = 5.0f * timeDelta;
                            } else if (fa < -5.0f * timeDelta) {
                                fa = -5.0f * timeDelta;
                            }
                            gCameraModeCombatState->followDistance += fa;
                            turnOnBlurFilter(target->anim.worldPosX, target->anim.worldPosY, target->anim.worldPosZ, 1,
                                             0);
                            if (camera->blendProgress == 0.0f) {
                                camera->smoothingFlags.b0 = 1;
                            }
                            Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                                           camera->anim.worldPosZ, &camera->anim.localPosX,
                                                           &camera->anim.localPosY, &camera->anim.localPosZ,
                                                           (GameObject*)camera->anim.parent);
                        }
                    }
                }
            }
        }
    }
}

void CameraModeCombat_init(CameraObject* camera, u32 unused, GameObject** targetPtr) {
    f32 dx;
    f32 dz;
    ObjHitVolumeRuntimeTransform* hitVolume;
    GameObject* target;
    GameObject* focus;

    camera->targetObj = *targetPtr;
    focus = (GameObject*)camera->anim.targetObj;
    if (gCameraModeCombatState == NULL) {
        gCameraModeCombatState = (CameraModeCombatState*)mmAlloc(sizeof(CameraModeCombatState), 0xf, 0);
    }
    dx = 0.0f;
    gCameraModeCombatState->heightOffset = 0.0f;
    gCameraModeCombatState->zoomOffset = 1.0f;
    gCameraModeCombatState->invalidTarget = 0;
    gCameraModeCombatState->unk11 = 0;
    gCameraModeCombatState->hitVolumeBlendStartIndex = 1;
    gCameraModeCombatState->hitVolumeBlendTargetIndex = 1;
    gCameraModeCombatState->hitVolumeBlendWeight = dx;
    if (focus->anim.classId != 1) {
        gCameraModeCombatState->invalidTarget = 1;
    } else {
        target = (GameObject*)camera->targetObj;
        if (target == NULL) {
            gCameraModeCombatState->invalidTarget = 1;
        } else {
            if (target->anim.hitVolumeTransforms == NULL) {
                dx = focus->anim.worldPosX - target->anim.worldPosX;
                dz = focus->anim.worldPosZ - target->anim.worldPosZ;
            } else {
                hitVolume = &target->anim.hitVolumeTransforms[target->hitVolumeIndex];
                dx = hitVolume->centerX - focus->anim.worldPosX;
                dz = hitVolume->centerZ - focus->anim.worldPosZ;
            }
            if (target->anim.classId != 0x6d) {
                gCameraModeCombatState->followDistance = sqrtf(dx * dx + dz * dz);
            } else {
                gCameraModeCombatState->followDistance = CAMERA_MODE_COMBAT_DEFAULT_FOLLOW_DISTANCE;
            }
            gCameraModeCombatState->unk10 = 0;
        }
    }
    return;
}

void CameraModeCombat_release(void) {
}

void CameraModeCombat_initialise(void) {
}

CameraModeCombatDescriptor gCameraModeCombatDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeCombat_initialise,
    CameraModeCombat_release,
    NULL,
    CameraModeCombat_init,
    CameraModeCombat_update,
    CameraModeCombat_free,
    CameraModeCombat_copyToCurrent,
    NULL,
};
