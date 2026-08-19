/*
 * DLL 77 / 0x4D - NPC conversation camera mode.
 */
#include "main/dll/dll_004D_cameramodenpcspeak.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_0042_cameramodenormal.h"
#include "main/frame_timing.h"
#include "main/maketex_api.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"
#include "main/obj_query.h"

CameraModeNpcSpeakState* gCameraModeNpcSpeakState;
f32 gCameraModeNpcSpeakMode6AnchorLerpScale;

f32 gCameraModeNpcSpeakMode6TargetHeightOffset = 30.0f;
f32 gCameraModeNpcSpeakMode6LookAtHeightOffset = 30.0f;
f32 gCameraModeNpcSpeakMode6LookAtYScale = 0.2f;
f32 gCameraModeNpcSpeakMode6LookAtXZScale = 0.2f;
f32 gCameraModeNpcSpeakMode6DistanceOffset = 4.0f;
int gCameraModeNpcSpeakMode6OrbitAngleOffset = 10000;
f32 gCameraModeNpcSpeakMode3DistanceOffset = 2.0f;
f32 gCameraModeNpcSpeakMode3PitchScale = 0.09f;

void CameraModeNpcSpeak_solveOrbitPosition(GameObject* target, f32* outX, f32* outY, f32* outZ) {
    CameraModeNpcSpeakState* state = gCameraModeNpcSpeakState;
    f32 dx;
    f32 dz;
    f32 distance;
    u16 angle;
    f32 sinValue;
    f32 cosValue;

    dx = target->anim.worldPosX - state->anchorX;
    dz = target->anim.worldPosZ - state->anchorZ;
    distance = sqrtf(dx * dx + dz * dz);
    angle = getAngle(dx, dz);

    {
        f32 anchorLerpScale = gCameraModeNpcSpeakState->anchorLerpScale;
        dx *= anchorLerpScale;
        dz *= anchorLerpScale;
    }
    dx += state->anchorX;
    dz += state->anchorZ;

    sinValue = mathSinf(3.1415927f * (f32)(s32)(angle + gCameraModeNpcSpeakState->orbitAngleOffset) / 32768.0f);
    cosValue = mathCosf(3.1415927f * (f32)(s32)(angle + gCameraModeNpcSpeakState->orbitAngleOffset) / 32768.0f);

    if (distance < gCameraModeNpcSpeakState->minDistance) {
        distance = gCameraModeNpcSpeakState->minDistance;
    }
    distance += gCameraModeNpcSpeakState->distanceOffset;

    *outX = sinValue * distance + dx;
    *outY = (target->anim.worldPosY + gCameraModeNpcSpeakState->targetHeightOffset) -
            0.03f * ((30.0f + target->anim.worldPosY) - state->anchorY);
    *outZ = cosValue * distance + dz;
}

void CameraModeNpcSpeak_copyToCurrent(void) {
}

void CameraModeNpcSpeak_free(void) {
    mm_free(gCameraModeNpcSpeakState);
    gCameraModeNpcSpeakState = NULL;
    Rcp_DisableBlurFilter();
}

void CameraModeNpcSpeak_update(CameraObject* camera) {
    CameraModeNpcSpeakState* state;
    GameObject* target = (GameObject*)camera->anim.targetObj;
    f32 cameraOffsetX, cameraOffsetZ, cameraOffsetY;
    f32 lookAtOffsetX, lookAtOffsetY, lookAtOffsetZ;

    if (target == NULL) {
        return;
    }
    state = gCameraModeNpcSpeakState;
    if (state->mode == 6) {
        state->orbitAngleOffset = (s32)((f32)state->orbitAngleVelocity * timeDelta + state->orbitAngleOffset);
        if (gCameraModeNpcSpeakState->orbitAngleVelocity > 0 && gCameraModeNpcSpeakState->orbitAngleOffset > 0xd6d8) {
            gCameraModeNpcSpeakState->orbitAngleOffset = 0xd6d8;
        } else if (gCameraModeNpcSpeakState->orbitAngleVelocity < 0 &&
                   gCameraModeNpcSpeakState->orbitAngleOffset < -0xd6d8) {
            gCameraModeNpcSpeakState->orbitAngleOffset = -0xd6d8;
        }
        CameraModeNpcSpeak_solveOrbitPosition(target, &gCameraModeNpcSpeakState->cameraX,
                                              &gCameraModeNpcSpeakState->cameraY, &gCameraModeNpcSpeakState->cameraZ);
    }
    camera->anim.worldPosX = gCameraModeNpcSpeakState->cameraX;
    camera->anim.worldPosY = gCameraModeNpcSpeakState->cameraY;
    camera->anim.worldPosZ = gCameraModeNpcSpeakState->cameraZ;
    lookAtOffsetX = target->anim.worldPosX - state->anchorX;
    lookAtOffsetY = (target->anim.worldPosY + gCameraModeNpcSpeakState->lookAtHeightOffset) - state->anchorY;
    lookAtOffsetZ = target->anim.worldPosZ - state->anchorZ;
    lookAtOffsetX *= gCameraModeNpcSpeakState->lookAtXZScale;
    lookAtOffsetY *= gCameraModeNpcSpeakState->lookAtYScale;
    lookAtOffsetZ *= gCameraModeNpcSpeakState->lookAtXZScale;
    if (gCameraModeNpcSpeakState->mode == 3) {
        camera->anim.rotY = (s16)(s32)getAngle(gCameraModeNpcSpeakMode3PitchScale * lookAtOffsetY,
                                               sqrtf(lookAtOffsetX * lookAtOffsetX + lookAtOffsetZ * lookAtOffsetZ));
    }
    lookAtOffsetX += state->anchorX;
    lookAtOffsetY += state->anchorY;
    lookAtOffsetZ += state->anchorZ;
    cameraOffsetX = camera->anim.worldPosX - lookAtOffsetX;
    cameraOffsetY = camera->anim.worldPosY - lookAtOffsetY;
    cameraOffsetZ = camera->anim.worldPosZ - lookAtOffsetZ;
    camera->anim.rotX = (s16)(0x8000 - getAngle(cameraOffsetX, cameraOffsetZ));
    if (gCameraModeNpcSpeakState->mode != 3) {
        camera->anim.rotY =
            (s16)(s32)getAngle(cameraOffsetY, sqrtf(cameraOffsetX * cameraOffsetX + cameraOffsetZ * cameraOffsetZ));
    }
    turnOnBlurFilter(state->anchorX, state->anchorY, state->anchorZ, 1, 0);
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

CameraModeNpcSpeakDescriptor gCameraModeNpcSpeakDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeNpcSpeak_initialise,
    CameraModeNpcSpeak_release,
    NULL,
    CameraModeNpcSpeak_init,
    CameraModeNpcSpeak_update,
    CameraModeNpcSpeak_free,
    CameraModeNpcSpeak_copyToCurrent,
};

void CameraModeNpcSpeak_init(CameraObject* camera, int unused, CameraModeNpcSpeakInitParams* params) {
    u16 cameraYaw, targetYaw;
    int mode = 0;
    int orbitAngleOffset;
    int positiveOrbitDelta, negativeOrbitDelta;
    GameObject* focusedNpc;
    f32 cameraPos[3];
    CamcontrolTraceWork traceWork;

    if (gCameraModeNpcSpeakState == NULL) {
        gCameraModeNpcSpeakState = (CameraModeNpcSpeakState*)mmAlloc(sizeof(CameraModeNpcSpeakState), 15, 0);
    }

    if (params != NULL) {
        gCameraModeNpcSpeakState->anchorX = params->anchorX;
        gCameraModeNpcSpeakState->anchorY = params->anchorY;
        gCameraModeNpcSpeakState->anchorZ = params->anchorZ;
        mode = params->mode;
    } else {
        GameObject* anchorNpc = getFocusedNpc();
        f32* anchorPosition;
        if (anchorNpc == NULL) {
            gCameraModeNpcSpeakState->anchorX = 0.0f;
            gCameraModeNpcSpeakState->anchorY = 0.0f;
            gCameraModeNpcSpeakState->anchorZ = 0.0f;
        }
        anchorPosition = (f32*)anchorNpc->anim.hitVolumeTransforms;
        if (anchorPosition == NULL) {
            gCameraModeNpcSpeakState->anchorX = 0.0f;
            gCameraModeNpcSpeakState->anchorY = 0.0f;
            gCameraModeNpcSpeakState->anchorZ = 0.0f;
        }
        gCameraModeNpcSpeakState->anchorX = anchorPosition[0];
        gCameraModeNpcSpeakState->anchorY = anchorPosition[1];
        gCameraModeNpcSpeakState->anchorZ = anchorPosition[2];
    }
    if (mode == 4) {
        mode = randomGetRange(0, 3);
    }
    {
        f32 valueA, valueB;
        gCameraModeNpcSpeakState->unk20 = 0;
        gCameraModeNpcSpeakState->mode = mode;
        gCameraModeNpcSpeakState->unk14 = 0.0f;
        valueA = 25.0f;
        gCameraModeNpcSpeakState->targetHeightOffset = valueA;
        gCameraModeNpcSpeakState->lookAtHeightOffset = 30.0f;
        gCameraModeNpcSpeakState->lookAtYScale = 0.9f;
        valueB = 0.5f;
        gCameraModeNpcSpeakState->anchorLerpScale = valueB;
        gCameraModeNpcSpeakState->lookAtXZScale = valueB;
        gCameraModeNpcSpeakState->minDistance = valueA;
    }
    gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0x2000, 0x2c00);

    switch (mode) {
    case 0:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        break;
    case 1:
        gCameraModeNpcSpeakState->distanceOffset = 5.0f;
        break;
    case 2:
        gCameraModeNpcSpeakState->distanceOffset = 40.0f;
        break;
    case 5:
        gCameraModeNpcSpeakState->distanceOffset = 80.0f;
        break;
    case 3:
        gCameraModeNpcSpeakState->distanceOffset = gCameraModeNpcSpeakMode3DistanceOffset;
        gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0xf00, 0x1f00);
        gCameraModeNpcSpeakState->lookAtHeightOffset = 0.0f;
        break;
    case 6:
        gCameraModeNpcSpeakState->targetHeightOffset = gCameraModeNpcSpeakMode6TargetHeightOffset;
        gCameraModeNpcSpeakState->lookAtHeightOffset = gCameraModeNpcSpeakMode6LookAtHeightOffset;
        gCameraModeNpcSpeakState->anchorLerpScale = gCameraModeNpcSpeakMode6AnchorLerpScale;
        gCameraModeNpcSpeakState->lookAtYScale = gCameraModeNpcSpeakMode6LookAtYScale;
        gCameraModeNpcSpeakState->orbitAngleOffset = gCameraModeNpcSpeakMode6OrbitAngleOffset;
        gCameraModeNpcSpeakState->lookAtXZScale = gCameraModeNpcSpeakMode6LookAtXZScale;
        gCameraModeNpcSpeakState->distanceOffset = gCameraModeNpcSpeakMode6DistanceOffset;
        gCameraModeNpcSpeakState->orbitAngleVelocity = 0xb6;
        gCameraModeNpcSpeakState->minDistance = 0.0f;
        break;
    case 7:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        gCameraModeNpcSpeakState->targetHeightOffset = 35.0f;
        gCameraModeNpcSpeakState->anchorLerpScale = 0.1f;
        gCameraModeNpcSpeakState->lookAtXZScale = 0.3f;
        gCameraModeNpcSpeakState->lookAtYScale = 0.6f;
        gCameraModeNpcSpeakState->orbitAngleOffset = randomGetRange(0x1800, 0x1c00);
        break;
    case 8:
        gCameraModeNpcSpeakState->distanceOffset = 15.0f;
        gCameraModeNpcSpeakState->lookAtHeightOffset = 10.0f;
        break;
    default:
        gCameraModeNpcSpeakState->distanceOffset = 20.0f;
        break;
    }

    cameraYaw = (u16)getAngle(camera->anim.worldPosX - gCameraModeNpcSpeakState->anchorX,
                              camera->anim.worldPosZ - gCameraModeNpcSpeakState->anchorZ);
    targetYaw =
        (u16)getAngle(((GameObject*)camera->anim.targetObj)->anim.worldPosX - gCameraModeNpcSpeakState->anchorX,
                      ((GameObject*)camera->anim.targetObj)->anim.worldPosZ - gCameraModeNpcSpeakState->anchorZ);
    {
        CameraModeNpcSpeakState* state = gCameraModeNpcSpeakState;
        orbitAngleOffset = state->orbitAngleOffset;
        positiveOrbitDelta = (targetYaw + orbitAngleOffset) - cameraYaw;
        if (positiveOrbitDelta > 0x8000) {
            positiveOrbitDelta -= 0xffff;
        }
        if (positiveOrbitDelta < -0x8000) {
            positiveOrbitDelta += 0xffff;
        }
        negativeOrbitDelta = (targetYaw - orbitAngleOffset) - cameraYaw;
        if (negativeOrbitDelta > 0x8000) {
            negativeOrbitDelta -= 0xffff;
        }
        if (negativeOrbitDelta < -0x8000) {
            negativeOrbitDelta += 0xffff;
        }
        if (positiveOrbitDelta < 0) {
            positiveOrbitDelta = -positiveOrbitDelta;
        }
        if (negativeOrbitDelta < 0) {
            negativeOrbitDelta = -negativeOrbitDelta;
        }
        if (negativeOrbitDelta < positiveOrbitDelta) {
            state->orbitAngleOffset = -orbitAngleOffset;
            gCameraModeNpcSpeakState->orbitAngleVelocity = -0x80;
        }
    }

    if (mode != 6 && mode != 7 && (focusedNpc = getFocusedNpc()) != NULL) {
        GameObject* target = (GameObject*)camera->anim.targetObj;
        s16 targetYawDelta;
        int relativeYawDelta;
        targetYawDelta = (s16)(targetYaw - (u16)target->anim.rotX);
        if (targetYawDelta > 0x8000) {
            targetYawDelta = (s16)(targetYawDelta - 0xffff);
        }
        if (targetYawDelta < -0x8000) {
            targetYawDelta = (s16)(targetYawDelta + 0xffff);
        }
        relativeYawDelta = targetYawDelta - (u16)(s16)Obj_GetYawDeltaToObject(target, focusedNpc, 0);
        if (relativeYawDelta > 0x8000) {
            relativeYawDelta -= 0xffff;
        }
        if (relativeYawDelta < -0x8000) {
            relativeYawDelta += 0xffff;
        }
        if ((relativeYawDelta > 0x1000 && gCameraModeNpcSpeakState->orbitAngleOffset > 0) ||
            (relativeYawDelta < -0x1000 && gCameraModeNpcSpeakState->orbitAngleOffset < 0)) {
            gCameraModeNpcSpeakState->orbitAngleOffset = -gCameraModeNpcSpeakState->orbitAngleOffset;
        }
    }

    CameraModeNpcSpeak_solveOrbitPosition((GameObject*)camera->anim.targetObj, &cameraPos[0], &cameraPos[1],
                                          &cameraPos[2]);
    camcontrol_traceMove(&camera->anim.worldPosX, cameraPos, &gCameraModeNpcSpeakState->cameraX, (u8*)&traceWork, 3,
                         1, 1, 4.0f);
}

void CameraModeNpcSpeak_release(void) {
}

void CameraModeNpcSpeak_initialise(void) {
}
