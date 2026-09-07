/*
 * DLL 74 / 0x4A - ship-battle camera mode.
 */
#include "main/dll/dll_004A_cameramodeshipbattle.h"

#include "dlls/objects/601_SB_Cloudrun.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"

CameraModeShipBattleState* gCameraModeShipBattleState;

void CameraModeShipBattle_copyToCurrent(void) {
}

void CameraModeShipBattle_free(void) {
    mm_free(gCameraModeShipBattleState);
    gCameraModeShipBattleState = NULL;
}

void CameraModeShipBattle_update(CameraObject* camera) {
    f32 valueA;
    f32 valueB;
    f32 valueC;
    f32 lateralStep;
    CameraModeShipBattleState* state;
    int targetMode = 0;
    GameObject* focus = (GameObject*)camera->anim.targetObj;
    if (focus != NULL) {
        targetMode = SB_CloudRunner_getTargetMode(focus);
    }
    state = gCameraModeShipBattleState;
    if (targetMode != state->targetMode) {
        if (targetMode == 2) {
            valueA = 220.0f;
        } else {
            valueA = 120.0f;
        }
        if (targetMode != 2 && targetMode != 5) {
            valueB = 75.0f;
            valueC = 0.0f;
        } else {
            valueB = 105.0f;
            valueC = state->smoothedYOffset;
        }
        state->targetMode = targetMode;
        gCameraModeShipBattleState->lateralDelta = valueA - gCameraModeShipBattleState->targetLateralOffset;
        gCameraModeShipBattleState->startLateralOffset = gCameraModeShipBattleState->targetLateralOffset;
        gCameraModeShipBattleState->verticalDelta = valueB - (gCameraModeShipBattleState->verticalOffset + valueC);
        gCameraModeShipBattleState->startVerticalOffset = gCameraModeShipBattleState->verticalOffset;
        gCameraModeShipBattleState->blendProgress = 0.0f;
    }
    valueB = gCameraModeShipBattleState->blendProgress;
    valueA = 1.0f;
    if (valueB < valueA) {
        gCameraModeShipBattleState->blendProgress = 0.005f * timeDelta + valueB;
        if (gCameraModeShipBattleState->blendProgress > valueA) {
            gCameraModeShipBattleState->blendProgress = valueA;
        }
        gCameraModeShipBattleState->targetLateralOffset =
            gCameraModeShipBattleState->blendProgress * gCameraModeShipBattleState->lateralDelta +
            gCameraModeShipBattleState->startLateralOffset;
        gCameraModeShipBattleState->verticalOffset =
            gCameraModeShipBattleState->blendProgress * gCameraModeShipBattleState->verticalDelta +
            gCameraModeShipBattleState->startVerticalOffset;
    }
    if (targetMode != 2 && targetMode != 5) {
        gCameraModeShipBattleState->smoothedZOffset =
            -((f32)focus->anim.rotZ / 3367.0f * timeDelta - gCameraModeShipBattleState->smoothedZOffset);
        gCameraModeShipBattleState->smoothedYOffset =
            -((f32)focus->anim.rotY / 1365.0f * timeDelta - gCameraModeShipBattleState->smoothedYOffset);
        state = gCameraModeShipBattleState;
        valueC = 0.02f;
        valueB = state->smoothedZOffset;
        valueA = valueC * valueB;
        state->smoothedZOffset = -(valueA * timeDelta - valueB);
        valueB = gCameraModeShipBattleState->smoothedYOffset;
        valueA = valueC * valueB;
        gCameraModeShipBattleState->smoothedYOffset = -(valueA * timeDelta - valueB);
        camera->anim.worldPosY = gCameraModeShipBattleState->smoothedYOffset +
                                 (focus->anim.worldPosY + gCameraModeShipBattleState->verticalOffset);
    } else {
        gCameraModeShipBattleState->smoothedZOffset =
            -((f32)focus->anim.rotZ / 3367.0f * timeDelta - gCameraModeShipBattleState->smoothedZOffset);
        gCameraModeShipBattleState->smoothedYOffset =
            -((f32)focus->anim.rotY / 1365.0f * timeDelta - gCameraModeShipBattleState->smoothedYOffset);
        state = gCameraModeShipBattleState;
        valueC = 0.02f;
        valueB = state->smoothedZOffset;
        valueA = valueC * valueB;
        state->smoothedZOffset = -(valueA * timeDelta - valueB);
        valueB = gCameraModeShipBattleState->smoothedYOffset;
        valueA = valueC * valueB;
        gCameraModeShipBattleState->smoothedYOffset = -(valueA * timeDelta - valueB);
        camera->anim.worldPosY = gCameraModeShipBattleState->smoothedYOffset +
                                 (focus->anim.worldPosY + gCameraModeShipBattleState->verticalOffset);
    }
    valueA = 98.0f + focus->anim.worldPosX;
    camera->anim.worldPosX = valueA + gCameraModeShipBattleState->lateralOffset;
    camera->anim.worldPosZ = focus->anim.worldPosZ + gCameraModeShipBattleState->smoothedZOffset;
    camera->anim.rotY = 0x708;
    camera->anim.rotX = 0x4000;
    camera->anim.rotZ = (s16)(-focus->anim.rotZ >> 3);
    camera->fov = 40.0f;
    state = gCameraModeShipBattleState;
    lateralStep = (state->targetLateralOffset - state->lateralOffset) / 100.0f;
    if (lateralStep > 3.0f) {
        lateralStep = 3.0f;
    } else if (lateralStep < -3.0f) {
        lateralStep = -3.0f;
    }
    lateralStep *= timeDelta;
    state->lateralOffset += lateralStep;
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY, camera->anim.worldPosZ,
                                   &camera->anim.localPosX, &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (GameObject*)camera->anim.parent);
}

void CameraModeShipBattle_init(void) {
    f32 value;
    u8 zero;

    if (gCameraModeShipBattleState == NULL) {
        gCameraModeShipBattleState = (CameraModeShipBattleState*)mmAlloc(sizeof(CameraModeShipBattleState), 0xF, 0);
    }
    value = 0.0f;
    gCameraModeShipBattleState->smoothedZOffset = 0.0f;
    gCameraModeShipBattleState->smoothedYOffset = value;
    gCameraModeShipBattleState->lateralOffset = 100.0f;
    value = 120.0f;
    gCameraModeShipBattleState->startLateralOffset = 120.0f;
    gCameraModeShipBattleState->targetLateralOffset = value;
    gCameraModeShipBattleState->blendProgress = 1.0f;
    zero = 0;
    gCameraModeShipBattleState->targetMode = zero;
    value = 75.0f;
    gCameraModeShipBattleState->startVerticalOffset = 75.0f;
    gCameraModeShipBattleState->verticalOffset = value;
    return;
}

void CameraModeShipBattle_release(void) {
}

void CameraModeShipBattle_initialise(void) {
}

CameraModeShipBattleDescriptor gCameraModeShipBattleDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeShipBattle_initialise,
    CameraModeShipBattle_release,
    NULL,
    CameraModeShipBattle_init,
    CameraModeShipBattle_update,
    CameraModeShipBattle_free,
    CameraModeShipBattle_copyToCurrent,
    NULL,
};
