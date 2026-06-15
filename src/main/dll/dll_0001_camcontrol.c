#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/savegame.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/objlib.h"
#include "main/pad.h"
#include "main/voxmaps.h"
#include "string.h"

extern void objShowButtonGlow(void* obj, f32 intensity, int mode);
extern int dll_19_func1B();
extern int isTalkingToNpc();
extern int gameTextFn_80134be8(void);
extern f32 fn_8014C5D0(int obj);
extern f32 fn_80183204(int obj);
extern f32 sqrtf(f32 x);

extern u8 gCamcontrolStateStorage[];
extern CamcontrolBaddieControlInterface** gBaddieControlInterface;
extern f32 timeDelta;
extern f32 gCamcontrolSavedFocusWorldZ;
extern f32 gCamcontrolSavedFocusWorldY;
extern f32 gCamcontrolSavedFocusWorldX;
extern f32 gCamcontrolSavedFocusLocalZ;
extern f32 gCamcontrolSavedFocusLocalY;
extern f32 gCamcontrolSavedFocusLocalX;
extern s8 lbl_803DD4CB;
extern undefined4 lbl_803DD4CC;

static inline CamcontrolBaddieControlInterface* camcontrol_GetBaddieControlInterface(void)
{
    return *gBaddieControlInterface;
}

static inline uint camcontrol_GetTargetKind(CamcontrolTargetObject* target)
{
    return target->targetSetup[target->targetSetupIndex].targetKind & CAMCONTROL_TARGET_KIND_MASK;
}

void camcontrol_updateTargetFeedback(void)
{
    uint targetKind;
    s16 objType;
    float alphaScale;
    CamcontrolTargetObject* target;
    ObjAnimComponent* reticle;
    u8 buttonPressed;
    int result;
    uint buttons;
    uint buttonMask;
    f32 targetDistance;

    target = (CamcontrolTargetObject*)CAMCONTROL_CAMERA->currentTarget;
    reticle = &gCamcontrolTargetReticle->anim;
    buttonPressed = false;
    if (reticle == NULL)
    {
        return;
    }
    result = gameTextFn_80134be8();
    if (result != 0)
    {
        return;
    }
    if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', target != NULL))
    {
        targetKind = CAMCONTROL_CAMERA->targetKind;
        if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON)
        {
            Sfx_PlayFromObject(0, 0x3ff);
            objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 2);
        }
        else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
            (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B))
        {
            Sfx_PlayFromObject(0, 0x402);
            objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 3);
        }
        else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED)
        {
            Sfx_PlayFromObject(0, SFXsc_spotfox01);
            objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 1);
        }
    }
    if (target != NULL)
    {
        target->targetFlags = target->targetFlags | CAMCONTROL_TARGET_FLAG_RETICLE_TOUCHING;
        buttons = getButtonsJustPressed(0);
        buttonMask = CAMCONTROL_TARGET_BUTTON_PRIMARY;
        targetKind = camcontrol_GetTargetKind(target);
        if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
            (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B))
        {
            buttonMask = CAMCONTROL_TARGET_BUTTON_CONTEXT;
        }
        if ((buttons & buttonMask) != 0)
        {
            buttonPressed = true;
        }
        if ((target->targetFlags & CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT) == 0)
        {
            if (buttonPressed)
            {
                target->targetFlags = target->targetFlags | CAMCONTROL_TARGET_FLAG_INPUT_PRESSED;
            }
        }
        else if ((buttonPressed) && (result = isTalkingToNpc(), result == 0))
        {
            Sfx_PlayFromObject(0, SFXsc_snort04);
        }
    }
    if (gCamcontrolTargetState == '\0')
    {
        if (gCamcontrolNormalizedMin >= reticle->currentMoveProgress)
        {
            if (target != NULL)
            {
                CAMCONTROL_CAMERA->targetReticleFocus = (int)target;
                CAMCONTROL_CAMERA->targetKind = camcontrol_GetTargetKind(target);
                gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE;
                gCamcontrolTargetChanged = true;
            }
            else
            {
                CAMCONTROL_CAMERA->targetReticleFocus = 0;
            }
        }
        else
        {
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)reticle, gCamcontrolReticleFadeOutStep, timeDelta,
                                                                        (ObjAnimEventList*)0x0);
        }
    }
    else if (((uint)CAMCONTROL_CAMERA->targetReticleFocus == (uint)target) ||
        (reticle->currentMoveProgress < gCamcontrolNormalizedMax))
    {
        ObjAnim_AdvanceCurrentMove(gCamcontrolReticleFadeInStep, timeDelta, (int)reticle,
                                   (ObjAnimEventList*)0x0);
    }
    else
    {
        gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE;
        if (target == NULL)
        {
            targetKind = CAMCONTROL_CAMERA->targetKind;
            if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON)
            {
                Sfx_PlayFromObject(0, 0x400);
            }
            else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
                (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B))
            {
                Sfx_PlayFromObject(0, 0x401);
            }
            else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED)
            {
                Sfx_PlayFromObject(0, SFXsc_spotfox02);
            }
        }
        else
        {
            ObjAnim_SetMoveProgress(gCamcontrolNormalizedMin, reticle);
        }
    }
    result = Obj_IsObjectAlive(CAMCONTROL_CAMERA->targetReticleFocus);
    if (result == 0)
    {
        CAMCONTROL_CAMERA->targetReticleFocus = 0;
    }
    if ((gCamcontrolTargetState != CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE) ||
        ((uint)CAMCONTROL_CAMERA->targetReticleFocus == 0))
        goto LAB_80102ab4;
    target = (CamcontrolTargetObject*)CAMCONTROL_CAMERA->targetReticleFocus;
    if ((target->targetFlags & CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT) != 0)
    {
        CAMCONTROL_CAMERA->targetFlags =
            CAMCONTROL_CAMERA->targetFlags | CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT;
    }
    else
    {
        CAMCONTROL_CAMERA->targetFlags =
            CAMCONTROL_CAMERA->targetFlags & ~CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT;
    }
    objType = target->objType;
    switch (objType)
    {
    case 0x11:
    case 0xd8:
    case 0x13a:
    case 0x251:
    case 0x25d:
    case 0x281:
    case 0x369:
    case 0x3fe:
    case 0x427:
    case 0x457:
    case 0x458:
    case 0x4ac:
    case 0x4d7:
    case 0x58b:
    case 0x5b7:
    case 0x5b8:
    case 0x5b9:
    case 0x5e1:
    case 0x613:
    case 0x642:
    case 0x6a2:
    case 0x6a3:
    case 0x6a4:
    case 0x6a5:
    case 0x842:
    case 0x84b:
    case 0x851:
        targetDistance = fn_8014C5D0((int)target);
        break;
    case 0x3de:
    case 0x49f:
        targetDistance = fn_80183204((int)target);
        break;
    case 0x31:
        targetDistance = gCamcontrolNormalizedMax;
        break;
    default:
        result = dll_19_func1B((int)target);
        if (result == 0)
        {
            targetDistance = gCamcontrolNormalizedMax;
        }
        else
        {
            targetDistance =
                camcontrol_GetBaddieControlInterface()->getTargetReticleDistance((int)target);
        }
        break;
    }
    if (targetDistance <= gCamcontrolNormalizedMin && CAMCONTROL_CAMERA->targetDistance > gCamcontrolNormalizedMin)
    {
        objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 4);
    }
    else if (targetDistance <= gCamcontrolTargetDistanceTier1 && CAMCONTROL_CAMERA->targetDistance > gCamcontrolTargetDistanceTier1)
    {
        objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 4);
    }
    else if (targetDistance <= gCamcontrolTargetDistanceTier2 && CAMCONTROL_CAMERA->targetDistance > gCamcontrolTargetDistanceTier2)
    {
        objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 4);
    }
    else if (targetDistance <= gCamcontrolTargetDistanceTier3 && CAMCONTROL_CAMERA->targetDistance > gCamcontrolTargetDistanceTier3)
    {
        objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 4);
    }
    CAMCONTROL_CAMERA->targetDistance = targetDistance;
LAB_80102ab4:
    alphaScale = gCamcontrolReticleAlphaScale * reticle->currentMoveProgress;
    if (alphaScale < gCamcontrolNormalizedMin)
    {
        alphaScale = gCamcontrolNormalizedMin;
    }
    else if (gCamcontrolReticleAlphaScale < alphaScale)
    {
        alphaScale = gCamcontrolReticleAlphaScale;
    }
    reticle->alpha = (int)alphaScale;
    gCamcontrolReticleSpin = CAMCONTROL_RETICLE_SPIN_STEP;
    reticle->rotX = (short)(int)(gCamcontrolReticleSpinStepPerFrame * timeDelta + (float)reticle->rotX);
    return;
}

int Camera_isZooming(void)
{
    return CAMCONTROL_CAMERA->blendProgress > gCamcontrolNormalizedMin;
}

void Camera_setTargetReticleOverride(int target)
{
    CAMCONTROL_CAMERA->targetReticleOverride = target;
}

void Camera_setTarget(int x)
{
    CAMCONTROL_CAMERA->overrideTarget = x;
    CAMCONTROL_CAMERA->currentTarget = x;
}

int Camera_getTarget(void)
{
    return CAMCONTROL_CAMERA->currentTarget;
}

int Camera_getOverrideTarget(void)
{
    return CAMCONTROL_CAMERA->overrideTarget;
}

void camcontrol_getRelativePosition(f32 heightOffset, int targetObj, float* outX, float* outY,
                                    float* outZ, float* outDistanceXZ, int useLocalPosition)
{
    ObjAnimComponent* focusObj;
    ObjAnimComponent* target;

    focusObj = CAMCONTROL_CAMERA->focusObj;
    target = (ObjAnimComponent*)targetObj;
    if (useLocalPosition != 0)
    {
        *outX = target->localPosX - focusObj->localPosX;
        *outY = target->localPosY - (focusObj->localPosY + heightOffset);
        *outZ = target->localPosZ - focusObj->localPosZ;
    }
    else
    {
        *outX = target->worldPosX - focusObj->worldPosX;
        *outY = target->worldPosY - (focusObj->worldPosY + heightOffset);
        *outZ = target->worldPosZ - focusObj->worldPosZ;
    }
    if (outDistanceXZ != (float*)0x0)
    {
        *outDistanceXZ = *outX * *outX + *outZ * *outZ;
        if (*outDistanceXZ > gCamcontrolNormalizedMin)
        {
            *outDistanceXZ = sqrtf(*outDistanceXZ);
        }
        if (*outDistanceXZ < gCamcontrolMinTargetDistance)
        {
            *outDistanceXZ = *(f32*)&gCamcontrolMinTargetDistance;
        }
    }
    return;
}

void camcontrol_initialise(float* dst, f32 numerator, f32 denominator, f32 minValue, f32 y, f32 z)
{
    f32 x;

    x = numerator / denominator;
    if (x < minValue)
    {
        x = minValue;
    }
    dst[0] = x;
    dst[1] = y;
    dst[2] = gCamcontrolNormalizedMin;
    dst[3] = z;
}

void Camera_moveBy(f32 x, f32 y, f32 z)
{
    CAMCONTROL_CAMERA->localX += x;
    CAMCONTROL_CAMERA->localY += y;
    CAMCONTROL_CAMERA->localZ += z;
}

void Camera_overridePos(f32 x, f32 y, f32 z)
{
    CAMCONTROL_CAMERA->overrideWorldPosPending = 1;
    CAMCONTROL_CAMERA->overrideWorldX = x;
    CAMCONTROL_CAMERA->overrideWorldY = y;
    CAMCONTROL_CAMERA->overrideWorldZ = z;
}

void Camera_setFocus(void* target)
{
    if (target == CAMCONTROL_CAMERA->focusObj)
    {
        return;
    }
    CAMCONTROL_CAMERA->focusObj = target;
}

void camcontrol_loadTriggeredCamAction(int triggerType, int actionNo, int triggerMode)
{
    int handlerCount;
    int handlerIndex;
    CamcontrolHandlerEntry* defaultHandler;
    register CamcontrolHandlerEntry** handlerEntry;
    int blendFrames;
    CamcontrolTriggeredAction* camAction;
    int actionOffset;
    CamcontrolQueuedActionParam triggerType1Param;
    CamcontrolQueuedActionParam triggerType2Param;

    switch (triggerType)
    {
    case CAMCONTROL_TRIGGER_KIND_LOAD_ACTION:
        break;
    case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1:
        triggerType1Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
        triggerType1Param.noBlendFlag = actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND;
        CAMCONTROL_CAMERA->blendCurveMode = 1;
        if (triggerType1Param.noBlendFlag != 0)
        {
            blendFrames = 0;
        }
        else
        {
            blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
        }
        Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE1, 1, 0, CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                       &triggerType1Param, blendFrames, CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2:
        triggerType2Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
        triggerType2Param.noBlendFlag = (byte)(actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND);
        if (triggerType2Param.noBlendFlag != 0)
        {
            blendFrames = 0;
        }
        else
        {
            blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
        }
        Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE2, 1, 0, CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                       &triggerType2Param, blendFrames, CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION:
        Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, 0, CAMCONTROL_DEFAULT_BLEND_FRAMES,
                       CAMCONTROL_QUEUE_SENTINEL);
        return;
    case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET:
        Camera_setMode(actionNo + CAMCONTROL_ACTION_DEFAULT, 1, 0, 0, 0,
                       CAMCONTROL_DEFAULT_BLEND_FRAMES, CAMCONTROL_QUEUE_SENTINEL);
        return;
    }
    if (actionNo != CAMCONTROL_ACTION_NO_NONE)
    {
        if (actionNo == CAMCONTROL_ACTION_NO_NONE)
        {
            camAction = (CamcontrolTriggeredAction*)0x0;
        }
        else
        {
            camAction = (CamcontrolTriggeredAction*)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_HEAP, 0);
            if (camAction != (CamcontrolTriggeredAction*)0x0)
            {
                actionOffset = (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE;
                getTabEntry(camAction, CAMCONTROL_ACTION_FILE_ID, actionOffset, CAMCONTROL_ACTION_RECORD_SIZE);
            }
        }
        if (camAction == (CamcontrolTriggeredAction*)0x0)
        {
            return;
        }
        camAction->triggerMode = triggerMode;
        SaveGame_setCamActionNo((short)actionNo);
        if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
                    ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
                ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
            ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2))
        {
            handlerIndex = 0;
            handlerEntry = gCamcontrolHandlerEntries;
            for (handlerCount = (int)gCamcontrolHandlerCount; 0 < handlerCount;
                 handlerCount = handlerCount - 1)
            {
                if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT)
                {
                    defaultHandler = gCamcontrolHandlerEntries[handlerIndex];
                    goto LAB_80102f3c;
                }
                handlerEntry = handlerEntry + 1;
                handlerIndex++;
            }
            defaultHandler = NULL;
        LAB_80102f3c:
            defaultHandler->handler->vtable->actionCallback(camAction, CAMCONTROL_ACTION_RECORD_SIZE);
        }
        else
        {
            switch (camAction->actionKind)
            {
            case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
            default:
                Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 2, CAMCONTROL_ACTION_RECORD_SIZE,
                               camAction, 0, CAMCONTROL_QUEUE_SENTINEL);
                break;
            case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
                Camera_setMode(CAMCONTROL_ACTION_TRIGGERED, 1, 2, CAMCONTROL_ACTION_RECORD_SIZE,
                               camAction, 0, CAMCONTROL_QUEUE_SENTINEL);
                break;
            }
        }
        mm_free(camAction);
    }
    else
    {
        OSReport(sCamcontrolTriggeredCamActionLoadWarning, actionNo);
        camAction = (CamcontrolTriggeredAction*)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_HEAP, 0);
        if (camAction != (CamcontrolTriggeredAction*)0x0)
        {
            getTabEntry(camAction, CAMCONTROL_ACTION_FILE_ID, CAMCONTROL_FALLBACK_ACTION_FILE_OFFSET,
                        CAMCONTROL_ACTION_RECORD_SIZE);
        }
        if (camAction == (CamcontrolTriggeredAction*)0x0)
        {
            return;
        }
        camAction->triggerMode = triggerMode;
        SaveGame_setCamActionNo(CAMCONTROL_FALLBACK_ACTION_NO);
        if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
                    ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
                ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
            ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2))
        {
            handlerIndex = 0;
            handlerEntry = gCamcontrolHandlerEntries;
            for (handlerCount = (int)gCamcontrolHandlerCount; 0 < handlerCount;
                 handlerCount = handlerCount - 1)
            {
                if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT)
                {
                    defaultHandler = gCamcontrolHandlerEntries[handlerIndex];
                    goto LAB_80102f3c_b;
                }
                handlerEntry = handlerEntry + 1;
                handlerIndex++;
            }
            defaultHandler = NULL;
        LAB_80102f3c_b:
            defaultHandler->handler->vtable->actionCallback(camAction, CAMCONTROL_ACTION_RECORD_SIZE);
        }
        else
        {
            switch (camAction->actionKind)
            {
            case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
            default:
                Camera_setMode(CAMCONTROL_ACTION_DEFAULT, 0, 2, CAMCONTROL_ACTION_RECORD_SIZE,
                               camAction, 0, CAMCONTROL_QUEUE_SENTINEL);
                break;
            case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
                Camera_setMode(CAMCONTROL_ACTION_TRIGGERED, 1, 2, CAMCONTROL_ACTION_RECORD_SIZE,
                               camAction, 0, CAMCONTROL_QUEUE_SENTINEL);
                break;
            }
        }
        mm_free(camAction);
    }
    return;
}

CamcontrolTriggeredAction* Camera_getCamActionsBinEntry(int actionNo)
{
    CamcontrolTriggeredAction* camAction;

    if (actionNo == CAMCONTROL_ACTION_NO_NONE)
    {
        return 0;
    }
    camAction = mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_HEAP, 0);
    if (camAction != 0)
    {
        getTabEntry(camAction, CAMCONTROL_ACTION_FILE_ID,
                    (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_RECORD_SIZE);
    }
    return camAction;
}

void camcontrol_release(void* camAction, int recordSize)
{
    CamcontrolHandlerEntry* currentHandler;

    currentHandler = gCamcontrolCurrentHandler;
    if (currentHandler != NULL)
    {
        currentHandler->handler->vtable->actionCallback(camAction, recordSize);
    }
}

void camcontrol_queueSavedAction(int blendFrames, u8 queueMode)
{
    if (gCamcontrolSavedActionId != CAMCONTROL_SAVED_ACTION_NONE)
    {
        Camera_setMode(gCamcontrolSavedActionId, gCamcontrolSavedActionPriority,
                       gCamcontrolSavedActionStartFlags, 0, 0, blendFrames, queueMode);
    }
    return;
}

void Camera_setMode(s32 actionId, int priority, int startFlags, int dataSize, void* data,
                    int blendFrames, u8 queueMode)
{
    if (gCamcontrolQueuedActionData != (void*)0x0)
    {
        mm_free(gCamcontrolQueuedActionData);
        gCamcontrolQueuedActionData = (void*)0x0;
        gCamcontrolQueuedActionPending = 0;
    }
    gCamcontrolQueuedActionId = actionId;
    gCamcontrolQueuedActionBlendFrames = blendFrames;
    if (data != (void*)0x0)
    {
        gCamcontrolQueuedActionData = mmAlloc(dataSize, CAMCONTROL_ACTION_HEAP, 0);
        memcpy(gCamcontrolQueuedActionData, data, dataSize);
    }
    else
    {
        gCamcontrolQueuedActionData = (void*)0x0;
    }
    if (actionId == CAMCONTROL_ACTION_DEFAULT)
    {
        gCamcontrolQueuedActionPriority = 0;
    }
    else
    {
        gCamcontrolQueuedActionPriority = (s8)priority;
    }
    gCamcontrolQueuedActionStartFlags = (s8)startFlags;
    gCamcontrolQueuedActionPending = 1;
    gCamcontrolQueuedActionMode = queueMode;
    return;
}

void Camera_update(void)
{
    ObjAnimComponent* focus;
    u8 textActive;
    CamcontrolTargetObject* target;

    if (gameTextFn_80134be8() != 0)
    {
        textActive = 1;
    }
    else
    {
        textActive = 0;
    }
    focus = CAMCONTROL_CAMERA->focusObj;
    if (focus == (ObjAnimComponent*)0x0)
    {
        CAMCONTROL_CAMERA->currentTarget = 0;
        CAMCONTROL_CAMERA->overrideTarget = 0;
    }
    else
    {
        gCamcontrolSavedFocusLocalX = focus->localPosX;
        gCamcontrolSavedFocusLocalY = focus->localPosY;
        gCamcontrolSavedFocusLocalZ = focus->localPosZ;
        gCamcontrolSavedFocusWorldX = focus->worldPosX;
        gCamcontrolSavedFocusWorldY = focus->worldPosY;
        gCamcontrolSavedFocusWorldZ = focus->worldPosZ;
        camcontrol_updateMoveAverage(CAMCONTROL_CAMERA, focus);
        if (CAMCONTROL_CAMERA->overrideWorldPosPending != 0)
        {
            focus->worldPosX = CAMCONTROL_CAMERA->overrideWorldX;
            focus->worldPosY = CAMCONTROL_CAMERA->overrideWorldY;
            focus->worldPosZ = CAMCONTROL_CAMERA->overrideWorldZ;
            Obj_TransformWorldPointToLocal(focus->worldPosX, focus->worldPosY, focus->worldPosZ,
                                           &focus->localPosX, &focus->localPosY, &focus->localPosZ,
                                           (u32)focus->parent);
            CAMCONTROL_CAMERA->overrideWorldPosPending = 0;
        }
        if (CAMCONTROL_CAMERA->localFrameObj != focus->parent)
        {
            Obj_TransformLocalPointToWorld(CAMCONTROL_CAMERA->localX, CAMCONTROL_CAMERA->localY, CAMCONTROL_CAMERA->localZ,
                                           &CAMCONTROL_CAMERA->worldX, &CAMCONTROL_CAMERA->worldY, &CAMCONTROL_CAMERA->worldZ,
                                           (u32)CAMCONTROL_CAMERA->localFrameObj);
            Obj_TransformLocalPointToWorld(CAMCONTROL_CAMERA->prevLocalX, CAMCONTROL_CAMERA->prevLocalY, CAMCONTROL_CAMERA->prevLocalZ,
                                           &CAMCONTROL_CAMERA->prevWorldX, &CAMCONTROL_CAMERA->prevWorldY, &CAMCONTROL_CAMERA->prevWorldZ,
                                           (u32)CAMCONTROL_CAMERA->localFrameObj);
            Obj_TransformWorldPointToLocal(CAMCONTROL_CAMERA->worldX, CAMCONTROL_CAMERA->worldY, CAMCONTROL_CAMERA->worldZ,
                                           &CAMCONTROL_CAMERA->localX, &CAMCONTROL_CAMERA->localY, &CAMCONTROL_CAMERA->localZ,
                                           (u32)focus->parent);
            Obj_TransformWorldPointToLocal(CAMCONTROL_CAMERA->prevWorldX, CAMCONTROL_CAMERA->prevWorldY, CAMCONTROL_CAMERA->prevWorldZ,
                                           &CAMCONTROL_CAMERA->prevLocalX, &CAMCONTROL_CAMERA->prevLocalY, &CAMCONTROL_CAMERA->prevLocalZ,
                                           (u32)focus->parent);
            CAMCONTROL_CAMERA->localFrameObj = focus->parent;
        }
        if (focus->parent != (void*)0x0)
        {
            focus->rotX += ((ObjAnimComponent*)focus->parent)->rotX;
        }
        camcontrol_applyQueuedAction();
        if (gCamcontrolCurrentHandler != 0)
        {
            gCamcontrolCurrentHandler->handler->vtable->update((void*)pCamera);
            Obj_TransformLocalPointToWorld(CAMCONTROL_CAMERA->localX, CAMCONTROL_CAMERA->localY, CAMCONTROL_CAMERA->localZ,
                                           &CAMCONTROL_CAMERA->worldX, &CAMCONTROL_CAMERA->worldY, &CAMCONTROL_CAMERA->worldZ,
                                           (u32)CAMCONTROL_CAMERA->localFrameObj);
            camcontrol_applyState(CAMCONTROL_CAMERA);
        }
        camcontrol_applyQueuedAction();
        if (textActive == 0)
        {
            if (CAMCONTROL_CAMERA->overrideTarget == 0u)
            {
                target = camcontrol_findBestTarget(CAMCONTROL_CAMERA, focus);
                CAMCONTROL_CAMERA->currentTarget = (int)target;
            }
            else
            {
                CAMCONTROL_CAMERA->currentTarget = CAMCONTROL_CAMERA->overrideTarget;
            }
        }
        CAMCONTROL_CAMERA->prevLocalX = CAMCONTROL_CAMERA->localX;
        CAMCONTROL_CAMERA->prevLocalY = CAMCONTROL_CAMERA->localY;
        CAMCONTROL_CAMERA->prevLocalZ = CAMCONTROL_CAMERA->localZ;
        CAMCONTROL_CAMERA->prevWorldX = CAMCONTROL_CAMERA->worldX;
        CAMCONTROL_CAMERA->prevWorldY = CAMCONTROL_CAMERA->worldY;
        CAMCONTROL_CAMERA->prevWorldZ = CAMCONTROL_CAMERA->worldZ;
        CAMCONTROL_CAMERA->frameFlags = 0;
        focus->localPosX = gCamcontrolSavedFocusLocalX;
        focus->localPosY = gCamcontrolSavedFocusLocalY;
        focus->localPosZ = gCamcontrolSavedFocusLocalZ;
        focus->worldPosX = gCamcontrolSavedFocusWorldX;
        focus->worldPosY = gCamcontrolSavedFocusWorldY;
        focus->worldPosZ = gCamcontrolSavedFocusWorldZ;
        if (focus->parent != (void*)0x0)
        {
            focus->rotX -= ((ObjAnimComponent*)focus->parent)->rotX;
        }
    }
    return;
}

void* Camera_getDefaultHandlerEntry(void)
{
    int i;

    i = 0;
    for (; i < gCamcontrolHandlerCount; i++)
    {
        if (gCamcontrolHandlerEntries[i]->actionId == CAMCONTROL_ACTION_DEFAULT)
        {
            return gCamcontrolHandlerEntries[i];
        }
    }
    return NULL;
}

void* Camera_GetFollowPos(void)
{
    return gCamcontrolCurrentHandler;
}

u32 Camera_getMode(void) { return gCamcontrolActiveActionId; }
u32 Camera_get(void) { return (u32)pCamera; }

void Camera_init(void* focus, f32 x, f32 y, f32 z)
{
    memset((void*)pCamera, 0, sizeof(CamcontrolCameraState));
    CAMCONTROL_CAMERA->localX = x;
    CAMCONTROL_CAMERA->localY = y;
    CAMCONTROL_CAMERA->localZ = z;
    CAMCONTROL_CAMERA->worldX = x;
    CAMCONTROL_CAMERA->worldY = y;
    CAMCONTROL_CAMERA->worldZ = z;
    CAMCONTROL_CAMERA->prevLocalX = x;
    CAMCONTROL_CAMERA->prevLocalY = y;
    CAMCONTROL_CAMERA->prevLocalZ = z;
    CAMCONTROL_CAMERA->prevWorldX = x;
    CAMCONTROL_CAMERA->prevWorldY = y;
    CAMCONTROL_CAMERA->prevWorldZ = z;
    CAMCONTROL_CAMERA->focusObj = focus;
    CAMCONTROL_CAMERA->fovY = gCamcontrolDefaultFovY;
    gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE;
}

void Camera_release(void)
{
    voxmaps_resetLoadedMaps();
    lbl_803DD4CB = -1;
}

void Camera_initialise(void)
{
    pCamera = gCamcontrolStateStorage;
    memset((void*)pCamera, 0, sizeof(CamcontrolCameraState));
    voxmaps_initialise();
    gCamcontrolActiveActionId = -1;
    gCamcontrolCurrentHandlerIndex = -1;
    gCamcontrolQueuedActionId = -1;
    lbl_803DD4CC = 0;
    lbl_803DD4CB = -1;
    gCamcontrolTargetClassMask = 0xffff;
}
