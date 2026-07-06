/*
 * camcontrol (DLL 0x0001) - the global gameplay camera controller.
 *
 * Owns the single camera state record (pCamera / CAMCONTROL_CAMERA) and
 * drives it each frame from Camera_update: it caches the focus object's
 * local/world position, optionally overrides the world position, keeps
 * the camera's local frame in sync with the focus object's parent, runs
 * the active handler's update vtable callback, applies queued actions,
 * and (when no game text is up) picks the current target.
 *
 * camcontrol_updateTargetFeedback runs the lock-on / context-action
 * reticle: it plays the acquire/lose SFX per target kind, glows the
 * A-button, fades the reticle in/out via its ObjAnim move progress, and
 * picks a per-objType reticle distance (with a baddie-control-interface
 * fallback) to pulse the button glow as the target nears.
 *
 * camcontrol_loadTriggeredCamAction loads a triggered cam action record
 * from the CAM .bin/.tab (CAMCONTROL_ACTION_FILE_ID) and dispatches it
 * through Camera_setMode or the default handler's actionCallback.
 *
 * Target kinds, action ids, trigger kinds, reticle states and the
 * camera/target flag bits are named in dll_0001_camcontrol.h.
 */
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
#include "main/dll/dll_0105_largecrate.h"
#include "main/audio/sfx_trigger_ids.h"

extern void camcontrol_updateVerticalBounds(void);

extern void CameraModeNormal_func0A(void);

extern void camslide_update(void);

extern void firstperson_updatePitch(void);

extern void firstperson_updatePosition(void);

extern void firstperson_loadSettings(void);
extern void CameraModeStaffAnim_copyToCurrent_nop(void);
extern void CameraModeBike_copyToCurrent(void);
extern void CameraModeViewfinder_copyToCurrent(void);
extern void CameraModeDebug_copyToCurrent_nop(void);
extern void CameraModeStatic_copyToCurrent_nop(void);
extern void CameraModeTestStrength_copyToCurrent_nop(void);

extern void CameraModeNormal_free(void);
extern void camcontrol_releasePathState(void);
extern void CameraModeBike_free(void);
extern void CameraModeViewfinder_free(void);
extern void CameraModeDebug_free(void);
extern void CameraModeStatic_free(void);
extern void CameraModeTestStrength_free(void);

extern void camstatic_update(void);
extern void camclimb_update(void);
extern void CameraModeBike_update(void);
extern void CameraModeViewfinder_update(void);
extern void CameraModeDebug_update(void);
extern void CameraModeStatic_update(void);
extern void CameraModeTestStrength_update(void);

extern void pathcam_loadSettings(void);
extern void CameraModeStaffAnim_init(void);
extern void CameraModeBike_init(void);
extern void CameraModeViewfinder_init(void);
extern void CameraModeDebug_init(void);
extern void CameraModeStatic_init(void);
extern void CameraModeTestStrength_init(void);

extern void camcontrol_releaseModeSettings(void);
extern void CameraModeStaffAnim_release(void);
extern void CameraModeBike_release(void);
extern void CameraModeViewfinder_release(void);
extern void CameraModeDebug_release_nop(void);
extern void CameraModeStatic_release(void);
extern void CameraModeTestStrength_release(void);

extern void camcontrol_initialiseModeSettings(void);
extern void CameraModeStaffAnim_initialise(void);
extern void CameraModeBike_initialise(void);
extern void CameraModeViewfinder_initialise(void);
extern void CameraModeDebug_initialise_nop(void);
extern void CameraModeStatic_initialise(void);
extern void CameraModeTestStrength_initialise(void);
extern void objShowButtonGlow(void* obj, f32 intensity, int mode);
extern int dll_19_func1B(int p); /* nonzero = obj is baddie-control managed (use its reticle distance) */
extern f32 fn_8014C5D0(register int obj); /* target reticle distance for the enemy objType group */
 /* target reticle distance for the largecrate objType group */
extern f32 sqrtf(f32 x);
u8 gCamcontrolStateStorage[0x148];
extern CamcontrolBaddieControlInterface** gBaddieControlInterface;
extern f32 timeDelta;
extern f32 gCamcontrolSavedFocusWorldZ;
extern f32 gCamcontrolSavedFocusWorldY;
extern f32 gCamcontrolSavedFocusWorldX;
extern f32 gCamcontrolSavedFocusLocalZ;
extern f32 gCamcontrolSavedFocusLocalY;
extern f32 gCamcontrolSavedFocusLocalX;
extern s8 lbl_803DD4CB;
extern u32 lbl_803DD4CC;

static inline CamcontrolBaddieControlInterface* camcontrol_GetBaddieControlInterface(void)
{
    return *gBaddieControlInterface;
}

static inline u32 camcontrol_GetTargetKind(CamcontrolTargetObject* target)
{
    return target->targetSetup[target->targetSetupIndex].targetKind & CAMCONTROL_TARGET_KIND_MASK;
}

void camcontrol_updateTargetFeedback(void)
{
    u32 targetKind;
    s16 objType;
    f32 alphaScale;
    CamcontrolTargetObject* target;
    ObjAnimComponent* reticle;
    u8 buttonPressed;
    int result;
    u32 buttons;
    u32 buttonMask;
    f32 targetDistance;

    target = (CamcontrolTargetObject*)CAMCONTROL_CAMERA->currentTarget;
    reticle = &gCamcontrolTargetReticle->anim;
    buttonPressed = false;
    if (reticle == NULL)
    {
        return;
    }
    result = gameTextFn_80134be8();
    switch (result)
    {
    case 0:
    if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', target != NULL))
    {
        targetKind = CAMCONTROL_CAMERA->targetKind;
        if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON)
        {
            Sfx_PlayFromObject(0, SFXTRIG_headcam_out);
            objShowButtonGlow(reticle, gCamcontrolNormalizedMax, 2);
        }
        else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
            (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B))
        {
            Sfx_PlayFromObject(0, SFXTRIG_lockon2_on);
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
        if (reticle->currentMoveProgress <= gCamcontrolNormalizedMin)
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
                                                                        NULL);
        }
    }
    else if (((u32)CAMCONTROL_CAMERA->targetReticleFocus != (u32)target) &&
        (reticle->currentMoveProgress >= gCamcontrolNormalizedMax))
    {
        gCamcontrolTargetState = CAMCONTROL_TARGET_RETICLE_STATE_INACTIVE;
        if (target != NULL)
        {
            ((int (*)(int, f32))ObjAnim_SetMoveProgress)((int)reticle, gCamcontrolNormalizedMin);
        }
        if (target == NULL)
        {
            targetKind = CAMCONTROL_CAMERA->targetKind;
            if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON)
            {
                Sfx_PlayFromObject(0, SFXTRIG_strafe_active);
            }
            else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
                (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B))
            {
                Sfx_PlayFromObject(0, SFXTRIG_lockon2_off);
            }
            else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED)
            {
                Sfx_PlayFromObject(0, SFXsc_spotfox02);
            }
        }
    }
    else
    {
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)reticle, gCamcontrolReticleFadeInStep,
                                                                    timeDelta, NULL);
    }
    result = Obj_IsObjectAlive(CAMCONTROL_CAMERA->targetReticleFocus);
    if (result == 0)
    {
        CAMCONTROL_CAMERA->targetReticleFocus = 0;
    }
    if ((gCamcontrolTargetState == CAMCONTROL_TARGET_RETICLE_STATE_ACTIVE) &&
        ((u32)CAMCONTROL_CAMERA->targetReticleFocus != 0))
    {
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
        target = (CamcontrolTargetObject*)CAMCONTROL_CAMERA->targetReticleFocus;
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
            targetDistance = largecrate_getReticleDistance((int)target);
            break;
        case 0x31:
            targetDistance = gCamcontrolNormalizedMax;
            break;
        default:
            result = dll_19_func1B((int)target);
            if (result != 0)
            {
                targetDistance =
                    camcontrol_GetBaddieControlInterface()->getTargetReticleDistance((int)target);
            }
            else
            {
                targetDistance = gCamcontrolNormalizedMax;
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
    }
    alphaScale = gCamcontrolReticleAlphaScale * reticle->currentMoveProgress;
    alphaScale = (alphaScale < gCamcontrolNormalizedMin)
                     ? gCamcontrolNormalizedMin
                     : ((alphaScale > gCamcontrolReticleAlphaScale) ? gCamcontrolReticleAlphaScale : alphaScale);
    reticle->alpha = alphaScale;
    gCamcontrolReticleSpin = CAMCONTROL_RETICLE_SPIN_STEP;
    *(s16*)&reticle->rotX = (gCamcontrolReticleSpinStepPerFrame * timeDelta + (float)reticle->rotX);
    break;
    }
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

void camcontrol_getRelativePosition(f32 heightOffset, int targetObj, f32* outX, f32* outY,
                                    f32* outZ, f32* outDistanceXZ, int useLocalPosition)
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
    if (outDistanceXZ != NULL)
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

void camcontrol_initialise(f32* dst, f32 numerator, f32 denominator, f32 minValue, f32 y, f32 z)
{
    f32 ratio;

    ratio = numerator / denominator;
    if (ratio < minValue)
    {
        ratio = minValue;
    }
    dst[0] = ratio;
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

static inline CamcontrolHandlerEntry* camcontrol_findDefaultHandler(void)
{
    int handlerCount;
    register CamcontrolHandlerEntry** handlerEntry;
    int handlerIndex;

    handlerIndex = 0;
    handlerEntry = gCamcontrolHandlerEntries;
    for (handlerCount = gCamcontrolHandlerCount; 0 < handlerCount; handlerCount--)
    {
        if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT)
        {
            return gCamcontrolHandlerEntries[handlerIndex];
        }
        handlerEntry++;
        handlerIndex++;
    }
    return NULL;
}

void camcontrol_loadTriggeredCamAction(int triggerType, int actionNo, int triggerMode)
{
    CamcontrolHandlerEntry* defaultHandler;
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
        triggerType2Param.noBlendFlag = (u8)(actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND);
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
            camAction = NULL;
        }
        else
        {
            camAction = (CamcontrolTriggeredAction*)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_HEAP, 0);
            if (camAction != NULL)
            {
                actionOffset = (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE;
                getTabEntry(camAction, CAMCONTROL_ACTION_FILE_ID, actionOffset, CAMCONTROL_ACTION_RECORD_SIZE);
            }
        }
        if (camAction == NULL)
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
            defaultHandler = camcontrol_findDefaultHandler();
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
        if (camAction != NULL)
        {
            getTabEntry(camAction, CAMCONTROL_ACTION_FILE_ID, CAMCONTROL_FALLBACK_ACTION_FILE_OFFSET,
                        CAMCONTROL_ACTION_RECORD_SIZE);
        }
        if (camAction == NULL)
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
            defaultHandler = camcontrol_findDefaultHandler();
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
        return NULL;
    }
    camAction = mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE, CAMCONTROL_ACTION_HEAP, 0);
    if (camAction != NULL)
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
    if (gCamcontrolQueuedActionData != NULL)
    {
        mm_free(gCamcontrolQueuedActionData);
        gCamcontrolQueuedActionData = NULL;
        gCamcontrolQueuedActionPending = 0;
    }
    gCamcontrolQueuedActionId = actionId;
    gCamcontrolQueuedActionBlendFrames = blendFrames;
    if (data != NULL)
    {
        gCamcontrolQueuedActionData = mmAlloc(dataSize, CAMCONTROL_ACTION_HEAP, 0);
        memcpy(gCamcontrolQueuedActionData, data, dataSize);
    }
    else
    {
        gCamcontrolQueuedActionData = NULL;
    }
    if (actionId == CAMCONTROL_ACTION_DEFAULT)
    {
        gCamcontrolQueuedActionPriority = 0;
    }
    else
    {
        gCamcontrolQueuedActionPriority = priority;
    }
    gCamcontrolQueuedActionStartFlags = startFlags;
    gCamcontrolQueuedActionPending = 1;
    gCamcontrolQueuedActionMode = queueMode;
    return;
}

#define camera CAMCONTROL_CAMERA
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
    focus = camera->focusObj;
    if (focus == NULL)
    {
        camera->currentTarget = 0;
        camera->overrideTarget = 0;
    }
    else
    {
        gCamcontrolSavedFocusLocalX = focus->localPosX;
        gCamcontrolSavedFocusLocalY = focus->localPosY;
        gCamcontrolSavedFocusLocalZ = focus->localPosZ;
        gCamcontrolSavedFocusWorldX = focus->worldPosX;
        gCamcontrolSavedFocusWorldY = focus->worldPosY;
        gCamcontrolSavedFocusWorldZ = focus->worldPosZ;
        camcontrol_updateMoveAverage(camera, focus);
        if (camera->overrideWorldPosPending != 0)
        {
            focus->worldPosX = camera->overrideWorldX;
            focus->worldPosY = camera->overrideWorldY;
            focus->worldPosZ = camera->overrideWorldZ;
            Obj_TransformWorldPointToLocal(focus->worldPosX, focus->worldPosY, focus->worldPosZ,
                                           &focus->localPosX, &focus->localPosY, &focus->localPosZ,
                                           (u32)focus->parent);
            camera->overrideWorldPosPending = 0;
        }
        if (camera->localFrameObj != focus->parent)
        {
            Obj_TransformLocalPointToWorld(camera->localX, camera->localY, camera->localZ,
                                           &camera->worldX, &camera->worldY, &camera->worldZ,
                                           (u32)camera->localFrameObj);
            Obj_TransformLocalPointToWorld(camera->prevLocalX, camera->prevLocalY, camera->prevLocalZ,
                                           &camera->prevWorldX, &camera->prevWorldY, &camera->prevWorldZ,
                                           (u32)camera->localFrameObj);
            Obj_TransformWorldPointToLocal(camera->worldX, camera->worldY, camera->worldZ,
                                           &camera->localX, &camera->localY, &camera->localZ,
                                           (u32)focus->parent);
            Obj_TransformWorldPointToLocal(camera->prevWorldX, camera->prevWorldY, camera->prevWorldZ,
                                           &camera->prevLocalX, &camera->prevLocalY, &camera->prevLocalZ,
                                           (u32)focus->parent);
            camera->localFrameObj = focus->parent;
        }
        if (focus->parent != NULL)
        {
            focus->rotX += ((ObjAnimComponent*)focus->parent)->rotX;
        }
        camcontrol_applyQueuedAction();
        if (gCamcontrolCurrentHandler != 0)
        {
            gCamcontrolCurrentHandler->handler->vtable->update((void*)pCamera);
            Obj_TransformLocalPointToWorld(camera->localX, camera->localY, camera->localZ,
                                           &camera->worldX, &camera->worldY, &camera->worldZ,
                                           (u32)camera->localFrameObj);
            camcontrol_applyState(camera);
        }
        camcontrol_applyQueuedAction();
        if (textActive == 0)
        {
            if (camera->overrideTarget == 0u)
            {
                target = camcontrol_findBestTarget(camera, focus);
                camera->currentTarget = (int)target;
            }
            else
            {
                camera->currentTarget = camera->overrideTarget;
            }
        }
        camera->prevLocalX = camera->localX;
        camera->prevLocalY = camera->localY;
        camera->prevLocalZ = camera->localZ;
        camera->prevWorldX = camera->worldX;
        camera->prevWorldY = camera->worldY;
        camera->prevWorldZ = camera->worldZ;
        camera->frameFlags = 0;
        focus->localPosX = gCamcontrolSavedFocusLocalX;
        focus->localPosY = gCamcontrolSavedFocusLocalY;
        focus->localPosZ = gCamcontrolSavedFocusLocalZ;
        focus->worldPosX = gCamcontrolSavedFocusWorldX;
        focus->worldPosY = gCamcontrolSavedFocusWorldY;
        focus->worldPosZ = gCamcontrolSavedFocusWorldZ;
        if (focus->parent != NULL)
        {
            focus->rotX -= ((ObjAnimComponent*)focus->parent)->rotX;
        }
    }
    return;
}
#undef camera

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

char sCamcontrolTriggeredCamActionLoadWarning[] = "<camcontrol.c>  failed to load triggered camaction actionno %d\n";

/* descriptor/ptr table auto 0x80319b58-0x80319cb4 */
u32 lbl_80319B58[16] = { 0x00000000, 0x00000000, 0x00000000, 0x000b0000, (u32)camcontrol_initialiseModeSettings, (u32)camcontrol_releaseModeSettings, 0x00000000, (u32)pathcam_loadSettings, (u32)camstatic_update, (u32)CameraModeNormal_free, (u32)firstperson_loadSettings, (u32)firstperson_updatePosition, (u32)firstperson_updatePitch, (u32)camslide_update, (u32)CameraModeNormal_func0A, (u32)camcontrol_updateVerticalBounds };
u32 lbl_80319B98[12] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeStaffAnim_initialise, (u32)CameraModeStaffAnim_release, 0x00000000, (u32)CameraModeStaffAnim_init, (u32)camclimb_update, (u32)camcontrol_releasePathState, (u32)CameraModeStaffAnim_copyToCurrent_nop, 0x00000000 };
u32 lbl_80319BC8[12] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeBike_initialise, (u32)CameraModeBike_release, 0x00000000, (u32)CameraModeBike_init, (u32)CameraModeBike_update, (u32)CameraModeBike_free, (u32)CameraModeBike_copyToCurrent, 0x00000000 };
u32 lbl_80319BF8[12] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeViewfinder_initialise, (u32)CameraModeViewfinder_release, 0x00000000, (u32)CameraModeViewfinder_init, (u32)CameraModeViewfinder_update, (u32)CameraModeViewfinder_free, (u32)CameraModeViewfinder_copyToCurrent, 0x00000000 };
u32 lbl_80319C28[12] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeDebug_initialise_nop, (u32)CameraModeDebug_release_nop, 0x00000000, (u32)CameraModeDebug_init, (u32)CameraModeDebug_update, (u32)CameraModeDebug_free, (u32)CameraModeDebug_copyToCurrent_nop, 0x00000000 };
u32 lbl_80319C58[12] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeStatic_initialise, (u32)CameraModeStatic_release, 0x00000000, (u32)CameraModeStatic_init, (u32)CameraModeStatic_update, (u32)CameraModeStatic_free, (u32)CameraModeStatic_copyToCurrent_nop, 0x00000000 };
u32 lbl_80319C88[11] = { 0x00000000, 0x00000000, 0x00000000, 0x00060000, (u32)CameraModeTestStrength_initialise, (u32)CameraModeTestStrength_release, 0x00000000, (u32)CameraModeTestStrength_init, (u32)CameraModeTestStrength_update, (u32)CameraModeTestStrength_free, (u32)CameraModeTestStrength_copyToCurrent_nop };
