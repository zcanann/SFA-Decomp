#include "main/audio/sfx_ids.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/dll/CAM/camcontrol.h"
#include "main/objanim_internal.h"
#include "string.h"

extern void Sfx_PlayFromObject(int obj,int sfxId);
extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,u32 obj);
extern void Obj_TransformLocalPointToWorld(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,u32 obj);
extern uint getButtonsJustPressed();
extern undefined4 FUN_80017640();
extern int Obj_IsObjectAlive();
extern undefined8 FUN_800723a0();
extern void objShowButtonGlow(void *obj,f32 intensity,int mode);
extern undefined4 FUN_800e8794();
extern int camcontrol_findBestTarget(int cameraState, short *target);
extern void camcontrol_updateMoveAverage(int cameraState, int target);
extern void camcontrol_applyState(short *cameraState);
extern void camcontrol_applyQueuedAction(void);
extern int dll_19_func1B();
extern int isTalkingToNpc();
extern int gameTextFn_80134be8(void);
extern f32 fn_8014C5D0(int obj);
extern f32 fn_80183204(int obj);
extern f32 sqrtf(f32 x);
extern void mm_free(void *ptr);
extern void *mmAlloc(int size,int heap,int flags);
extern void SaveGame_setCamActionNo(s16 actionNo);
extern void voxmaps_initialise(void);
extern void voxmaps_resetLoadedMaps(void);

extern void *gCamcontrolHandlers[20];
extern u8 gCamcontrolStateStorage[];
extern undefined4* gBaddieControlInterface;
extern s8 gCamcontrolTargetChanged;
extern short* gCamcontrolTargetReticle;
extern u16 lbl_803DD4C8;
extern s8 gCamcontrolTargetState;
extern short* gCamcontrolState;
extern f32 timeDelta;
extern f64 lbl_803E1650;
extern f32 gCamcontrolSavedFocusWorldZ;
extern f32 gCamcontrolSavedFocusWorldY;
extern f32 gCamcontrolSavedFocusWorldX;
extern f32 gCamcontrolSavedFocusLocalZ;
extern f32 gCamcontrolSavedFocusLocalY;
extern f32 gCamcontrolSavedFocusLocalX;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
extern f32 lbl_803E1634;
extern f32 lbl_803E1638;
extern f32 lbl_803E163C;
extern f32 lbl_803E1670;
extern f32 lbl_803E1674;
extern f32 lbl_803E1678;
extern f32 lbl_803E167C;
extern f32 lbl_803E1680;
extern f32 lbl_803E2300;
extern f32 lbl_803E1684;
extern u16 lbl_803DB992;
extern s8 lbl_803DD4CB;
extern undefined4 lbl_803DD4CC;

typedef struct CamcontrolBaddieControlInterface {
  u8 pad00[0x60];
  f32 (*getTargetReticleDistance)(int obj);
} CamcontrolBaddieControlInterface;

typedef struct CamcontrolTargetSetup {
  u8 pad00[0x04];
  u8 targetKind;
} CamcontrolTargetSetup;

typedef struct CamcontrolTargetObject {
  u8 pad00[0x46];
  s16 objType;
  u8 pad48[0x78 - 0x48];
  CamcontrolTargetSetup *targetSetup;
  u8 pad7C[0xAF - 0x7C];
  u8 targetFlags;
  u8 padB0[0xE4 - 0xB0];
  u8 targetSetupIndex;
} CamcontrolTargetObject;

#define CAMCONTROL_TARGET_KIND_MASK 0x0F
#define CAMCONTROL_TARGET_KIND_LOCKON 1
#define CAMCONTROL_TARGET_KIND_CONTEXT_A 4
#define CAMCONTROL_TARGET_KIND_SUPPRESSED 8
#define CAMCONTROL_TARGET_KIND_CONTEXT_B 9
#define CAMCONTROL_TARGET_FLAG_RETICLE_TOUCHING 0x04
#define CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT 0x10
#define CAMCONTROL_TARGET_FLAG_INPUT_PRESSED 0x01
#define CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT 0x20
#define CAMCONTROL_TARGET_BUTTON_PRIMARY 0x100
#define CAMCONTROL_TARGET_BUTTON_CONTEXT 0x900

STATIC_ASSERT(sizeof(CamcontrolTargetSetup) == 0x05);
STATIC_ASSERT(offsetof(CamcontrolTargetSetup, targetKind) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, objType) == 0x46);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetSetup) == 0x78);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetFlags) == 0xAF);
STATIC_ASSERT(offsetof(CamcontrolTargetObject, targetSetupIndex) == 0xE4);

static inline CamcontrolBaddieControlInterface *camcontrol_GetBaddieControlInterface(void) {
  return (CamcontrolBaddieControlInterface *)*gBaddieControlInterface;
}

static inline uint camcontrol_GetTargetKind(CamcontrolTargetObject *target) {
  return target->targetSetup[target->targetSetupIndex].targetKind & CAMCONTROL_TARGET_KIND_MASK;
}

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetFeedback
 * EN v1.0 Address: 0x8010224C
 * EN v1.0 Size: 1652b
 * EN v1.1 Address: 0x801024E8
 * EN v1.1 Size: 1736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updateTargetFeedback(void)
{
  uint targetKind;
  s16 objType;
  float fVar4;
  CamcontrolTargetObject *target;
  ObjAnimComponent *reticle;
  u8 buttonPressed;
  int result;
  uint buttons;
  uint buttonMask;
  f32 targetDistance;
  
  target = (CamcontrolTargetObject *)CAMCONTROL_CAMERA->currentTarget;
  reticle = (ObjAnimComponent *)gCamcontrolTargetReticle;
  buttonPressed = false;
  if (reticle == NULL) {
    return;
  }
  result = gameTextFn_80134be8();
  if (result != 0) {
    return;
  }
  if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', target != NULL)) {
    targetKind = CAMCONTROL_CAMERA->targetKind;
    if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON) {
      Sfx_PlayFromObject(0,0x3ff);
      objShowButtonGlow(reticle,lbl_803E162C,2);
    }
    else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
             (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
      Sfx_PlayFromObject(0,0x402);
      objShowButtonGlow(reticle,lbl_803E162C,3);
    }
    else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED) {
      Sfx_PlayFromObject(0,SFXsc_spotfox01);
      objShowButtonGlow(reticle,lbl_803E162C,1);
    }
  }
  if (target != NULL) {
    target->targetFlags = target->targetFlags | CAMCONTROL_TARGET_FLAG_RETICLE_TOUCHING;
    buttons = getButtonsJustPressed(0);
    buttonMask = CAMCONTROL_TARGET_BUTTON_PRIMARY;
    targetKind = camcontrol_GetTargetKind(target);
    if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
        (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
      buttonMask = CAMCONTROL_TARGET_BUTTON_CONTEXT;
    }
    if ((buttons & buttonMask) != 0) {
      buttonPressed = true;
    }
    if ((target->targetFlags & CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT) == 0) {
      if (buttonPressed) {
        target->targetFlags = target->targetFlags | CAMCONTROL_TARGET_FLAG_INPUT_PRESSED;
      }
    }
    else if ((buttonPressed) && (result = isTalkingToNpc(), result == 0)) {
      Sfx_PlayFromObject(0,SFXsc_snort04);
    }
  }
  if (gCamcontrolTargetState == '\0') {
    if (reticle->currentMoveProgress <= lbl_803E1630) {
      if (target == NULL) {
        CAMCONTROL_CAMERA->targetReticleFocus = 0;
      }
      else {
        CAMCONTROL_CAMERA->targetReticleFocus = (int)target;
        CAMCONTROL_CAMERA->targetKind = camcontrol_GetTargetKind(target);
        gCamcontrolTargetState = '\x03';
        gCamcontrolTargetChanged = '\x01';
      }
    }
    else {
      ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)reticle,lbl_803E1670,timeDelta,
                                 (ObjAnimEventList *)0x0);
    }
  }
  else if (((uint)CAMCONTROL_CAMERA->targetReticleFocus == (uint)target) ||
          (reticle->currentMoveProgress < lbl_803E162C)) {
    ObjAnim_AdvanceCurrentMove(lbl_803E1674,timeDelta,(int)reticle,
                               (ObjAnimEventList *)0x0);
  }
  else {
    gCamcontrolTargetState = '\0';
    if (target == NULL) {
      targetKind = CAMCONTROL_CAMERA->targetKind;
      if (targetKind == CAMCONTROL_TARGET_KIND_LOCKON) {
        Sfx_PlayFromObject(0,0x400);
      }
      else if ((targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_A) ||
               (targetKind == CAMCONTROL_TARGET_KIND_CONTEXT_B)) {
        Sfx_PlayFromObject(0,0x401);
      }
      else if (targetKind != CAMCONTROL_TARGET_KIND_SUPPRESSED) {
        Sfx_PlayFromObject(0,SFXsc_spotfox02);
      }
    }
    else {
      ObjAnim_SetMoveProgress(lbl_803E1630,reticle);
    }
  }
  result = Obj_IsObjectAlive(CAMCONTROL_CAMERA->targetReticleFocus);
  if (result == 0) {
    CAMCONTROL_CAMERA->targetReticleFocus = 0;
  }
  if ((gCamcontrolTargetState != '\x03') || ((uint)CAMCONTROL_CAMERA->targetReticleFocus == 0))
  goto LAB_80102ab4;
  target = (CamcontrolTargetObject *)CAMCONTROL_CAMERA->targetReticleFocus;
  if ((target->targetFlags & CAMCONTROL_TARGET_FLAG_ACCEPTS_INPUT) != 0) {
    CAMCONTROL_CAMERA->targetFlags =
        CAMCONTROL_CAMERA->targetFlags | CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT;
  }
  else {
    CAMCONTROL_CAMERA->targetFlags =
        CAMCONTROL_CAMERA->targetFlags & ~CAMCONTROL_CAMERA_TARGET_FLAG_ACCEPTS_INPUT;
  }
  objType = target->objType;
  if (objType == 0x49f) {
LAB_80102994:
    targetDistance = fn_80183204((int)target);
  }
  else {
    if (objType < 0x49f) {
      if (objType != 0x281) {
        if (objType < 0x281) {
          if (objType != 0x13a) {
            if (objType < 0x13a) {
              if (objType == 0x31) {
                targetDistance = lbl_803E162C;
                goto LAB_801029e0;
              }
              if (objType < 0x31) {
                if (objType != 0x11) goto LAB_801029ac;
              }
              else if (objType != 0xd8) goto LAB_801029ac;
            }
            else if ((objType != 0x25d) && ((0x25c < objType || (objType != 0x251)))) goto LAB_801029ac;
          }
        }
        else if (objType != 0x3fe) {
          if (objType < 0x3fe) {
            if (objType == 0x3de) goto LAB_80102994;
            if ((0x3dd < objType) || (objType != 0x369)) goto LAB_801029ac;
          }
          else if (objType < 0x457) {
            if (objType != 0x427) goto LAB_801029ac;
          }
          else if (0x458 < objType) goto LAB_801029ac;
        }
      }
    }
    else if (objType != 0x613) {
      if (objType < 0x613) {
        if (objType != 0x58b) {
          if (objType < 0x58b) {
            if ((objType != 0x4d7) && ((0x4d6 < objType || (objType != 0x4ac)))) {
LAB_801029ac:
              result = dll_19_func1B((int)target);
              if (result == 0) {
                targetDistance = lbl_803E162C;
              }
              else {
                targetDistance =
                    camcontrol_GetBaddieControlInterface()->getTargetReticleDistance((int)target);
              }
              goto LAB_801029e0;
            }
          }
          else if ((objType != 0x5e1) && (((0x5e0 < objType || (0x5b9 < objType)) || (objType < 0x5b7))))
          goto LAB_801029ac;
        }
      }
      else if (objType != 0x842) {
        if (objType < 0x842) {
          if (objType < 0x6a2) {
            if (objType != 0x642) goto LAB_801029ac;
          }
          else if (0x6a5 < objType) goto LAB_801029ac;
        }
        else if ((objType != 0x851) && ((0x850 < objType || (objType != 0x84b)))) goto LAB_801029ac;
      }
    }
    targetDistance = fn_8014C5D0((int)target);
  }
LAB_801029e0:
  if ((lbl_803E1630 < targetDistance) ||
     (CAMCONTROL_CAMERA->targetDistance <= lbl_803E1630)) {
    if ((lbl_803E1634 < targetDistance) ||
       (CAMCONTROL_CAMERA->targetDistance <= lbl_803E1634)) {
      if ((lbl_803E1638 < targetDistance) ||
         (CAMCONTROL_CAMERA->targetDistance <= lbl_803E1638)) {
        if ((targetDistance <= lbl_803E163C) &&
           (lbl_803E163C < CAMCONTROL_CAMERA->targetDistance)) {
          objShowButtonGlow(reticle,lbl_803E162C,4);
        }
      }
      else {
        objShowButtonGlow(reticle,lbl_803E162C,4);
      }
    }
    else {
      objShowButtonGlow(reticle,lbl_803E162C,4);
    }
  }
  else {
    objShowButtonGlow(reticle,lbl_803E162C,4);
  }
  CAMCONTROL_CAMERA->targetDistance = targetDistance;
LAB_80102ab4:
  fVar4 = lbl_803E1678 * reticle->currentMoveProgress;
  if (fVar4 < lbl_803E1630) {
    fVar4 = lbl_803E1630;
  }
  else if (lbl_803E1678 < fVar4) {
    fVar4 = lbl_803E1678;
  }
  reticle->alpha = (int)fVar4;
  lbl_803DD4C8 = 0x400;
  *(s16 *)reticle = (short)(int)(lbl_803E167C * timeDelta + (float)*(s16 *)reticle);
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int Camera_isZooming(void)
{
  return CAMCONTROL_CAMERA->zoomDistance > lbl_803E1630;
}
#pragma scheduling reset

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

/*
 * --INFO--
 *
 * Function: camcontrol_getRelativePosition
 * EN v1.0 Address: 0x80102914
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80102BB0
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_getRelativePosition(f32 heightOffset,int targetObj,float *outX,float *outY,
                                    float *outZ,float *outDistanceXZ,int useLocalPosition)
{
  ObjAnimComponent *focusObj;
  ObjAnimComponent *target;

  focusObj = CAMCONTROL_CAMERA->focusObj;
  target = (ObjAnimComponent *)targetObj;
  if (useLocalPosition != 0) {
    *outX = target->localPosX - focusObj->localPosX;
    *outY = target->localPosY - (focusObj->localPosY + heightOffset);
    *outZ = target->localPosZ - focusObj->localPosZ;
  }
  else {
    *outX = target->worldPosX - focusObj->worldPosX;
    *outY = target->worldPosY - (focusObj->worldPosY + heightOffset);
    *outZ = target->worldPosZ - focusObj->worldPosZ;
  }
  if (outDistanceXZ != (float *)0x0) {
    *outDistanceXZ = *outX * *outX + *outZ * *outZ;
    if (*outDistanceXZ > lbl_803E1630) {
      *outDistanceXZ = sqrtf(*outDistanceXZ);
    }
    if (*outDistanceXZ < lbl_803E1680) {
      *outDistanceXZ = *(f32 *)&lbl_803E1680;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

void camcontrol_initialise(float *dst,f32 numerator,f32 denominator,f32 minValue,f32 y,f32 z)
{
  f32 x;

  x = numerator / denominator;
  if (x < minValue) {
    x = minValue;
  }
  dst[0] = x;
  dst[1] = y;
  dst[2] = lbl_803E1630;
  dst[3] = z;
}

void Camera_moveBy(f32 x,f32 y,f32 z)
{
  CAMCONTROL_CAMERA->localX += x;
  CAMCONTROL_CAMERA->localY += y;
  CAMCONTROL_CAMERA->localZ += z;
}

#pragma scheduling off
void Camera_overridePos(f32 x,f32 y,f32 z)
{
  CAMCONTROL_CAMERA->overrideWorldPosPending = 1;
  CAMCONTROL_CAMERA->overrideWorldX = x;
  CAMCONTROL_CAMERA->overrideWorldY = y;
  CAMCONTROL_CAMERA->overrideWorldZ = z;
}
#pragma scheduling reset

void Camera_setFocus(void *target)
{
  if (target == CAMCONTROL_CAMERA->focusObj) {
    return;
  }
  CAMCONTROL_CAMERA->focusObj = target;
}

/*
 * --INFO--
 *
 * Function: camcontrol_loadTriggeredCamAction
 * EN v1.0 Address: 0x80102AA0
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80102D3C
 * EN v1.1 Size: 1012b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_loadTriggeredCamAction(int triggerType,int actionNo,int triggerMode)
{
  int handlerCount;
  int handlerIndex;
  CamcontrolHandlerEntry *defaultHandler;
  register CamcontrolHandlerEntry **handlerEntry;
  int blendFrames;
  CamcontrolTriggeredAction *camAction;
  int actionOffset;
  CamcontrolQueuedActionParam triggerType1Param;
  CamcontrolQueuedActionParam triggerType2Param;
  
  switch (triggerType) {
  case CAMCONTROL_TRIGGER_KIND_LOAD_ACTION:
    break;
  case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1:
    triggerType1Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
    triggerType1Param.noBlendFlag = actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND;
    CAMCONTROL_CAMERA->triggerType1Pending = 1;
    if (triggerType1Param.noBlendFlag != 0) {
      blendFrames = 0;
    }
    else {
      blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
    }
    Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE1,1,0,CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                   &triggerType1Param,blendFrames,CAMCONTROL_QUEUE_SENTINEL);
    return;
  case CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2:
    triggerType2Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
    triggerType2Param.noBlendFlag = (byte)(actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND);
    if (triggerType2Param.noBlendFlag != 0) {
      blendFrames = 0;
    }
    else {
      blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
    }
    Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE2,1,0,CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                   &triggerType2Param,blendFrames,CAMCONTROL_QUEUE_SENTINEL);
    return;
  case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION:
    Camera_setMode(CAMCONTROL_ACTION_DEFAULT,0,1,0,0,CAMCONTROL_DEFAULT_BLEND_FRAMES,
                   CAMCONTROL_QUEUE_SENTINEL);
    return;
  case CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET:
    Camera_setMode(actionNo + CAMCONTROL_ACTION_DEFAULT,1,0,0,0,
                   CAMCONTROL_DEFAULT_BLEND_FRAMES,CAMCONTROL_QUEUE_SENTINEL);
    return;
  }
  if (actionNo != CAMCONTROL_ACTION_NO_NONE) {
    if (actionNo == CAMCONTROL_ACTION_NO_NONE) {
      camAction = (CamcontrolTriggeredAction *)0x0;
    }
    else {
      camAction = (CamcontrolTriggeredAction *)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE,CAMCONTROL_ACTION_HEAP,0);
      if (camAction != (CamcontrolTriggeredAction *)0x0) {
        actionOffset = (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE;
        getTabEntry(camAction,CAMCONTROL_ACTION_FILE_ID,actionOffset,CAMCONTROL_ACTION_RECORD_SIZE);
      }
    }
    if (camAction == (CamcontrolTriggeredAction *)0x0) {
      return;
    }
    camAction->triggerMode = triggerMode;
    SaveGame_setCamActionNo((short)actionNo);
    if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
         ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
        ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
       ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2)) {
      handlerIndex = 0;
      handlerEntry = gCamcontrolHandlerEntries;
      for (handlerCount = (int)gCamcontrolHandlerCount; 0 < handlerCount;
           handlerCount = handlerCount - 1) {
        if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT) {
          defaultHandler = gCamcontrolHandlerEntries[handlerIndex];
          goto LAB_80102f3c;
        }
        handlerEntry = handlerEntry + 1;
        handlerIndex++;
      }
      defaultHandler = NULL;
LAB_80102f3c:
      defaultHandler->handler->vtable->actionCallback(camAction,CAMCONTROL_ACTION_RECORD_SIZE);
    }
    else {
      switch (camAction->actionKind) {
      case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
      default:
        Camera_setMode(CAMCONTROL_ACTION_DEFAULT,0,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
        break;
      case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
        Camera_setMode(CAMCONTROL_ACTION_TRIGGERED,1,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
        break;
      }
    }
    mm_free(camAction);
  }
  else {
    OSReport(sCamcontrolTriggeredCamActionLoadWarning,actionNo);
    camAction = (CamcontrolTriggeredAction *)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE,CAMCONTROL_ACTION_HEAP,0);
    if (camAction != (CamcontrolTriggeredAction *)0x0) {
      getTabEntry(camAction,CAMCONTROL_ACTION_FILE_ID,CAMCONTROL_FALLBACK_ACTION_FILE_OFFSET,
                  CAMCONTROL_ACTION_RECORD_SIZE);
    }
    if (camAction == (CamcontrolTriggeredAction *)0x0) {
      return;
    }
    camAction->triggerMode = triggerMode;
    SaveGame_setCamActionNo(CAMCONTROL_FALLBACK_ACTION_NO);
    if (((((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_DEFAULT) &&
         ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGERED)) &&
        ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE1)) &&
       ((int)gCamcontrolActiveActionId != CAMCONTROL_ACTION_TRIGGER_TYPE2)) {
      handlerIndex = 0;
      handlerEntry = gCamcontrolHandlerEntries;
      for (handlerCount = (int)gCamcontrolHandlerCount; 0 < handlerCount;
           handlerCount = handlerCount - 1) {
        if ((*handlerEntry)->actionId == CAMCONTROL_ACTION_DEFAULT) {
          defaultHandler = gCamcontrolHandlerEntries[handlerIndex];
          goto LAB_80102f3c_b;
        }
        handlerEntry = handlerEntry + 1;
        handlerIndex++;
      }
      defaultHandler = NULL;
LAB_80102f3c_b:
      defaultHandler->handler->vtable->actionCallback(camAction,CAMCONTROL_ACTION_RECORD_SIZE);
    }
    else {
      switch (camAction->actionKind) {
      case CAMCONTROL_TRIGGERED_ACTION_KIND_DEFAULT:
      default:
        Camera_setMode(CAMCONTROL_ACTION_DEFAULT,0,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
        break;
      case CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED:
        Camera_setMode(CAMCONTROL_ACTION_TRIGGERED,1,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
        break;
      }
    }
    mm_free(camAction);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Camera_getCamActionsBinEntry
 * EN v1.0 Address: 0x80102E94
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80103130
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
CamcontrolTriggeredAction *Camera_getCamActionsBinEntry(int actionNo)
{
  CamcontrolTriggeredAction *camAction;

  if (actionNo == CAMCONTROL_ACTION_NO_NONE) {
    return 0;
  }
  camAction = mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE,CAMCONTROL_ACTION_HEAP,0);
  if (camAction != 0) {
    getTabEntry(camAction,CAMCONTROL_ACTION_FILE_ID,
                (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE,CAMCONTROL_ACTION_RECORD_SIZE);
  }
  return camAction;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_release
 * EN v1.0 Address: 0x80102F08
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801031A4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_release(int camAction, int recordSize)
{
  CamcontrolHandlerEntry *currentHandler;

  currentHandler = gCamcontrolCurrentHandler;
  if (currentHandler != NULL) {
    currentHandler->handler->vtable->actionCallback(camAction, recordSize);
  }
}

/*
 * --INFO--
 *
 * Function: camcontrol_queueSavedAction
 * EN v1.0 Address: 0x80102F44
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801031E0
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_queueSavedAction(undefined4 blendFrames,undefined queueMode)
{
  if (gCamcontrolSavedActionId != CAMCONTROL_SAVED_ACTION_NONE) {
    Camera_setMode(gCamcontrolSavedActionId,gCamcontrolSavedActionPriority,
                   gCamcontrolSavedActionStartFlags,0,0,blendFrames,queueMode);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Camera_setMode
 * EN v1.0 Address: 0x80102F88
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80103224
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void Camera_setMode(s32 actionId,int priority,int startFlags,int dataSize,void *data,
                    undefined4 blendFrames,undefined queueMode)
{
  if (gCamcontrolQueuedActionData != (void *)0x0) {
    mm_free(gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionData = (void *)0x0;
    gCamcontrolQueuedActionPending = 0;
  }
  gCamcontrolQueuedActionId = actionId;
  gCamcontrolQueuedActionBlendFrames = blendFrames;
  if (data != (void *)0x0) {
    gCamcontrolQueuedActionData = mmAlloc(dataSize,CAMCONTROL_ACTION_HEAP,0);
    memcpy(gCamcontrolQueuedActionData,data,dataSize);
  }
  else {
    gCamcontrolQueuedActionData = (void *)0x0;
  }
  if (actionId == CAMCONTROL_ACTION_DEFAULT) {
    gCamcontrolQueuedActionPriority = 0;
  }
  else {
    gCamcontrolQueuedActionPriority = (s8)priority;
  }
  gCamcontrolQueuedActionStartFlags = (s8)startFlags;
  gCamcontrolQueuedActionPending = 1;
  gCamcontrolQueuedActionMode = queueMode;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Camera_update
 * EN v1.0 Address: 0x801030C0
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x8010335C
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void Camera_update(void)
{
  short *psVar3;
  u8 textActive;
  undefined4 uVar2;

  if (gameTextFn_80134be8() != 0) {
    textActive = 1;
  }
  else {
    textActive = 0;
  }
  psVar3 = *(short **)((char *)pCamera + 0xa4);
  if (psVar3 == (short *)0x0) {
    *(undefined4 *)((char *)pCamera + 0x124) = 0;
    *(undefined4 *)((char *)pCamera + 0x11c) = 0;
  }
  else {
    gCamcontrolSavedFocusLocalX = *(float *)(psVar3 + 6);
    gCamcontrolSavedFocusLocalY = *(float *)(psVar3 + 8);
    gCamcontrolSavedFocusLocalZ = *(float *)(psVar3 + 10);
    gCamcontrolSavedFocusWorldX = *(float *)(psVar3 + 0xc);
    gCamcontrolSavedFocusWorldY = *(float *)(psVar3 + 0xe);
    gCamcontrolSavedFocusWorldZ = *(float *)(psVar3 + 0x10);
    camcontrol_updateMoveAverage((int)pCamera,(int)psVar3);
    if (*(u8 *)((char *)pCamera + 0x13d) != 0) {
      *(float *)(psVar3 + 0xc) = *(float *)((char *)pCamera + 0xdc);
      *(float *)(psVar3 + 0xe) = *(float *)((char *)pCamera + 0xe0);
      *(float *)(psVar3 + 0x10) = *(float *)((char *)pCamera + 0xe4);
      Obj_TransformWorldPointToLocal(*(float *)(psVar3 + 0xc),*(float *)(psVar3 + 0xe),
                                     *(float *)(psVar3 + 0x10),(float *)(psVar3 + 6),
                                     (float *)(psVar3 + 8),(float *)(psVar3 + 10),
                                     *(int *)(psVar3 + 0x18));
      *(undefined *)((char *)pCamera + 0x13d) = 0;
    }
    if (*(u32 *)((char *)pCamera + 0x30) != *(u32 *)(psVar3 + 0x18)) {
      Obj_TransformLocalPointToWorld(*(float *)((char *)pCamera + 0xc),
                                     *(float *)((char *)pCamera + 0x10),
                                     *(float *)((char *)pCamera + 0x14),
                                     (float *)((char *)pCamera + 0x18),
                                     (float *)((char *)pCamera + 0x1c),
                                     (float *)((char *)pCamera + 0x20),
                                     *(int *)((char *)pCamera + 0x30));
      Obj_TransformLocalPointToWorld(*(float *)((char *)pCamera + 0xa8),
                                     *(float *)((char *)pCamera + 0xac),
                                     *(float *)((char *)pCamera + 0xb0),
                                     (float *)((char *)pCamera + 0xb8),
                                     (float *)((char *)pCamera + 0xbc),
                                     (float *)((char *)pCamera + 0xc0),
                                     *(int *)((char *)pCamera + 0x30));
      Obj_TransformWorldPointToLocal(*(float *)((char *)pCamera + 0x18),
                                     *(float *)((char *)pCamera + 0x1c),
                                     *(float *)((char *)pCamera + 0x20),
                                     (float *)((char *)pCamera + 0xc),
                                     (float *)((char *)pCamera + 0x10),
                                     (float *)((char *)pCamera + 0x14),*(int *)(psVar3 + 0x18))
      ;
      Obj_TransformWorldPointToLocal(*(float *)((char *)pCamera + 0xb8),
                                     *(float *)((char *)pCamera + 0xbc),
                                     *(float *)((char *)pCamera + 0xc0),
                                     (float *)((char *)pCamera + 0xa8),
                                     (float *)((char *)pCamera + 0xac),
                                     (float *)((char *)pCamera + 0xb0),*(int *)(psVar3 + 0x18));
      *(undefined4 *)((char *)pCamera + 0x30) = *(undefined4 *)(psVar3 + 0x18);
    }
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 += **(short **)(psVar3 + 0x18);
    }
    camcontrol_applyQueuedAction();
    if (gCamcontrolCurrentHandler != 0) {
      gCamcontrolCurrentHandler->handler->vtable->update((void *)pCamera);
      Obj_TransformLocalPointToWorld(*(float *)((char *)pCamera + 0xc),
                                     *(float *)((char *)pCamera + 0x10),
                                     *(float *)((char *)pCamera + 0x14),
                                     (float *)((char *)pCamera + 0x18),
                                     (float *)((char *)pCamera + 0x1c),
                                     (float *)((char *)pCamera + 0x20),
                                     *(int *)((char *)pCamera + 0x30));
      camcontrol_applyState((short *)pCamera);
    }
    camcontrol_applyQueuedAction();
    if (textActive == 0) {
      if (*(u32 *)((char *)pCamera + 0x11c) == 0) {
        uVar2 = camcontrol_findBestTarget((int)pCamera,psVar3);
        *(undefined4 *)((char *)pCamera + 0x124) = uVar2;
      }
      else {
        *(int *)((char *)pCamera + 0x124) = *(int *)((char *)pCamera + 0x11c);
      }
    }
    *(float *)((char *)pCamera + 0xa8) = *(float *)((char *)pCamera + 0xc);
    *(float *)((char *)pCamera + 0xac) = *(float *)((char *)pCamera + 0x10);
    *(float *)((char *)pCamera + 0xb0) = *(float *)((char *)pCamera + 0x14);
    *(float *)((char *)pCamera + 0xb8) = *(float *)((char *)pCamera + 0x18);
    *(float *)((char *)pCamera + 0xbc) = *(float *)((char *)pCamera + 0x1c);
    *(float *)((char *)pCamera + 0xc0) = *(float *)((char *)pCamera + 0x20);
    *(undefined *)((char *)pCamera + 0x140) = 0;
    *(float *)(psVar3 + 6) = gCamcontrolSavedFocusLocalX;
    *(float *)(psVar3 + 8) = gCamcontrolSavedFocusLocalY;
    *(float *)(psVar3 + 10) = gCamcontrolSavedFocusLocalZ;
    *(float *)(psVar3 + 0xc) = gCamcontrolSavedFocusWorldX;
    *(float *)(psVar3 + 0xe) = gCamcontrolSavedFocusWorldY;
    *(float *)(psVar3 + 0x10) = gCamcontrolSavedFocusWorldZ;
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 -= **(short **)(psVar3 + 0x18);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *Camera_getDefaultHandlerEntry(void)
{
  int i;

  i = 0;
  for (; i < gCamcontrolHandlerCount; i++) {
    if (gCamcontrolHandlerEntries[i]->actionId == CAMCONTROL_ACTION_DEFAULT) {
      return gCamcontrolHandlerEntries[i];
    }
  }
  return NULL;
}

void *Camera_GetFollowPos(void)
{
  return gCamcontrolCurrentHandler;
}

/* sda21 accessors. */
u32 Camera_getMode(void) { return gCamcontrolActiveActionId; }
u32 Camera_get(void) { return (u32)pCamera; }

void Camera_init(void *focus,f32 x,f32 y,f32 z)
{
  memset((void *)pCamera,0,sizeof(CamcontrolCameraState));
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
  CAMCONTROL_CAMERA->focusHeight = lbl_803E1684;
  gCamcontrolTargetState = 0;
}

void Camera_release(void)
{
  voxmaps_resetLoadedMaps();
  lbl_803DD4CB = -1;
}

void Camera_initialise(void)
{
  pCamera = gCamcontrolStateStorage;
  memset((void *)pCamera,0,sizeof(CamcontrolCameraState));
  voxmaps_initialise();
  gCamcontrolActiveActionId = -1;
  gCamcontrolCurrentHandlerIndex = -1;
  gCamcontrolQueuedActionId = -1;
  lbl_803DD4CC = 0;
  lbl_803DD4CB = -1;
  lbl_803DB992 = 0xffff;
}
#pragma peephole reset
#pragma scheduling reset
