#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CAM/camcontrol.h"
#include "main/objanim.h"
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
extern void getTabEntry(void *dst,int fileId,int offset,int size);
extern void mm_free(void *ptr);
extern void *mmAlloc(int size,int heap,int flags);
extern void SaveGame_setCamActionNo(s16 actionNo);
extern void voxmaps_initialise(void);
extern void voxmaps_resetLoadedMaps(void);

extern void *gCamcontrolHandlers[20];
extern u8 gCamcontrolStateStorage[];
extern undefined4* gBaddieControlInterface;
extern u8 gCamcontrolTargetChanged;
extern short* gCamcontrolTargetReticle;
extern u16 lbl_803DD4C8;
extern u8 gCamcontrolTargetState;
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

static inline CamcontrolBaddieControlInterface *camcontrol_GetBaddieControlInterface(void) {
  return (CamcontrolBaddieControlInterface *)*gBaddieControlInterface;
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
  byte cVar2;
  short sVar3;
  float fVar4;
  int iVar11;
  short *psVar6;
  int buttonPressed;
  byte bVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  f32 targetDistance;
  
  iVar11 = *(int *)(pCamera + 0x124);
  psVar6 = gCamcontrolTargetReticle;
  buttonPressed = false;
  if (psVar6 == (short *)0x0) {
    return;
  }
  iVar8 = gameTextFn_80134be8();
  if (iVar8 != 0) {
    return;
  }
  if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', iVar11 != 0)) {
    cVar2 = *(byte *)(pCamera + 0x138);
    if (cVar2 == 1) {
      Sfx_PlayFromObject(0,0x3ff);
      objShowButtonGlow(psVar6,lbl_803E162C,2);
    }
    else if ((cVar2 == 4) || (cVar2 == 9)) {
      Sfx_PlayFromObject(0,0x402);
      objShowButtonGlow(psVar6,lbl_803E162C,3);
    }
    else if (cVar2 != 8) {
      Sfx_PlayFromObject(0,0x288);
      objShowButtonGlow(psVar6,lbl_803E162C,1);
    }
  }
  if (iVar11 != 0) {
    *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 4;
    uVar9 = getButtonsJustPressed(0);
    uVar10 = 0x100;
    bVar7 = *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
    if ((bVar7 == 4) || (bVar7 == 9)) {
      uVar10 = 0x900;
    }
    if ((uVar9 & uVar10) != 0) {
      buttonPressed = true;
    }
    if ((*(byte *)(iVar11 + 0xaf) & 0x10) == 0) {
      if (buttonPressed) {
        *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 1;
      }
    }
    else if ((buttonPressed) && (iVar8 = isTalkingToNpc(), iVar8 == 0)) {
      Sfx_PlayFromObject(0,0x287);
    }
  }
  if (gCamcontrolTargetState == '\0') {
    if (*(float *)(psVar6 + 0x4c) <= lbl_803E1630) {
      if (iVar11 == 0) {
        *(undefined4 *)(pCamera + 0x128) = 0;
      }
      else {
        *(int *)(pCamera + 0x128) = iVar11;
        *(byte *)(pCamera + 0x138) =
             *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
        gCamcontrolTargetState = '\x03';
        gCamcontrolTargetChanged = '\x01';
      }
    }
    else {
      ObjAnim_AdvanceCurrentMove(lbl_803E1670,timeDelta,(int)psVar6,
                                 (ObjAnimEventList *)0x0);
    }
  }
  else if ((*(int *)(pCamera + 0x128) == iVar11) ||
          (*(float *)(psVar6 + 0x4c) < lbl_803E162C)) {
    ObjAnim_AdvanceCurrentMove(lbl_803E1674,timeDelta,(int)psVar6,
                               (ObjAnimEventList *)0x0);
  }
  else {
    gCamcontrolTargetState = '\0';
    if (iVar11 == 0) {
      cVar2 = *(byte *)(pCamera + 0x138);
      if (cVar2 == 1) {
        Sfx_PlayFromObject(0,0x400);
      }
      else if ((cVar2 == 4) || (cVar2 == 9)) {
        Sfx_PlayFromObject(0,0x401);
      }
      else if (cVar2 != 8) {
        Sfx_PlayFromObject(0,0x289);
      }
    }
    else {
      ObjAnim_SetMoveProgress(lbl_803E1630,(ObjAnimComponent *)psVar6);
    }
  }
  iVar11 = Obj_IsObjectAlive(*(int *)(pCamera + 0x128));
  if (iVar11 == 0) {
    *(undefined4 *)(pCamera + 0x128) = 0;
  }
  if ((gCamcontrolTargetState != '\x03') || (*(int *)(pCamera + 0x128) == 0))
  goto LAB_80102ab4;
  if ((*(byte *)(*(int *)(pCamera + 0x128) + 0xaf) & 0x10) == 0) {
    *(byte *)(pCamera + 0x141) = *(byte *)(pCamera + 0x141) & 0xdf;
  }
  else {
    *(byte *)(pCamera + 0x141) = *(byte *)(pCamera + 0x141) | 0x20;
  }
  iVar11 = *(int *)(pCamera + 0x128);
  sVar3 = *(short *)(iVar11 + 0x46);
  if (sVar3 == 0x49f) {
LAB_80102994:
    targetDistance = fn_80183204(iVar11);
  }
  else {
    if (sVar3 < 0x49f) {
      if (sVar3 != 0x281) {
        if (sVar3 < 0x281) {
          if (sVar3 != 0x13a) {
            if (sVar3 < 0x13a) {
              if (sVar3 == 0x31) {
                targetDistance = lbl_803E162C;
                goto LAB_801029e0;
              }
              if (sVar3 < 0x31) {
                if (sVar3 != 0x11) goto LAB_801029ac;
              }
              else if (sVar3 != 0xd8) goto LAB_801029ac;
            }
            else if ((sVar3 != 0x25d) && ((0x25c < sVar3 || (sVar3 != 0x251)))) goto LAB_801029ac;
          }
        }
        else if (sVar3 != 0x3fe) {
          if (sVar3 < 0x3fe) {
            if (sVar3 == 0x3de) goto LAB_80102994;
            if ((0x3dd < sVar3) || (sVar3 != 0x369)) goto LAB_801029ac;
          }
          else if (sVar3 < 0x457) {
            if (sVar3 != 0x427) goto LAB_801029ac;
          }
          else if (0x458 < sVar3) goto LAB_801029ac;
        }
      }
    }
    else if (sVar3 != 0x613) {
      if (sVar3 < 0x613) {
        if (sVar3 != 0x58b) {
          if (sVar3 < 0x58b) {
            if ((sVar3 != 0x4d7) && ((0x4d6 < sVar3 || (sVar3 != 0x4ac)))) {
LAB_801029ac:
              iVar8 = dll_19_func1B(iVar11);
              if (iVar8 == 0) {
                targetDistance = lbl_803E162C;
              }
              else {
                targetDistance =
                    camcontrol_GetBaddieControlInterface()->getTargetReticleDistance(iVar11);
              }
              goto LAB_801029e0;
            }
          }
          else if ((sVar3 != 0x5e1) && (((0x5e0 < sVar3 || (0x5b9 < sVar3)) || (sVar3 < 0x5b7))))
          goto LAB_801029ac;
        }
      }
      else if (sVar3 != 0x842) {
        if (sVar3 < 0x842) {
          if (sVar3 < 0x6a2) {
            if (sVar3 != 0x642) goto LAB_801029ac;
          }
          else if (0x6a5 < sVar3) goto LAB_801029ac;
        }
        else if ((sVar3 != 0x851) && ((0x850 < sVar3 || (sVar3 != 0x84b)))) goto LAB_801029ac;
      }
    }
    targetDistance = fn_8014C5D0(iVar11);
  }
LAB_801029e0:
  if ((lbl_803E1630 < targetDistance) ||
     (*(float *)(pCamera + 0x134) <= lbl_803E1630)) {
    if ((lbl_803E1634 < targetDistance) ||
       (*(float *)(pCamera + 0x134) <= lbl_803E1634)) {
      if ((lbl_803E1638 < targetDistance) ||
         (*(float *)(pCamera + 0x134) <= lbl_803E1638)) {
        if ((targetDistance <= lbl_803E163C) &&
           (lbl_803E163C < *(float *)(pCamera + 0x134))) {
          objShowButtonGlow(psVar6,lbl_803E162C,4);
        }
      }
      else {
        objShowButtonGlow(psVar6,lbl_803E162C,4);
      }
    }
    else {
      objShowButtonGlow(psVar6,lbl_803E162C,4);
    }
  }
  else {
    objShowButtonGlow(psVar6,lbl_803E162C,4);
  }
  *(float *)(pCamera + 0x134) = targetDistance;
LAB_80102ab4:
  fVar4 = lbl_803E1678 * *(float *)(psVar6 + 0x4c);
  if (fVar4 < lbl_803E1630) {
    fVar4 = lbl_803E1630;
  }
  else if (lbl_803E1678 < fVar4) {
    fVar4 = lbl_803E1678;
  }
  *(u8 *)(psVar6 + 0x1b) = (int)fVar4;
  lbl_803DD4C8 = 0x400;
  *psVar6 = (short)(int)(lbl_803E167C * timeDelta + (float)*psVar6);
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

void Camera_func15(int x)
{
  CAMCONTROL_CAMERA->func15Value = x;
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
                                    float *outZ,float *outDistanceXZ,int useWorldPosition)
{
  int focusObj;

  focusObj = *(int *)((char *)pCamera + 0xa4);
  if (useWorldPosition != 0) {
    *outX = *(float *)(targetObj + 0xc) - *(float *)(focusObj + 0xc);
    *outY = *(float *)(targetObj + 0x10) - (*(float *)(focusObj + 0x10) + heightOffset);
    *outZ = *(float *)(targetObj + 0x14) - *(float *)(focusObj + 0x14);
  }
  else {
    *outX = *(float *)(targetObj + 0x18) - *(float *)(focusObj + 0x18);
    *outY = *(float *)(targetObj + 0x1c) - (*(float *)(focusObj + 0x1c) + heightOffset);
    *outZ = *(float *)(targetObj + 0x20) - *(float *)(focusObj + 0x20);
  }
  if (outDistanceXZ != (float *)0x0) {
    *outDistanceXZ = *outX * *outX + *outZ * *outZ;
    if (*outDistanceXZ > lbl_803E1630) {
      *outDistanceXZ = sqrtf(*outDistanceXZ);
    }
    if (*outDistanceXZ < lbl_803E1680) {
      *outDistanceXZ = lbl_803E1680;
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
    *(undefined *)((int)pCamera + 0x139) = 1;
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
void camcontrol_release(void)
{
  CamcontrolHandlerEntry *currentHandler;

  currentHandler = gCamcontrolCurrentHandler;
  if (currentHandler != NULL) {
    currentHandler->handler->vtable->actionCallback();
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
