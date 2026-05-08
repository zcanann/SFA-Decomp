#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CAM/camcontrol.h"
#include "main/objanim.h"
#include "string.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern uint FUN_80006c00();
extern undefined4 FUN_80017640();
extern int Obj_IsObjectAlive();
extern undefined8 FUN_800723a0();
extern undefined4 FUN_80081100();
extern undefined4 FUN_800e8794();
extern undefined4 camcontrol_findBestTarget();
extern undefined4 camcontrol_updateMoveAverage();
extern undefined4 camcontrol_applyState();
extern undefined8 camcontrol_applyQueuedAction();
extern int FUN_801113c0();
extern int FUN_8012ef0c();
extern int FUN_80133a28();
extern double FUN_8014cbcc();
extern double FUN_80183544();
extern f32 sqrtf(f32 x);
extern void getTabEntry(void *dst,int fileId,int offset,int size);
extern void fn_80023800(void *ptr);
extern void *mmAlloc(int size,int heap,int flags);
extern void fn_800E84D8(s16 actionNo);
extern void voxmaps_initialise(void);
extern void voxmaps_resetLoadedMaps(void);

extern void *gCamcontrolHandlers[20];
extern void *lbl_803A4228[20];
extern u8 lbl_803A4278[];
extern undefined4* DAT_803dd738;
extern undefined4 gCamcontrolTargetChanged;
extern short* gCamcontrolTargetReticle;
extern undefined4 DAT_803de140;
extern undefined4 gCamcontrolTargetState;
extern undefined4 gCamcontrolSavedActionMode;
extern undefined4 gCamcontrolSavedActionFlags;
extern undefined4 gCamcontrolSavedActionId;
extern undefined lbl_803DD4F8;
extern undefined4 lbl_803DD4FC;
extern s8 lbl_803DD500;
extern s8 lbl_803DD501;
extern undefined lbl_803DD502;
extern void *lbl_803DD504;
extern undefined4 lbl_803DD510;
extern undefined4 gCamcontrolCurrentHandler;
extern u8 gCamcontrolHandlerCount;
extern short* gCamcontrolState;
extern char sCamcontrolTriggeredCamActionLoadWarning[];
extern f64 DOUBLE_803e22d0;
extern f32 lbl_803DC074;
extern f32 lbl_803DE14C;
extern f32 lbl_803DE150;
extern f32 lbl_803DE154;
extern f32 lbl_803DE158;
extern f32 lbl_803DE15C;
extern f32 lbl_803DE160;
extern f32 lbl_803E1630;
extern f32 lbl_803E1680;
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;
extern f32 lbl_803E22BC;
extern f32 lbl_803E22F0;
extern f32 lbl_803E22F4;
extern f32 lbl_803E22F8;
extern f32 lbl_803E22FC;
extern f32 lbl_803E2300;
extern f32 lbl_803E1684;
extern s16 lbl_803DB992;
extern undefined lbl_803DD4CA;
extern s8 lbl_803DD4CB;
extern undefined4 lbl_803DD4CC;
extern int lbl_803DD514;
extern u8 lbl_803DD520;

typedef struct CamcontrolHandlerVTable {
  u8 pad00[0x10];
  void (*release)(void);
} CamcontrolHandlerVTable;

typedef struct CamcontrolHandler {
  CamcontrolHandlerVTable *vtable;
} CamcontrolHandler;

typedef struct CamcontrolCurrentHandler {
  u8 pad00[4];
  CamcontrolHandler *handler;
} CamcontrolCurrentHandler;

extern CamcontrolCurrentHandler *lbl_803DD51C;
extern int lbl_803DD4EC;
extern int lbl_803DD4F0;
extern int lbl_803DD4F4;
extern u32 lbl_803DD518;
extern u32 pCamera;

#define gCamcontrolQueuedActionMode lbl_803DD4F8
#define gCamcontrolQueuedActionBlendFrames lbl_803DD4FC
#define gCamcontrolQueuedActionPriority lbl_803DD500
#define gCamcontrolQueuedActionStartFlags lbl_803DD501
#define gCamcontrolQueuedActionPending lbl_803DD502
#define gCamcontrolQueuedActionData lbl_803DD504
#define gCamcontrolCurrentActionId lbl_803DD510

typedef struct CamcontrolTriggeredAction {
  u8 actionKind;
  u8 pad01[0xC];
  s8 triggerMode;
  u8 pad0E[2];
} CamcontrolTriggeredAction;

typedef struct CamcontrolQueuedActionParam {
  uint actionIndex;
  byte noBlendFlag;
} CamcontrolQueuedActionParam;

#define CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE1 1
#define CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2 2
#define CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION 3
#define CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET 4
#define CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED 1
#define CAMCONTROL_ACTION_DEFAULT 0x42
#define CAMCONTROL_ACTION_TRIGGERED 0x4B
#define CAMCONTROL_ACTION_TRIGGER_TYPE1 0x48
#define CAMCONTROL_ACTION_TRIGGER_TYPE2 0x47
#define CAMCONTROL_ACTION_NO_NONE 0
#define CAMCONTROL_SAVED_ACTION_NONE -1
#define CAMCONTROL_ACTION_INDEX_MASK 0x7F
#define CAMCONTROL_ACTION_FLAG_NO_BLEND 0x80
#define CAMCONTROL_ACTION_RECORD_SIZE 0x10
#define CAMCONTROL_QUEUED_ACTION_PARAM_SIZE sizeof(CamcontrolQueuedActionParam)
#define CAMCONTROL_ACTION_FILE_ID 0xB
#define CAMCONTROL_ACTION_HEAP 0xF
#define CAMCONTROL_DEFAULT_BLEND_FRAMES 0x78
#define CAMCONTROL_QUEUE_SENTINEL 0xFF

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
  bool bVar1;
  char cVar2;
  short sVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  byte bVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  double dVar12;
  
  psVar6 = gCamcontrolTargetReticle;
  iVar11 = *(int *)(gCamcontrolState + 0x124);
  if (gCamcontrolTargetReticle == (short *)0x0) {
    return;
  }
  iVar8 = FUN_80133a28();
  if (iVar8 != 0) {
    return;
  }
  if ((gCamcontrolTargetChanged != '\0') && (gCamcontrolTargetChanged = '\0', iVar11 != 0)) {
    cVar2 = *(char *)(gCamcontrolState + 0x138);
    if (cVar2 == '\x01') {
      FUN_80006824(0,0x3ff);
      FUN_80081100((double)lbl_803E22AC,psVar6,2);
    }
    else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
      FUN_80006824(0,0x402);
      FUN_80081100((double)lbl_803E22AC,psVar6,3);
    }
    else if (cVar2 != '\b') {
      FUN_80006824(0,0x288);
      FUN_80081100((double)lbl_803E22AC,psVar6,1);
    }
  }
  if (iVar11 != 0) {
    *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 4;
    uVar9 = FUN_80006c00(0);
    uVar10 = 0x100;
    bVar7 = *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
    if ((bVar7 == 4) || (bVar7 == 9)) {
      uVar10 = 0x900;
    }
    bVar1 = (uVar9 & uVar10) != 0;
    if ((*(byte *)(iVar11 + 0xaf) & 0x10) == 0) {
      if (bVar1) {
        *(byte *)(iVar11 + 0xaf) = *(byte *)(iVar11 + 0xaf) | 1;
      }
    }
    else if ((bVar1) && (iVar8 = FUN_8012ef0c(), iVar8 == 0)) {
      FUN_80006824(0,0x287);
    }
  }
  if (gCamcontrolTargetState == '\0') {
    if (lbl_803E22B0 < *(float *)(psVar6 + 0x4c)) {
      ObjAnim_AdvanceCurrentMove((double)lbl_803E22F0,(double)lbl_803DC074,(int)psVar6,
                                 (ObjAnimEventList *)0x0);
    }
    else if (iVar11 == 0) {
      *(undefined4 *)(gCamcontrolState + 0x128) = 0;
    }
    else {
      *(int *)(gCamcontrolState + 0x128) = iVar11;
      *(byte *)(gCamcontrolState + 0x138) =
           *(byte *)(*(int *)(iVar11 + 0x78) + (uint)*(byte *)(iVar11 + 0xe4) * 5 + 4) & 0xf;
      gCamcontrolTargetState = '\x03';
      gCamcontrolTargetChanged = '\x01';
    }
  }
  else if ((*(int *)(gCamcontrolState + 0x128) == iVar11) ||
          (*(float *)(psVar6 + 0x4c) < lbl_803E22AC)) {
    ObjAnim_AdvanceCurrentMove((double)lbl_803E22F4,(double)lbl_803DC074,(int)psVar6,
                               (ObjAnimEventList *)0x0);
  }
  else {
    gCamcontrolTargetState = '\0';
    if (iVar11 == 0) {
      cVar2 = *(char *)(gCamcontrolState + 0x138);
      if (cVar2 == '\x01') {
        FUN_80006824(0,0x400);
      }
      else if ((cVar2 == '\x04') || (cVar2 == '\t')) {
        FUN_80006824(0,0x401);
      }
      else if (cVar2 != '\b') {
        FUN_80006824(0,0x289);
      }
    }
    else {
      ObjAnim_SetMoveProgress((double)lbl_803E22B0,(ObjAnimComponent *)psVar6);
    }
  }
  iVar11 = Obj_IsObjectAlive(*(int *)(gCamcontrolState + 0x128));
  if (iVar11 == 0) {
    *(undefined4 *)(gCamcontrolState + 0x128) = 0;
  }
  if ((gCamcontrolTargetState != '\x03') || (*(int *)(gCamcontrolState + 0x128) == 0))
  goto LAB_80102ab4;
  if ((*(byte *)(*(int *)(gCamcontrolState + 0x128) + 0xaf) & 0x10) == 0) {
    *(byte *)(gCamcontrolState + 0x141) = *(byte *)(gCamcontrolState + 0x141) & 0xdf;
  }
  else {
    *(byte *)(gCamcontrolState + 0x141) = *(byte *)(gCamcontrolState + 0x141) | 0x20;
  }
  iVar11 = *(int *)(gCamcontrolState + 0x128);
  sVar3 = *(short *)(iVar11 + 0x46);
  if (sVar3 == 0x49f) {
LAB_80102994:
    dVar12 = FUN_80183544(iVar11);
  }
  else {
    if (sVar3 < 0x49f) {
      if (sVar3 != 0x281) {
        if (sVar3 < 0x281) {
          if (sVar3 != 0x13a) {
            if (sVar3 < 0x13a) {
              if (sVar3 == 0x31) {
                dVar12 = (double)lbl_803E22AC;
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
              iVar8 = FUN_801113c0(iVar11);
              if (iVar8 == 0) {
                dVar12 = (double)lbl_803E22AC;
              }
              else {
                dVar12 = (double)(**(code **)(*DAT_803dd738 + 0x60))(iVar11);
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
    dVar12 = FUN_8014cbcc(iVar11);
  }
LAB_801029e0:
  if (((double)lbl_803E22B0 < dVar12) ||
     ((double)*(float *)(gCamcontrolState + 0x134) <= (double)lbl_803E22B0)) {
    if (((double)lbl_803E22B4 < dVar12) ||
       ((double)*(float *)(gCamcontrolState + 0x134) <= (double)lbl_803E22B4)) {
      if (((double)lbl_803E22B8 < dVar12) ||
         ((double)*(float *)(gCamcontrolState + 0x134) <= (double)lbl_803E22B8)) {
        if ((dVar12 <= (double)lbl_803E22BC) &&
           ((double)lbl_803E22BC < (double)*(float *)(gCamcontrolState + 0x134))) {
          FUN_80081100((double)lbl_803E22AC,psVar6,4);
        }
      }
      else {
        FUN_80081100((double)lbl_803E22AC,psVar6,4);
      }
    }
    else {
      FUN_80081100((double)lbl_803E22AC,psVar6,4);
    }
  }
  else {
    FUN_80081100((double)lbl_803E22AC,psVar6,4);
  }
  *(float *)(gCamcontrolState + 0x134) = (float)dVar12;
LAB_80102ab4:
  fVar4 = lbl_803E22F8 * *(float *)(psVar6 + 0x4c);
  fVar5 = lbl_803E22B0;
  if ((lbl_803E22B0 <= fVar4) && (fVar5 = fVar4, lbl_803E22F8 < fVar4)) {
    fVar5 = lbl_803E22F8;
  }
  *(char *)(psVar6 + 0x1b) = (char)(int)fVar5;
  DAT_803de140 = 0x400;
  *psVar6 = (short)(int)(lbl_803E22FC * lbl_803DC074 +
                        (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) -
                               DOUBLE_803e22d0));
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int Camera_isZooming(void)
{
  return *(float *)((char *)pCamera + 0xf4) > lbl_803E1630;
}
#pragma scheduling reset

void Camera_func15(int x)
{
  *(int *)((char *)pCamera + 0x120) = x;
}

void Camera_setTarget(int x)
{
  *(int *)((char *)pCamera + 0x11c) = x;
  *(int *)((char *)pCamera + 0x124) = x;
}

int Camera_getTarget(void)
{
  return *(int *)((char *)pCamera + 0x124);
}

int Camera_getOverrideTarget(void)
{
  return *(int *)((char *)pCamera + 0x11c);
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
void camcontrol_getRelativePosition(f32 param_1,int param_2,float *param_3,float *param_4,
                                    float *param_5,float *param_6,int param_7)
{
  int iVar1;

  iVar1 = *(int *)((char *)pCamera + 0xa4);
  if (param_7 != 0) {
    *param_3 = *(float *)(param_2 + 0xc) - *(float *)(iVar1 + 0xc);
    *param_4 = *(float *)(param_2 + 0x10) - (*(float *)(iVar1 + 0x10) + param_1);
    *param_5 = *(float *)(param_2 + 0x14) - *(float *)(iVar1 + 0x14);
  }
  else {
    *param_3 = *(float *)(param_2 + 0x18) - *(float *)(iVar1 + 0x18);
    *param_4 = *(float *)(param_2 + 0x1c) - (*(float *)(iVar1 + 0x1c) + param_1);
    *param_5 = *(float *)(param_2 + 0x20) - *(float *)(iVar1 + 0x20);
  }
  if (param_6 != (float *)0x0) {
    *param_6 = *param_3 * *param_3 + *param_5 * *param_5;
    if (*param_6 > lbl_803E1630) {
      *param_6 = sqrtf(*param_6);
    }
    if (*param_6 < lbl_803E1680) {
      *param_6 = lbl_803E1680;
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
  *(float *)((char *)pCamera + 0xc) += x;
  *(float *)((char *)pCamera + 0x10) += y;
  *(float *)((char *)pCamera + 0x14) += z;
}

#pragma scheduling off
void Camera_overridePos(f32 x,f32 y,f32 z)
{
  *(u8 *)((char *)pCamera + 0x13d) = 1;
  *(float *)((char *)pCamera + 0xdc) = x;
  *(float *)((char *)pCamera + 0xe0) = y;
  *(float *)((char *)pCamera + 0xe4) = z;
}
#pragma scheduling reset

void Camera_setFocus(void *target)
{
  if (target == *(void **)((char *)pCamera + 0xa4)) {
    return;
  }
  *(void **)((char *)pCamera + 0xa4) = target;
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
void camcontrol_loadTriggeredCamAction(int triggerType,uint actionNo,char triggerMode)
{
  uint handlerCount;
  int handlerIndex;
  void **handlerEntry;
  int blendFrames;
  CamcontrolTriggeredAction *camAction;
  int actionOffset;
  int loadedActionNo;
  CamcontrolQueuedActionParam triggerType2Param;
  CamcontrolQueuedActionParam triggerType1Param;
  
  if (triggerType == CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2) {
    triggerType2Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
    triggerType2Param.noBlendFlag = (byte)(actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND);
    if ((actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND) == 0) {
      blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
    }
    else {
      blendFrames = 0;
    }
    Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE2,1,0,CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                   &triggerType2Param,blendFrames,CAMCONTROL_QUEUE_SENTINEL);
    return;
  }
  if (triggerType < CAMCONTROL_TRIGGER_KIND_QUEUE_TYPE2) {
    if ((triggerType != 0) && (-1 < triggerType)) {
      triggerType1Param.actionIndex = actionNo & CAMCONTROL_ACTION_INDEX_MASK;
      triggerType1Param.noBlendFlag = (byte)actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND;
      *(undefined *)((int)gCamcontrolState + 0x139) = 1;
      if ((actionNo & CAMCONTROL_ACTION_FLAG_NO_BLEND) == 0) {
        blendFrames = CAMCONTROL_DEFAULT_BLEND_FRAMES;
      }
      else {
        blendFrames = 0;
      }
      Camera_setMode(CAMCONTROL_ACTION_TRIGGER_TYPE1,1,0,CAMCONTROL_QUEUED_ACTION_PARAM_SIZE,
                     &triggerType1Param,blendFrames,CAMCONTROL_QUEUE_SENTINEL);
      return;
    }
  }
  else {
    if (triggerType == CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET) {
      Camera_setMode(actionNo + CAMCONTROL_ACTION_DEFAULT,1,0,0,0,
                     CAMCONTROL_DEFAULT_BLEND_FRAMES,CAMCONTROL_QUEUE_SENTINEL);
      return;
    }
    if (triggerType < CAMCONTROL_TRIGGER_KIND_DEFAULT_ACTION_OFFSET) {
      Camera_setMode(CAMCONTROL_ACTION_DEFAULT,0,1,0,0,CAMCONTROL_DEFAULT_BLEND_FRAMES,
                     CAMCONTROL_QUEUE_SENTINEL);
      return;
    }
  }
  if (actionNo == CAMCONTROL_ACTION_NO_NONE) {
    OSReport(sCamcontrolTriggeredCamActionLoadWarning,actionNo);
    actionOffset = 0;
    loadedActionNo = 1;
  }
  else {
    actionOffset = (actionNo - 1) * CAMCONTROL_ACTION_RECORD_SIZE;
    loadedActionNo = actionNo;
  }
  camAction = (CamcontrolTriggeredAction *)mmAlloc(CAMCONTROL_ACTION_RECORD_SIZE,CAMCONTROL_ACTION_HEAP,0);
  if (camAction != (CamcontrolTriggeredAction *)0x0) {
    getTabEntry(camAction,CAMCONTROL_ACTION_FILE_ID,actionOffset,CAMCONTROL_ACTION_RECORD_SIZE);
    camAction->triggerMode = triggerMode;
    fn_800E84D8((short)loadedActionNo);
    if ((((gCamcontrolCurrentActionId == CAMCONTROL_ACTION_DEFAULT) ||
         (gCamcontrolCurrentActionId == CAMCONTROL_ACTION_TRIGGERED)) ||
        (gCamcontrolCurrentActionId == CAMCONTROL_ACTION_TRIGGER_TYPE1)) ||
       (gCamcontrolCurrentActionId == CAMCONTROL_ACTION_TRIGGER_TYPE2)) {
      if (camAction->actionKind == CAMCONTROL_TRIGGERED_ACTION_KIND_TRIGGERED) {
        Camera_setMode(CAMCONTROL_ACTION_TRIGGERED,1,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
      }
      else {
        Camera_setMode(CAMCONTROL_ACTION_DEFAULT,0,2,CAMCONTROL_ACTION_RECORD_SIZE,
                       camAction,0,CAMCONTROL_QUEUE_SENTINEL);
      }
    }
    else {
      handlerIndex = 0;
      handlerEntry = gCamcontrolHandlers;
      for (handlerCount = (uint)gCamcontrolHandlerCount; handlerCount != 0;
           handlerCount = handlerCount - 1) {
        if (*(short *)*handlerEntry == CAMCONTROL_ACTION_DEFAULT) {
          handlerIndex = (int)gCamcontrolHandlers[handlerIndex];
          goto LAB_80102f3c;
        }
        handlerEntry = handlerEntry + 1;
        handlerIndex = handlerIndex + 1;
      }
      handlerIndex = 0;
LAB_80102f3c:
      (**(code **)(**(int **)(handlerIndex + 4) + 0x10))(camAction,
                                                          CAMCONTROL_ACTION_RECORD_SIZE);
    }
    fn_80023800(camAction);
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
void *Camera_getCamActionsBinEntry(int actionNo)
{
  void *camAction;

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
 * Function: camcontrol_releaseCurrentHandler
 * EN v1.0 Address: 0x80102F08
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x801031A4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_releaseCurrentHandler(void)
{
  if (lbl_803DD51C != NULL) {
    lbl_803DD51C->handler->vtable->release();
  }
  return;
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
void camcontrol_queueSavedAction(undefined4 param_1,undefined param_2)
{
  if (lbl_803DD4F4 != CAMCONTROL_SAVED_ACTION_NONE) {
    Camera_setMode(lbl_803DD4F4,lbl_803DD4F0,lbl_803DD4EC,0,0,param_1,param_2);
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
    fn_80023800(gCamcontrolQueuedActionData);
    gCamcontrolQueuedActionData = (void *)0x0;
    gCamcontrolQueuedActionPending = 0;
  }
  gCamcontrolCurrentActionId = actionId;
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
void Camera_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 uVar2;
  short *psVar3;
  undefined8 uVar4;
  
  iVar1 = FUN_80133a28();
  psVar3 = *(short **)(gCamcontrolState + 0x52);
  if (psVar3 == (short *)0x0) {
    psVar3 = gCamcontrolState;
    psVar3[0x92] = 0;
    psVar3[0x93] = 0;
    psVar3 = gCamcontrolState;
    psVar3[0x8e] = 0;
    psVar3[0x8f] = 0;
  }
  else {
    lbl_803DE160 = *(float *)(psVar3 + 6);
    lbl_803DE15C = *(float *)(psVar3 + 8);
    lbl_803DE158 = *(float *)(psVar3 + 10);
    lbl_803DE154 = *(float *)(psVar3 + 0xc);
    lbl_803DE150 = *(float *)(psVar3 + 0xe);
    lbl_803DE14C = *(float *)(psVar3 + 0x10);
    camcontrol_updateMoveAverage((int)gCamcontrolState,(int)psVar3);
    if (*(char *)((int)gCamcontrolState + 0x13d) != '\0') {
      *(undefined4 *)(psVar3 + 0xc) = *(undefined4 *)(gCamcontrolState + 0x6e);
      *(undefined4 *)(psVar3 + 0xe) = *(undefined4 *)(gCamcontrolState + 0x70);
      *(undefined4 *)(psVar3 + 0x10) = *(undefined4 *)(gCamcontrolState + 0x72);
      param_2 = (double)*(float *)(psVar3 + 0xe);
      param_3 = (double)*(float *)(psVar3 + 0x10);
      FUN_800068f4((double)*(float *)(psVar3 + 0xc),param_2,param_3,(float *)(psVar3 + 6),
                   (float *)(psVar3 + 8),(float *)(psVar3 + 10),*(int *)(psVar3 + 0x18));
      *(undefined *)((int)gCamcontrolState + 0x13d) = 0;
    }
    if (*(int *)(gCamcontrolState + 0x18) != *(int *)(psVar3 + 0x18)) {
      FUN_800068f8((double)*(float *)(gCamcontrolState + 6),(double)*(float *)(gCamcontrolState + 8),
                   (double)*(float *)(gCamcontrolState + 10),(float *)(gCamcontrolState + 0xc),
                   (float *)(gCamcontrolState + 0xe),(float *)(gCamcontrolState + 0x10),
                   *(int *)(gCamcontrolState + 0x18));
      FUN_800068f8((double)*(float *)(gCamcontrolState + 0x54),(double)*(float *)(gCamcontrolState + 0x56),
                   (double)*(float *)(gCamcontrolState + 0x58),(float *)(gCamcontrolState + 0x5c),
                   (float *)(gCamcontrolState + 0x5e),(float *)(gCamcontrolState + 0x60),
                   *(int *)(gCamcontrolState + 0x18));
      FUN_800068f4((double)*(float *)(gCamcontrolState + 0xc),(double)*(float *)(gCamcontrolState + 0xe),
                   (double)*(float *)(gCamcontrolState + 0x10),(float *)(gCamcontrolState + 6),
                   (float *)(gCamcontrolState + 8),(float *)(gCamcontrolState + 10),*(int *)(psVar3 + 0x18))
      ;
      param_2 = (double)*(float *)(gCamcontrolState + 0x5e);
      param_3 = (double)*(float *)(gCamcontrolState + 0x60);
      FUN_800068f4((double)*(float *)(gCamcontrolState + 0x5c),param_2,param_3,
                   (float *)(gCamcontrolState + 0x54),(float *)(gCamcontrolState + 0x56),
                   (float *)(gCamcontrolState + 0x58),*(int *)(psVar3 + 0x18));
      *(undefined4 *)(gCamcontrolState + 0x18) = *(undefined4 *)(psVar3 + 0x18);
    }
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 + **(short **)(psVar3 + 0x18);
    }
    camcontrol_applyQueuedAction();
    if (gCamcontrolCurrentHandler != 0) {
      (**(code **)(**(int **)(gCamcontrolCurrentHandler + 4) + 8))(gCamcontrolState);
      param_2 = (double)*(float *)(gCamcontrolState + 8);
      param_3 = (double)*(float *)(gCamcontrolState + 10);
      FUN_800068f8((double)*(float *)(gCamcontrolState + 6),param_2,param_3,
                   (float *)(gCamcontrolState + 0xc),(float *)(gCamcontrolState + 0xe),
                   (float *)(gCamcontrolState + 0x10),*(int *)(gCamcontrolState + 0x18));
      camcontrol_applyState(gCamcontrolState);
    }
    uVar4 = camcontrol_applyQueuedAction();
    if (iVar1 == 0) {
      if (*(int *)(gCamcontrolState + 0x8e) == 0) {
        uVar2 = camcontrol_findBestTarget(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8);
        *(undefined4 *)(gCamcontrolState + 0x92) = uVar2;
      }
      else {
        *(int *)(gCamcontrolState + 0x92) = *(int *)(gCamcontrolState + 0x8e);
      }
    }
    *(undefined4 *)(gCamcontrolState + 0x54) = *(undefined4 *)(gCamcontrolState + 6);
    *(undefined4 *)(gCamcontrolState + 0x56) = *(undefined4 *)(gCamcontrolState + 8);
    *(undefined4 *)(gCamcontrolState + 0x58) = *(undefined4 *)(gCamcontrolState + 10);
    *(undefined4 *)(gCamcontrolState + 0x5c) = *(undefined4 *)(gCamcontrolState + 0xc);
    *(undefined4 *)(gCamcontrolState + 0x5e) = *(undefined4 *)(gCamcontrolState + 0xe);
    *(undefined4 *)(gCamcontrolState + 0x60) = *(undefined4 *)(gCamcontrolState + 0x10);
    *(undefined *)(gCamcontrolState + 0xa0) = 0;
    *(float *)(psVar3 + 6) = lbl_803DE160;
    *(float *)(psVar3 + 8) = lbl_803DE15C;
    *(float *)(psVar3 + 10) = lbl_803DE158;
    *(float *)(psVar3 + 0xc) = lbl_803DE154;
    *(float *)(psVar3 + 0xe) = lbl_803DE150;
    *(float *)(psVar3 + 0x10) = lbl_803DE14C;
    if (*(short **)(psVar3 + 0x18) != (short *)0x0) {
      *psVar3 = *psVar3 - **(short **)(psVar3 + 0x18);
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *Camera_func08(void)
{
  void **entry;
  int i;

  i = 0;
  entry = lbl_803A4228;
  for (; i < lbl_803DD520; i++) {
    if (*(u16 *)*entry == CAMCONTROL_ACTION_DEFAULT) {
      return lbl_803A4228[i];
    }
    entry++;
  }
  return NULL;
}

void *Camera_GetFollowPos(void)
{
  return lbl_803DD51C;
}

/* sda21 accessors. */
u32 Camera_getMode(void) { return lbl_803DD518; }
u32 Camera_get(void) { return pCamera; }

void Camera_init(void *focus,f32 x,f32 y,f32 z)
{
  memset((void *)pCamera,0,0x144);
  *(f32 *)((char *)pCamera + 0x0c) = x;
  *(f32 *)((char *)pCamera + 0x10) = y;
  *(f32 *)((char *)pCamera + 0x14) = z;
  *(f32 *)((char *)pCamera + 0x18) = x;
  *(f32 *)((char *)pCamera + 0x1c) = y;
  *(f32 *)((char *)pCamera + 0x20) = z;
  *(f32 *)((char *)pCamera + 0xa8) = x;
  *(f32 *)((char *)pCamera + 0xac) = y;
  *(f32 *)((char *)pCamera + 0xb0) = z;
  *(f32 *)((char *)pCamera + 0xb8) = x;
  *(f32 *)((char *)pCamera + 0xbc) = y;
  *(f32 *)((char *)pCamera + 0xc0) = z;
  *(void **)((char *)pCamera + 0xa4) = focus;
  *(f32 *)((char *)pCamera + 0xb4) = lbl_803E1684;
  lbl_803DD4CA = 0;
}

void Camera_release(void)
{
  voxmaps_resetLoadedMaps();
  lbl_803DD4CB = -1;
}

void Camera_initialise(void)
{
  pCamera = (u32)lbl_803A4278;
  memset((void *)pCamera,0,0x144);
  voxmaps_initialise();
  lbl_803DD518 = -1;
  lbl_803DD514 = -1;
  gCamcontrolCurrentActionId = -1;
  lbl_803DD4CC = 0;
  lbl_803DD4CB = -1;
  lbl_803DB992 = 0xffff;
}
#pragma peephole reset
#pragma scheduling reset
