#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CF/laser.h"
#include "main/dll/zBomb.h"

extern undefined4 FUN_8000a380();
extern int fn_8001FFB4(int eventId);
extern void fn_800200E8(int eventId,int value);
extern void FUN_80026e00(int param_1,int param_2,float *param_3);
extern void fn_80041018(int obj);
extern undefined4 FUN_80097734();

extern undefined4* lbl_803DCA68;
extern undefined4* DAT_803dcaa8;
extern undefined4* lbl_803DCAAC;
extern s32 lbl_80329B78[];
extern char sTextBlockInitNoLongerSupported[];
extern char sLaserInitNoLongerSupported[];
extern f32 FLOAT_803db414;
extern f32 FLOAT_803e648c;
extern f32 FLOAT_803e6494;
extern f32 FLOAT_803e64ac;
extern f32 FLOAT_803e64b0;
extern f32 FLOAT_803e64c4;
extern f32 FLOAT_803e64c8;
extern f32 FLOAT_803e64cc;
extern f32 FLOAT_803e64d0;
extern f32 FLOAT_803e64d4;

typedef struct DfpTargetBlockPoint {
  f32 x;
  f32 y;
  f32 z;
} DfpTargetBlockPoint;

typedef struct DfpTargetBlockState {
  u32 controlId;
  DfpTargetBlockPoint floorPoints[8];
  s16 stateSfxId;
  s16 completionSfxId;
  s8 floorPointCount;
  s8 mode;
  u8 stateSfxReady;
  u8 completionSfxReady;
} DfpTargetBlockState;

typedef enum DfpTargetBlockMode {
  DFPTARGETBLOCK_MODE_RAISING = 0,
  DFPTARGETBLOCK_MODE_ACTIVE = 1,
  DFPTARGETBLOCK_MODE_RESETTING = 2,
  DFPTARGETBLOCK_MODE_LOWERING = 3,
  DFPTARGETBLOCK_MODE_SETTLED = 4,
} DfpTargetBlockMode;

/*
 * --INFO--
 *
 * Function: dfptargetblock_update
 * EN v1.0 Address: 0x80208B70
 * EN v1.0 Size: 524b
 */
void dfptargetblock_update(int param_1)
{
  char cVar1;
  float fVar2;
  undefined uVar3;
  int iVar4;
  DfpTargetBlockState *state;
  undefined auStack_28[12];
  float local_1c;
  float local_18;
  float local_14;

  state = *(DfpTargetBlockState **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    local_1c = FLOAT_803e648c;
    local_18 = FLOAT_803e64c4;
    local_14 = FLOAT_803e648c;
    FUN_80097734((double)FLOAT_803e64c8,(double)FLOAT_803e64c4,(double)FLOAT_803e64c4,
                 (double)FLOAT_803e64b0,param_1,5,1,2,0x32,auStack_28,0);
  }
  else {
    if (state->completionSfxReady == '\0') {
      uVar3 = fn_8001FFB4((int)state->completionSfxId);
      state->completionSfxReady = uVar3;
    }
    if (state->stateSfxReady == '\0') {
      uVar3 = fn_8001FFB4((int)state->stateSfxId);
      state->stateSfxReady = uVar3;
    }
    fVar2 = FLOAT_803e64ac;
    if (((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
       (cVar1 = state->mode, cVar1 != DFPTARGETBLOCK_MODE_SETTLED)) {
      if ((cVar1 == DFPTARGETBLOCK_MODE_RAISING) || (cVar1 == DFPTARGETBLOCK_MODE_RESETTING)) {
        if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc)) {
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803db414;
          if (*(float *)(iVar4 + 0xc) <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc);
            state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
          }
        }
      }
      else if (cVar1 == DFPTARGETBLOCK_MODE_LOWERING) {
        if (*(float *)(iVar4 + 0xc) - FLOAT_803e64ac <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = FLOAT_803e6494 * FLOAT_803db414 + *(float *)(param_1 + 0x10);
          fVar2 = *(float *)(iVar4 + 0xc) - fVar2;
          if (*(float *)(param_1 + 0x10) <= fVar2) {
            *(float *)(param_1 + 0x10) = fVar2;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
            fn_800200E8((int)state->completionSfxId,1);
          }
        }
      }
      else if (state->controlId != 0) {
        (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1);
        (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,state->controlId);
        (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,state->controlId);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_init
 * EN v1.0 Address: 0x80208D7C
 * EN v1.0 Size: 600b
 */
void dfptargetblock_init(int param_1,int param_2)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  DfpTargetBlockState *state;
  double dVar11;
  float local_58;
  float local_54;
  float local_50;

  state = *(DfpTargetBlockState **)(param_1 + 0xb8);
  iVar7 = **(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    lbl_80329B78[0] = (int)*(float *)(param_1 + 0xc);
    lbl_80329B78[1] = (int)*(float *)(param_1 + 0x10);
    lbl_80329B78[2] = (int)*(float *)(param_1 + 0x14);
  }
  else {
    dVar11 = (double)FLOAT_803e64cc;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      FUN_80026e00(iVar7,iVar8,&local_58);
      if ((double)local_54 < dVar11) {
        dVar11 = (double)local_54;
      }
    }
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      FUN_80026e00(iVar7,iVar8,&local_58);
      if ((double)local_54 == dVar11) {
        bVar2 = false;
        cVar1 = state->floorPointCount;
        for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
          iVar4 = (int)&state->floorPoints[iVar6];
          if ((local_58 == *(float *)iVar4) && (local_50 == *(float *)(iVar4 + 8))) {
            bVar2 = true;
            iVar6 = (int)cVar1;
          }
        }
        if (!bVar2) {
          iVar3 = (int)state->floorPointCount;
          state->floorPoints[iVar3].x = local_58;
          state->floorPoints[(int)state->floorPointCount].y = local_54;
          state->floorPoints[(int)state->floorPointCount].z = local_50;
          state->floorPointCount = state->floorPointCount + '\x01';
        }
      }
    }
    state->mode = DFPTARGETBLOCK_MODE_RAISING;
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e64ac;
    state->completionSfxId = *(short *)(param_2 + 0x1e);
    state->stateSfxId = *(short *)(param_2 + 0x20);
    uVar5 = fn_8001FFB4((int)state->completionSfxId);
    state->completionSfxReady = uVar5;
    uVar5 = fn_8001FFB4((int)state->stateSfxId);
    state->stateSfxReady = uVar5;
    if (state->completionSfxReady != '\0') {
      *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + FLOAT_803e64d0;
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e64d4;
      state->mode = DFPTARGETBLOCK_MODE_SETTLED;
    }
  }
  return;
}

void dfptargetblock_release(void)
{
}

void dfptargetblock_initialise(void)
{
}

int laser_getExtraSizeUnsupported(void)
{
  return 0;
}

int laser_func08(void)
{
  return 0;
}

void laser_freeUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

void laser_renderUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

void laser_hitDetectUnsupported(void)
{
}

void laser_updateUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

void laser_initUnsupported(void)
{
  OSReport(sLaserInitNoLongerSupported);
  return;
}

void laser_releaseUnsupported(void)
{
}

void laser_initialiseUnsupported(void)
{
}

int laserObj_getExtraSize(void)
{
  return sizeof(LaserState);
}

int laserObj_func08(void)
{
  return 0;
}

void laserObj_free(void)
{
}

void laserObj_render(void)
{
}

void laserObj_hitDetect(void)
{
}

void laserObj_update(int param_1)
{
  LaserObject *obj;
  LaserState *state;
  uint uVar1;
  int mode;

  obj = (LaserObject *)param_1;
  if ((obj->state->sequenceLatched == '\0') &&
     (uVar1 = fn_8001FFB4((int)obj->state->secondarySequenceId), uVar1 != 0)) {
    obj->statusFlags &= ~LASER_OBJECT_STATUS_08;
  }
  else {
    obj->statusFlags |= LASER_OBJECT_STATUS_08;
  }
  fn_80041018(param_1);
  if ((obj->statusFlags & 1) != 0) {
    mode = (u8)(*(code *)(*lbl_803DCAAC + 0x40))((int)obj->modeIndex);
    if (mode != 2) {
      if ((mode < 2) && (mode != 0)) {
        state = obj->state;
        if ((*(code *)(*lbl_803DCA68 + 0x20))(0x2e8) != 0) {
          fn_800200E8((int)state->primarySequenceId,1);
          fn_800200E8((int)state->secondarySequenceId,0);
          state->sequenceLatched = 1;
          obj->statusFlags |= LASER_OBJECT_STATUS_08;
        }
      }
    }
    else {
      state = obj->state;
      if ((*(code *)(*lbl_803DCA68 + 0x20))(0x83c) != 0) {
        fn_800200E8((int)state->primarySequenceId,1);
        fn_800200E8((int)state->secondarySequenceId,0);
        state->sequenceLatched = 1;
        obj->statusFlags |= LASER_OBJECT_STATUS_08;
        (*(code *)(*lbl_803DCAAC + 0x44))(7,8);
        (*(code *)(*lbl_803DCAAC + 0x44))(0xd,2);
      }
    }
  }
  return;
}

void laserObj_init(LaserObject *obj,int param_2)
{
  LaserState *state;
  uint uVar1;

  state = obj->state;
  state->primarySequenceId = *(short *)(param_2 + 0x1e);
  state->secondarySequenceId = *(short *)(param_2 + 0x20);
  state->sequenceLatched = 0;
  obj->modeWord = *(s8 *)(param_2 + 0x18) << 8;
  uVar1 = fn_8001FFB4((int)state->primarySequenceId);
  if (uVar1 != 0) {
    state->sequenceLatched = 1;
    obj->statusFlags |= LASER_OBJECT_STATUS_08;
  }
  obj->objectFlags |= 0x6000;
  return;
}

void laserObj_release(void)
{
}

void laserObj_initialise(void)
{
}
