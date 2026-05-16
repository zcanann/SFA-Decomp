#include "ghidra_import.h"
#include "main/dll/door.h"
#include "main/dll/fruit.h"
#include "main/dll/zBomb.h"

extern undefined4 FUN_8000a380();
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern void fn_80026E00(int param_1,int param_2,float *param_3);
extern undefined4 objParticleFn_80097734();

extern undefined4* lbl_803DCAA8;
extern s32 lbl_80329B78[];
extern f32 timeDelta;
extern f32 lbl_803E648C;
extern f32 lbl_803E6494;
extern f32 lbl_803E64AC;
extern f32 lbl_803E64B0;
extern f32 lbl_803E64C4;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;

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
  u8 mode;
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
#pragma scheduling off
#pragma peephole off
void dfptargetblock_update(int param_1)
{
  u8 cVar1;
  undefined uVar3;
  DfpTargetBlockState *state;
  int iVar4;
  float buf[6];

  state = *(DfpTargetBlockState **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    buf[3] = lbl_803E648C;
    buf[4] = lbl_803E64C4;
    buf[5] = lbl_803E648C;
    objParticleFn_80097734((double)lbl_803E64C8,(double)lbl_803E64C4,(double)lbl_803E64C4,
                 (double)lbl_803E64B0,param_1,5,1,2,0x32,buf,0);
  }
  else {
    if (state->completionSfxReady == '\0') {
      uVar3 = GameBit_Get((int)state->completionSfxId);
      state->completionSfxReady = uVar3;
    }
    if (state->stateSfxReady == '\0') {
      uVar3 = GameBit_Get((int)state->stateSfxId);
      state->stateSfxReady = uVar3;
    }
    if (((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
       (cVar1 = state->mode, cVar1 != DFPTARGETBLOCK_MODE_SETTLED)) {
      if ((cVar1 == DFPTARGETBLOCK_MODE_RAISING) || (cVar1 == DFPTARGETBLOCK_MODE_RESETTING)) {
        if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc)) {
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + timeDelta;
          if (*(float *)(param_1 + 0x10) >= *(float *)(iVar4 + 0xc)) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc);
            state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
          }
        }
      }
      else if (cVar1 == DFPTARGETBLOCK_MODE_LOWERING) {
        if (*(float *)(param_1 + 0x10) >= *(float *)(iVar4 + 0xc) - lbl_803E64AC) {
          *(float *)(param_1 + 0x10) = lbl_803E6494 * timeDelta + *(float *)(param_1 + 0x10);
          if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc) - lbl_803E64AC) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc) - lbl_803E64AC;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
            GameBit_Set((int)state->completionSfxId,1);
          }
        }
      }
      else if (state->controlId != 0) {
        (*(code *)(*lbl_803DCAA8 + 0x10))((double)timeDelta,param_1);
        (*(code *)(*lbl_803DCAA8 + 0x14))(param_1,state->controlId);
        (*(code *)(*lbl_803DCAA8 + 0x18))((double)timeDelta,param_1,state->controlId);
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfptargetblock_init(int param_1,int param_2)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar8;
  DfpTargetBlockState *state;
  int iVar7;
  double dVar11;
  DfpTargetBlockPoint point;

  state = *(DfpTargetBlockState **)(param_1 + 0xb8);
  iVar7 = **(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    lbl_80329B78[0] = (int)*(float *)(param_1 + 0xc);
    lbl_80329B78[1] = (int)*(float *)(param_1 + 0x10);
    lbl_80329B78[2] = (int)*(float *)(param_1 + 0x14);
  }
  else {
    dVar11 = (double)lbl_803E64CC;
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      fn_80026E00(iVar7,iVar8,&point.x);
      if ((double)point.y < dVar11) {
        dVar11 = (double)point.y;
      }
    }
    for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar8 = iVar8 + 1) {
      fn_80026E00(iVar7,iVar8,&point.x);
      if ((double)point.y == dVar11) {
        bVar2 = false;
        cVar1 = state->floorPointCount;
        for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
          iVar4 = (int)state + iVar6 * 12;
          if ((point.x == *(float *)(iVar4 + 4)) && (point.z == *(float *)(iVar4 + 12))) {
            bVar2 = true;
            iVar6 = (int)cVar1;
          }
        }
        if (!bVar2) {
          iVar3 = (int)state->floorPointCount;
          state->floorPoints[iVar3].x = point.x;
          state->floorPoints[(int)state->floorPointCount].y = point.y;
          state->floorPoints[(int)state->floorPointCount].z = point.z;
          state->floorPointCount = state->floorPointCount + '\x01';
        }
      }
    }
    state->mode = DFPTARGETBLOCK_MODE_RAISING;
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - lbl_803E64AC;
    state->completionSfxId = *(short *)(param_2 + 0x1e);
    state->stateSfxId = *(short *)(param_2 + 0x20);
    uVar5 = GameBit_Get((int)state->completionSfxId);
    state->completionSfxReady = uVar5;
    uVar5 = GameBit_Get((int)state->stateSfxId);
    state->stateSfxReady = uVar5;
    if (state->completionSfxReady != '\0') {
      *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + lbl_803E64D0;
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + lbl_803E64D4;
      state->mode = DFPTARGETBLOCK_MODE_SETTLED;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

void dfptargetblock_release(void)
{
}

void dfptargetblock_initialise(void)
{
}

s32 lbl_80329B78[] = {0, 0, 0};

u32 gDfptargetblockObjDescriptor[] = {
    0, 0, 0, 0x00090000,
    (u32)dfptargetblock_initialise,
    (u32)dfptargetblock_release,
    0,
    (u32)dfptargetblock_init,
    (u32)dfptargetblock_update,
    (u32)dfptargetblock_hitDetect,
    (u32)dfptargetblock_render,
    (u32)dfptargetblock_free,
    (u32)dfptargetblock_func08,
    (u32)dfptargetblock_getExtraSize,
    0,
};
