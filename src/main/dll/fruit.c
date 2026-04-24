#include "ghidra_import.h"
#include "main/dll/fruit.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8003b818();
extern int FUN_800620e8();
extern undefined4 FUN_800723a0();

extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e7118;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e7124;

typedef struct ZBombAudioState {
  s16 unused0;
  s16 triggerSfxId;
  s16 specialSfxStopTimer;
  u8 effectEmitterActive;
  u8 unused7;
  u8 stopRequested;
} ZBombAudioState;

/*
 * --INFO--
 *
 * Function: zBomb_hitDetect
 * EN v1.0 Address: 0x802086C4
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x802086D0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 zBomb_hitDetect(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  ZBombAudioState *state;
  
  state = *(ZBombAudioState **)(param_1 + 0xb8);
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 2) {
      FUN_80017698((int)state->triggerSfxId + 5,0);
      state->stopRequested = 1;
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        FUN_80017698((int)state->triggerSfxId + 5,1);
      }
    }
    else if (bVar1 < 4) {
      sVar2 = state->triggerSfxId;
      if (sVar2 == 0x674) {
        FUN_80017698(0x670,1);
        state->specialSfxStopTimer = 0x96;
      }
      else if (sVar2 < 0x674) {
        if (sVar2 == 0x672) {
          FUN_80017698(0x66e,1);
          state->specialSfxStopTimer = 0x96;
        }
        else if (0x671 < sVar2) {
          FUN_80017698(0x66f,1);
          state->specialSfxStopTimer = 0x96;
        }
      }
      else if (sVar2 < 0x676) {
        FUN_80017698(0x9f5,1);
        state->specialSfxStopTimer = 0x96;
      }
    }
    *(undefined *)(param_3 + iVar3 + 0x81) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: zBomb_updateAudioState
 * EN v1.0 Address: 0x80208818
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x8020882C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void zBomb_updateAudioState(uint param_1)
{
  short sVar1;
  uint uVar2;
  ZBombAudioState *state;
  
  state = *(ZBombAudioState **)(param_1 + 0xb8);
  uVar2 = FUN_80017690((int)state->triggerSfxId);
  if (((state->effectEmitterActive == 0) && ((short)uVar2 != 0)) &&
     (uVar2 = FUN_80017690(0xedf), uVar2 != 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    state->effectEmitterActive = 1;
  }
  if (((state->stopRequested != 0) && (state->effectEmitterActive != 0)) &&
     (uVar2 = FUN_80017690(0xedf), uVar2 != 0)) {
    FUN_80017698((int)state->triggerSfxId,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    state->effectEmitterActive = 0;
    state->stopRequested = 0;
  }
  if ((int)state->specialSfxStopTimer != 0) {
    state->specialSfxStopTimer =
         (short)(int)((float)((double)CONCAT44(0x43300000,(int)state->specialSfxStopTimer ^ 0x80000000) -
                             DOUBLE_803e7118) - FLOAT_803dc074);
    FUN_800068c4(param_1,0x458);
    if (state->specialSfxStopTimer < 1) {
      state->specialSfxStopTimer = 0;
      sVar1 = state->triggerSfxId;
      if (sVar1 == 0x674) {
        FUN_80017698(0x670,0);
      }
      else if (sVar1 < 0x674) {
        if (sVar1 == 0x672) {
          FUN_80017698(0x66e,0);
        }
        else if (0x671 < sVar1) {
          FUN_80017698(0x66f,0);
        }
      }
      else if (sVar1 < 0x676) {
        FUN_80017698(0x9f5,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: zBomb_updateAudioStateWrapper
 * EN v1.0 Address: 0x802089C8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x802089FC
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void zBomb_updateAudioStateWrapper(uint param_1)
{
  zBomb_updateAudioState(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802089e8
 * EN v1.0 Address: 0x802089E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208A1C
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802089e8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802089ec
 * EN v1.0 Address: 0x802089EC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80208AE0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802089ec(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80208a0c
 * EN v1.0 Address: 0x80208A0C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80208B0C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80208a0c(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: zBomb_resolveCollision
 * EN v1.0 Address: 0x80208A2C
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x80208B40
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void zBomb_resolveCollision(int *param_1,int param_2)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  float local_90;
  float local_8c;
  float local_88;
  int aiStack_84 [21];
  
  iVar3 = 0;
  iVar4 = param_2;
  while( true ) {
    if (*(char *)(param_2 + 0x68) <= iVar3) {
      return;
    }
    local_90 = *(float *)(iVar4 + 4) + (float)param_1[3];
    dVar5 = (double)local_90;
    local_8c = *(float *)(iVar4 + 8) + (float)param_1[4];
    local_88 = *(float *)(iVar4 + 0xc) + (float)param_1[5];
    dVar6 = (double)local_88;
    iVar2 = FUN_800620e8(param_1 + 3,&local_90,(float *)0x1,aiStack_84,param_1,8,0xffffffff,0,0);
    if (iVar2 != 0) break;
    iVar4 = iVar4 + 0xc;
    iVar3 = iVar3 + 1;
  }
  if (FLOAT_803e7124 != (float)param_1[9]) {
    param_1[3] = (int)((float)param_1[3] + (float)((double)local_90 - dVar5));
  }
  if (FLOAT_803e7124 != (float)param_1[0xb]) {
    param_1[5] = (int)((float)param_1[5] + (float)((double)local_88 - dVar6));
  }
  fVar1 = FLOAT_803e7124;
  param_1[9] = (int)FLOAT_803e7124;
  param_1[10] = (int)fVar1;
  param_1[0xb] = (int)fVar1;
  FUN_80006824((uint)param_1,0x1d0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80208c28
 * EN v1.0 Address: 0x80208C28
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80208CAC
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80208c28(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (((*(char *)(iVar1 + 0x6b) == '\0') && (*(char *)(iVar1 + 0x6a) != '\0')) &&
     (*(char *)(iVar1 + 0x69) != '\x04')) {
    FUN_8003b818(param_1);
  }
  return;
}
