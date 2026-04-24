#include "ghidra_import.h"
#include "main/dll/zBomb.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_800369d0();
extern undefined4 FUN_800810f8();
extern void zBomb_resolveCollision(int *param_1,int param_2);
extern double FUN_80293900();

extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de978;
extern f32 FLOAT_803de97c;
extern f32 FLOAT_803e7124;
extern f32 FLOAT_803e7128;
extern f32 FLOAT_803e712c;
extern f32 FLOAT_803e7130;
extern f32 FLOAT_803e7134;
extern f32 FLOAT_803e7138;
extern f32 FLOAT_803e713c;
extern f32 FLOAT_803e7140;
extern f32 FLOAT_803e7144;
extern f32 FLOAT_803e7148;
extern f32 FLOAT_803e714c;
extern f32 FLOAT_803e7150;
extern f32 FLOAT_803e7154;
extern f32 FLOAT_803e7158;
extern f32 FLOAT_803e715c;
extern f32 FLOAT_803e7160;

typedef union ZBombControlId {
  u32 value;
  struct {
    u16 unused0;
    s16 triggerSfxId;
  } audio;
} ZBombControlId;

typedef struct ZBombState {
  ZBombControlId control;
  s16 specialSfxStopTimer;
  u8 effectEmitterActive;
  u8 unused7;
  u8 stopRequested;
  u8 unk09[0x5B];
  s16 stateSfxId;
  s16 completionSfxId;
  u8 state;
  u8 stateSfxReady;
  u8 completionSfxReady;
} ZBombState;

/*
 * --INFO--
 *
 * Function: zBomb_update
 * EN v1.0 Address: 0x80208B70
 * EN v1.0 Size: 1724b
 * EN v1.1 Address: 0x80208CFC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void zBomb_update(int *param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  ZBombState *state;
  double dVar7;
  double dVar8;
  int local_58;
  int local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  float local_48;
  int local_44;
  int local_40;
  int local_3c;
  
  local_58 = -1;
  state = *(ZBombState **)(param_1 + 0x2e);
  iVar5 = param_1[0x13];
  if (*(short *)((int)param_1 + 0x46) == 0x4e0) {
    FLOAT_803de978 = (float)param_1[3];
    FLOAT_803de97c = (float)param_1[5];
  }
  else if ((((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
           (state->state != '\x04')) && (state->state != '\x03')) {
    param_1[0x20] = param_1[3];
    param_1[0x21] = param_1[4];
    param_1[0x22] = param_1[5];
    local_54 = 0;
    iVar3 = FUN_800369d0((int)param_1,&local_54,&local_58,(uint *)0x0);
    if (((iVar3 != 0) && (local_54 != 0)) && ((iVar3 == 0xe && (iVar3 == 0xe)))) {
      FUN_80006824((uint)param_1,0x44d);
      fVar1 = *(float *)(local_54 + 0x24);
      fVar2 = *(float *)(local_54 + 0x2c);
      if (fVar1 < FLOAT_803e7124) {
        fVar1 = fVar1 * FLOAT_803e712c;
      }
      if (fVar2 < FLOAT_803e7124) {
        fVar2 = fVar2 * FLOAT_803e712c;
      }
      if (fVar1 <= fVar2) {
        *(float *)(local_54 + 0x24) = FLOAT_803e7124;
      }
      else {
        *(float *)(local_54 + 0x2c) = FLOAT_803e7124;
      }
      fVar1 = FLOAT_803e7130;
      param_1[9] = (int)(*(float *)(local_54 + 0x24) * FLOAT_803e7130);
      param_1[0xb] = (int)(*(float *)(local_54 + 0x2c) * fVar1);
    }
    param_1[3] = (int)((float)param_1[9] * FLOAT_803dc074 + (float)param_1[3]);
    param_1[5] = (int)((float)param_1[0xb] * FLOAT_803dc074 + (float)param_1[5]);
    if (FLOAT_803e7124 != (float)param_1[9]) {
      FUN_800068c4((uint)param_1,0x3bd);
      fVar1 = (float)param_1[9];
      if (FLOAT_803e7124 <= fVar1) {
        if ((FLOAT_803e7124 < fVar1) && (fVar1 <= FLOAT_803e7124)) {
          param_1[9] = (int)FLOAT_803e7124;
        }
      }
      else if (FLOAT_803e7124 <= fVar1) {
        param_1[9] = (int)FLOAT_803e7124;
      }
    }
    if (FLOAT_803e7124 != (float)param_1[0xb]) {
      FUN_800068c4((uint)param_1,0x3bd);
      fVar1 = (float)param_1[0xb];
      if (FLOAT_803e7124 <= fVar1) {
        if ((FLOAT_803e7124 < fVar1) && (fVar1 <= FLOAT_803e7124)) {
          param_1[0xb] = (int)FLOAT_803e7124;
        }
      }
      else if (FLOAT_803e7124 <= fVar1) {
        param_1[0xb] = (int)FLOAT_803e7124;
      }
    }
    zBomb_resolveCollision(param_1,(int)state);
    dVar8 = (double)(*(float *)(iVar5 + 8) - (float)param_1[3]);
    dVar7 = (double)(*(float *)(iVar5 + 0x10) - (float)param_1[5]);
    cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x2b));
    if (cVar4 == '\x01') {
      if ((((double)FLOAT_803e7134 < dVar8) || (dVar8 < (double)FLOAT_803e7138)) ||
         ((dVar7 < (double)FLOAT_803e713c || ((double)FLOAT_803e7140 < dVar7)))) {
        param_1[3] = *(int *)(iVar5 + 8);
        param_1[5] = *(int *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e7124;
        param_1[9] = (int)FLOAT_803e7124;
        param_1[0xb] = (int)fVar1;
        state->state = 2;
        param_1[4] = (int)(*(float *)(iVar5 + 0xc) - FLOAT_803e7144);
        FUN_80006824((uint)param_1,0x1d3);
      }
      fVar1 = (float)param_1[3] - FLOAT_803de978;
      fVar2 = (float)param_1[5] - FLOAT_803de97c;
      if ((FLOAT_803e7124 == fVar1) && (FLOAT_803e7124 == fVar2)) {
        state->state = 3;
      }
      else {
        dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar7 < (double)FLOAT_803e7148) {
          state->state = 3;
        }
      }
    }
    else if (cVar4 == '\x02') {
      if (((((double)FLOAT_803e714c < dVar8) || (dVar8 < (double)FLOAT_803e7150)) ||
          (dVar7 < (double)FLOAT_803e713c)) || ((double)FLOAT_803e7154 < dVar7)) {
        param_1[3] = *(int *)(iVar5 + 8);
        param_1[5] = *(int *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e7124;
        param_1[9] = (int)FLOAT_803e7124;
        param_1[0xb] = (int)fVar1;
        state->state = 2;
        param_1[4] = (int)(*(float *)(iVar5 + 0xc) - FLOAT_803e7144);
        FUN_80006824((uint)param_1,0x1d3);
        local_44 = param_1[3];
        local_40 = param_1[4];
        local_3c = param_1[5];
        local_48 = FLOAT_803e7128;
        local_4c = 0;
        local_4e = 0;
        local_50 = 0;
        iVar5 = 0x14;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x5f5,&local_50,0x200001,0xffffffff,0);
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      fVar1 = (float)param_1[3] - FLOAT_803de978;
      fVar2 = (float)param_1[5] - FLOAT_803de97c;
      if ((FLOAT_803e7124 == fVar1) && (FLOAT_803e7124 == fVar2)) {
        state->state = 3;
      }
      else {
        dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar7 < (double)FLOAT_803e7158) {
          state->state = 3;
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: zBomb_init
 * EN v1.0 Address: 0x8020922C
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x802091A8
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void zBomb_init(int param_1)
{
  char cVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  ZBombState *state;
  undefined auStack_28 [12];
  float local_1c;
  float local_18;
  float local_14;
  
  state = *(ZBombState **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    local_1c = FLOAT_803e7124;
    local_18 = FLOAT_803e715c;
    local_14 = FLOAT_803e7124;
    FUN_800810f8((double)FLOAT_803e7160,(double)FLOAT_803e715c,(double)FLOAT_803e715c,
                 (double)FLOAT_803e7148,param_1,5,1,2,0x32,(int)auStack_28,0);
  }
  else {
    if (state->completionSfxReady == '\0') {
      uVar3 = FUN_80017690((int)state->completionSfxId);
      state->completionSfxReady = (char)uVar3;
    }
    if (state->stateSfxReady == '\0') {
      uVar3 = FUN_80017690((int)state->stateSfxId);
      state->stateSfxReady = (char)uVar3;
    }
    fVar2 = FLOAT_803e7144;
    if (((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
       (cVar1 = state->state, cVar1 != '\x04')) {
      if ((cVar1 == '\0') || (cVar1 == '\x02')) {
        if (*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 0xc)) {
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
          if (*(float *)(iVar4 + 0xc) <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0xc);
            state->state = 1;
          }
        }
      }
      else if (cVar1 == '\x03') {
        if (*(float *)(iVar4 + 0xc) - FLOAT_803e7144 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = FLOAT_803e712c * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
          fVar2 = *(float *)(iVar4 + 0xc) - fVar2;
          if (*(float *)(param_1 + 0x10) <= fVar2) {
            *(float *)(param_1 + 0x10) = fVar2;
            state->state = 4;
            FUN_80017698((int)state->completionSfxId,1);
          }
        }
      }
      else if (state->control.value != 0) {
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1);
        (**(code **)(*DAT_803dd728 + 0x14))(param_1,state->control.value);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,state->control.value);
      }
    }
  }
  return;
}
