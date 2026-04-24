#include "ghidra_import.h"
#include "main/dll/SH/SHthorntail_internal.h"
#include "main/dll/SC/SCchieflightfoot.h"

extern undefined4 FUN_80006824();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern char objHitReact_update();
extern int FUN_800384ec();
extern undefined4 FUN_800388b4();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern int FUN_800575b4();
extern undefined4 FUN_8006ef38();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_801d58e4();
extern undefined4 FUN_801d58e8();
extern undefined4 FUN_801d5ed4();
extern undefined4 FUN_801d5ed8();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined DAT_80327b78;
extern undefined DAT_80327d6c;
extern undefined4 DAT_80327f60;
extern undefined4 DAT_80327f84;
extern undefined4 DAT_80327fc8;
extern undefined4 DAT_80327fdc;
extern undefined4 DAT_80328000;
extern undefined4 DAT_803dcc60;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60e0;
extern f32 FLOAT_803e60e4;
extern f32 FLOAT_803e60e8;

/*
 * --INFO--
 *
 * Function: SHthorntail_update
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 2280b
 * EN v1.1 Address: 0x801D6548
 * EN v1.1 Size: 1928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                        undefined8 param_5,undefined8 param_6,undefined8 param_7,
                        undefined8 param_8)
{
  SHthorntailObject *obj;
  SHthorntailConfig *config;
  SHthorntailRuntime *runtime;
  byte bVar1;
  short *psVar2;
  char cVar3;
  undefined uVar4;
  undefined *puVar5;
  int iVar6;
  uint uVar7;
  float *pfVar8;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar9;
  int iVar10;
  double extraout_f1;
  double dVar11;
  double extraout_f1_00;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  undefined auStack_78 [12];
  float fStack_6c;
  undefined4 uStack_68;
  float fStack_64;
  float local_60 [2];
  float local_58;
  short local_52;
  char local_4d [8];
  char local_45;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar2 = (short *)FUN_8028683c();
  obj = (SHthorntailObject *)psVar2;
  runtime = obj->runtime;
  config = obj->config;
  iVar10 = (int)runtime;
  iVar9 = (int)config;
  dVar11 = extraout_f1;
  if (runtime->behaviorState == '\f') {
    if (runtime->effectTimer <= FLOAT_803e60b0) {
      if ((psVar2[0x58] & 0x800U) != 0) {
        FUN_800388b4(psVar2,4,&fStack_6c,&uStack_68,&fStack_64,0);
        in_r8 = 0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(psVar2,0x7f0,auStack_78,0x200001,0xffffffff);
      }
      runtime->effectTimer = FLOAT_803e60e8;
    }
    dVar11 = (double)runtime->effectTimer;
    runtime->effectTimer = (float)(dVar11 - (double)FLOAT_803dc074);
  }
  runtime->behaviorFlags = runtime->behaviorFlags & 0xf7;
  if (((&DAT_80327fc8)[runtime->behaviorState] & 2) == 0) {
    puVar5 = &DAT_80327b78;
  }
  else {
    puVar5 = &DAT_80327d6c;
  }
  iVar6 = 0x19;
  uVar7 = (uint)runtime->hitReactState;
  pfVar8 = (float *)runtime->collisionShapeState;
  cVar3 =
      objHitReact_update(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                         puVar5,0x19,uVar7,pfVar8,in_r8,in_r9,in_r10);
  runtime->hitReactState = cVar3;
  if (cVar3 == '\0') {
    uVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar2 + 0x56));
    runtime->locomotionMode = uVar4;
    bVar1 = config->controlMode;
    if (bVar1 == 2) {
      FUN_801d58e8(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                   (int)runtime,iVar6,uVar7,pfVar8,in_r8,in_r9,in_r10);
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        FUN_801d5ed8(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                     (int)runtime,(int)config,uVar7,pfVar8,in_r8,in_r9,in_r10);
      }
      else {
        FUN_801d5ed4((uint)psVar2,(int)runtime,(int)config);
      }
    }
    else if (bVar1 < 4) {
      FUN_801d58e4(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar2,
                   (int)runtime,iVar6,uVar7,pfVar8,in_r8,in_r9,in_r10);
    }
    if (((&DAT_80327fc8)[runtime->behaviorState] & 1) == 0) {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xef;
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) & 0xf7;
    }
    else {
      *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 0x10;
    }
    if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0) {
      bVar1 = runtime->freezeFrameCounter + 1;
      runtime->freezeFrameCounter = bVar1;
      if (bVar1 < 0xb) {
        *(byte *)((int)psVar2 + 0xaf) = *(byte *)((int)psVar2 + 0xaf) | 8;
      }
      else {
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
      }
    }
    if ((int)psVar2[0x50] != (int)*(short *)(&DAT_80327f60 + runtime->behaviorState * 2)) {
      FUN_800305f8((double)FLOAT_803e60b0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,(int)*(short *)(&DAT_80327f60 + runtime->behaviorState * 2),0,uVar7,
                   pfVar8,in_r8,in_r9,in_r10);
      runtime->storedFacingAngle = *psVar2;
    }
    iVar6 = FUN_8002fc3c((double)*(float *)(&DAT_80327f84 + runtime->behaviorState * 4),
                         (double)FLOAT_803dc074);
    if (iVar6 == 0) {
      runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
    }
    else {
      runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
    }
    if (((&DAT_80327fc8)[runtime->behaviorState] & 8) != 0) {
      if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
        runtime->storedFacingAngle = *psVar2;
      }
      uStack_3c = (int)runtime->storedFacingAngle ^ 0x80000000;
      local_40 = 0x43300000;
      dVar11 = (double)FUN_80293f90();
      dVar11 = -dVar11;
      uStack_34 = (int)runtime->storedFacingAngle ^ 0x80000000;
      local_38 = 0x43300000;
      dVar12 = (double)FUN_80294964();
      *(float *)(psVar2 + 6) = (float)(dVar11 * -(double)local_58 + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(-dVar12 * -(double)local_58 + (double)*(float *)(psVar2 + 10));
      *(float *)(psVar2 + 6) =
           (float)(-dVar12 * -(double)local_60[0] + (double)*(float *)(psVar2 + 6));
      *(float *)(psVar2 + 10) =
           (float)(dVar11 * (double)local_60[0] + (double)*(float *)(psVar2 + 10));
      *psVar2 = *psVar2 + local_52;
    }
    pfVar8 = local_60;
    for (iVar6 = 0; iVar6 < local_45; iVar6 = iVar6 + 1) {
      if (*(char *)((int)pfVar8 + 0x13) == '\0') {
        if (*(ushort *)(&DAT_80327fdc + runtime->behaviorState * 2) != 0) {
          FUN_80006824((uint)psVar2,*(ushort *)(&DAT_80327fdc + runtime->behaviorState * 2));
        }
      }
      else if ((*(char *)((int)pfVar8 + 0x13) == '\a') &&
              ((&DAT_80328000)[runtime->behaviorState] != 0)) {
        FUN_80006824((uint)psVar2,(ushort)(byte)(&DAT_80328000)[runtime->behaviorState]);
      }
      pfVar8 = (float *)((int)pfVar8 + 1);
    }
    FUN_8006ef38((double)FLOAT_803e60e0,(double)FLOAT_803e60e0,psVar2,local_60,8,(int)runtime->pathState,
                 (int)runtime->moveScratch);
    if (((&DAT_80327fc8)[runtime->behaviorState] & 4) == 0) {
      runtime->movementControlFlags = runtime->movementControlFlags | 1;
    }
    else {
      runtime->movementControlFlags = runtime->movementControlFlags & 0xfe;
    }
    FUN_801150ac();
    if (((&DAT_80327fc8)[runtime->behaviorState] & 2) == 0) {
      FUN_8003b280((int)psVar2,(int)runtime->collisionShapeState);
    }
    else {
      FUN_8003b1a4((int)psVar2,(int)runtime->collisionShapeState);
    }
    runtime->behaviorFlags = runtime->behaviorFlags & 0xfd;
    if (((runtime->behaviorFlags & 4) == 0) && (iVar6 = FUN_800384ec((int)psVar2), iVar6 != 0)) {
      uVar7 = FUN_80017760(1,(uint)*runtime->impactSfxIds);
      runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
      (**(code **)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(runtime->impactSfxIds + uVar7),psVar2,0xffffffff);
    }
    if (config->leashRadiusByte != '\0') {
      dVar11 = FUN_80017708((float *)(psVar2 + 0xc),&config->homePosX);
      uStack_34 = (uint)config->leashRadiusByte * (uint)config->leashRadiusByte ^ 0x80000000;
      local_38 = 0x43300000;
      if (((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e60c0) < dVar11) &&
         (iVar9 = FUN_800575b4((double)(*(float *)(psVar2 + 0x54) * *(float *)(psVar2 + 4)),
                               (float *)(psVar2 + 6)), iVar9 == 0)) {
        iVar9 = FUN_80017730();
        *psVar2 = (short)iVar9;
      }
    }
    runtime->activeMoveValid = 1;
    if (DAT_803dcc60 == -1) {
      DAT_803dcc60 = config->configToken;
      *(float *)(psVar2 + 0x14) = -(FLOAT_803e60e4 * FLOAT_803dc074 - *(float *)(psVar2 + 0x14));
      (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,psVar2,(int)runtime->moveScratch);
      (**(code **)(*DAT_803dd728 + 0x14))(psVar2,(int)runtime->moveScratch);
      (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,psVar2,(int)runtime->moveScratch);
      psVar2[1] = *(short *)(iVar10 + 0x7dc);
      psVar2[2] = *(short *)(iVar10 + 0x7de);
    }
    else {
      if (DAT_803dcc60 == config->configToken) {
        DAT_803dcc60 = -1;
      }
      if ((runtime->behaviorState < '\x02') || ('\x06' < runtime->behaviorState)) {
        (**(code **)(*DAT_803dd728 + 0x20))(psVar2,(int)runtime->moveScratch);
      }
      else {
        *(float *)(psVar2 + 0x14) = -(FLOAT_803e60e4 * FLOAT_803dc074 - *(float *)(psVar2 + 0x14));
        (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,psVar2,(int)runtime->moveScratch);
        (**(code **)(*DAT_803dd728 + 0x14))(psVar2,(int)runtime->moveScratch);
        (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,psVar2,(int)runtime->moveScratch);
        psVar2[1] = *(short *)(iVar10 + 0x7dc);
        psVar2[2] = *(short *)(iVar10 + 0x7de);
      }
    }
  }
  FUN_80286888();
  return;
}
