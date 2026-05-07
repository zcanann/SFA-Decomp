#include "ghidra_import.h"
#include "main/dll/SH/SHthorntail_internal.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SC/SClevelcontrol.h"
#include "main/dll/SC/SCchieflightfoot.h"
#include "main/objHitReact.h"

extern undefined4 Sfx_PlayFromObject();
extern double FUN_80017708();
extern int FUN_80017730();
extern uint FUN_80017760();
extern uint randomGetRange(int min,int max);
extern undefined4 Obj_GetActiveModel();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 fn_8002CEC0();
extern int ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnimArg,
                                      void *eventList);
extern undefined4 ObjAnim_SetCurrentMove(double moveProgress,int objAnimArg,int moveId,u32 flags);
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSet();
extern void ObjPath_GetPointWorldPosition(SHthorntailObject *obj,int pointIndex,f32 *x,f32 *y,f32 *z,int param_6);
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern int FUN_800575b4();
extern undefined4 fn_8006EF38();
extern undefined4 fn_80114F64();
extern undefined4 fn_8011507C();
extern void fn_80115094(SHthorntailObject *obj,SHthorntailRuntime *runtime);
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern ObjHitReactEntry DAT_80327b78;
extern ObjHitReactEntry DAT_80327d6c;
extern s16 DAT_80327f60[];
extern f32 DAT_80327f84[];
extern u8 DAT_80327fc8[];
extern u16 DAT_80327fdc[];
extern u8 DAT_80328000[];
extern u8 lbl_80326EF8[0x30];
extern u8 lbl_80326F28[0x4AC];
extern undefined4 lbl_803E5410;
extern undefined4* pDll_expgfx;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* lbl_803DCAA8;
extern f32 timeDelta;
extern f64 lbl_803E5428;
extern f64 lbl_803E5440;
extern f32 lbl_803E5418;
extern f32 lbl_803E5448;
extern f32 lbl_803E544C;
extern f32 lbl_803E5450;
extern f32 lbl_803E545C;
extern f32 lbl_803E5460;
extern f32 lbl_803E5464;
extern f32 lbl_803E5468;
extern f32 lbl_803E546C;
extern f32 lbl_803E5470;
extern f32 lbl_803E5474;
extern f32 lbl_803E5478;
extern f32 lbl_803E547C;
extern f32 lbl_803E5480;
extern f32 lbl_803E5484;
extern f32 lbl_803E5488;
extern f64 lbl_803E5490;

/*
 * --INFO--
 *
 * Function: SHthorntail_update
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 1928b
 * EN v1.1 Address: 0x801D6548
 * EN v1.1 Size: 1928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_update(SHthorntailObject *obj)
{
  SHthorntailConfig *config;
  SHthorntailRuntime *runtime;
  byte bVar1;
  short *psVar2;
  char cVar3;
  undefined uVar4;
  ObjHitReactEntry *hitReactEntries;
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
  float fStack_68;
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
  psVar2 = (short *)obj;
  runtime = obj->runtime;
  config = obj->config;
  iVar10 = (int)runtime;
  iVar9 = (int)config;
  dVar11 = extraout_f1;
  if (runtime->behaviorState == '\f') {
    if (runtime->effectTimer <= lbl_803E5418) {
      if ((psVar2[0x58] & 0x800U) != 0) {
        ObjPath_GetPointWorldPosition(obj,4,&fStack_6c,&fStack_68,&fStack_64,0);
        in_r8 = 0;
        in_r9 = *pDll_expgfx;
        (*(code *)(in_r9 + 8))(psVar2,0x7f0,auStack_78,0x200001,0xffffffff);
      }
      runtime->effectTimer = lbl_803E5450;
    }
    dVar11 = (double)runtime->effectTimer;
    runtime->effectTimer = (float)(dVar11 - (double)timeDelta);
  }
  runtime->behaviorFlags = runtime->behaviorFlags & 0xf7;
  if ((DAT_80327fc8[runtime->behaviorState] & 2) == 0) {
    hitReactEntries = &DAT_80327b78;
  }
  else {
    hitReactEntries = &DAT_80327d6c;
  }
  iVar6 = 0x19;
  uVar7 = (uint)runtime->hitReactState;
  pfVar8 = (float *)runtime->hitReactScratch;
  cVar3 = objHitReact_update((ObjAnimComponent *)psVar2,hitReactEntries,0x19,uVar7,pfVar8);
  runtime->hitReactState = cVar3;
  if (cVar3 == '\0') {
    uVar4 = (*(code *)(*DAT_803dd72c + 0x40))((int)*(char *)(psVar2 + 0x56));
    runtime->locomotionMode = uVar4;
    bVar1 = config->controlMode;
    switch (bVar1) {
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
      SHthorntail_updateLevelControlMode0(obj,runtime,config);
      break;
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
      SHthorntail_updateLevelControlMode1((uint)psVar2,runtime,config);
      break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
      SHthorntail_updateRootControlMode2(obj,runtime);
      break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
      SHthorntail_updateRootControlMode3(obj,runtime);
      break;
    }
    if ((DAT_80327fc8[runtime->behaviorState] & 1) == 0) {
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
    if ((int)psVar2[0x50] != (int)DAT_80327f60[runtime->behaviorState]) {
      ObjAnim_SetCurrentMove((double)lbl_803E5418,(int)psVar2,
                             (int)DAT_80327f60[runtime->behaviorState],0);
      runtime->storedFacingAngle = *psVar2;
    }
    iVar6 = ObjAnim_AdvanceCurrentMove((double)DAT_80327f84[runtime->behaviorState],
                                       (double)timeDelta,(int)psVar2,local_60);
    if (iVar6 == 0) {
      runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
    }
    else {
      runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
    }
    if ((DAT_80327fc8[runtime->behaviorState] & 8) != 0) {
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
        if (DAT_80327fdc[runtime->behaviorState] != 0) {
          Sfx_PlayFromObject((uint)psVar2,DAT_80327fdc[runtime->behaviorState]);
        }
      }
      else if ((*(char *)((int)pfVar8 + 0x13) == '\a') &&
              (DAT_80328000[runtime->behaviorState] != 0)) {
        Sfx_PlayFromObject((uint)psVar2,(ushort)DAT_80328000[runtime->behaviorState]);
      }
      pfVar8 = (float *)((int)pfVar8 + 1);
    }
    fn_8006EF38((double)lbl_803E5448,(double)lbl_803E5448,psVar2,local_60,8,
                 (int)runtime->renderPathPoints,(int)runtime->moveScratch);
    if ((DAT_80327fc8[runtime->behaviorState] & 4) == 0) {
      runtime->movementControlFlags = runtime->movementControlFlags | 1;
    }
    else {
      runtime->movementControlFlags = runtime->movementControlFlags & 0xfe;
    }
    fn_80115094(obj,runtime);
    if ((DAT_80327fc8[runtime->behaviorState] & 2) == 0) {
      FUN_8003b280((int)psVar2,(int)runtime->collisionShapeState);
    }
    else {
      FUN_8003b1a4((int)psVar2,(int)runtime->collisionShapeState);
    }
    runtime->behaviorFlags = runtime->behaviorFlags & 0xfd;
    if (((runtime->behaviorFlags & 4) == 0) && (iVar6 = ObjTrigger_IsSet((int)psVar2), iVar6 != 0)) {
      uVar7 = FUN_80017760(1,(uint)*runtime->impactSfxTable);
      runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
      (*(code *)(*DAT_803dd6d4 + 0x48))
                (*(undefined *)(runtime->impactSfxTable + uVar7),psVar2,0xffffffff);
    }
    if (config->leashRadiusByte != '\0') {
      dVar11 = FUN_80017708((float *)(psVar2 + 0xc),(float *)&config->homePos);
      if (((double)(f32)(s32)((uint)config->leashRadiusByte * (uint)config->leashRadiusByte) < dVar11) &&
         (iVar9 = FUN_800575b4((double)(*(float *)(psVar2 + 0x54) * *(float *)(psVar2 + 4)),
                               (float *)(psVar2 + 6)), iVar9 == 0)) {
        iVar9 = FUN_80017730();
        *psVar2 = (short)iVar9;
      }
    }
    runtime->activeMoveValid = 1;
    if (gSHthorntailActiveConfigToken == SHTHORNTAIL_CONFIG_TOKEN_NONE) {
      gSHthorntailActiveConfigToken = config->configToken;
      *(float *)(psVar2 + 0x14) = -(lbl_803E544C * timeDelta - *(float *)(psVar2 + 0x14));
      (*(code *)(*DAT_803dd728 + 0x10))((double)timeDelta,psVar2,(int)runtime->moveScratch);
      (*(code *)(*DAT_803dd728 + 0x14))(psVar2,(int)runtime->moveScratch);
      (*(code *)(*DAT_803dd728 + 0x18))((double)timeDelta,psVar2,(int)runtime->moveScratch);
      psVar2[1] = *(short *)(iVar10 + 0x7dc);
      psVar2[2] = *(short *)(iVar10 + 0x7de);
    }
    else {
      if (gSHthorntailActiveConfigToken == config->configToken) {
        gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
      }
      if ((runtime->behaviorState < '\x02') || ('\x06' < runtime->behaviorState)) {
        (*(code *)(*DAT_803dd728 + 0x20))(psVar2,(int)runtime->moveScratch);
      }
      else {
        *(float *)(psVar2 + 0x14) = -(lbl_803E544C * timeDelta - *(float *)(psVar2 + 0x14));
        (*(code *)(*DAT_803dd728 + 0x10))((double)timeDelta,psVar2,(int)runtime->moveScratch);
        (*(code *)(*DAT_803dd728 + 0x14))(psVar2,(int)runtime->moveScratch);
        (*(code *)(*DAT_803dd728 + 0x18))((double)timeDelta,psVar2,(int)runtime->moveScratch);
        psVar2[1] = *(short *)(iVar10 + 0x7dc);
        psVar2[2] = *(short *)(iVar10 + 0x7de);
      }
    }
  }
  FUN_80286888();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sh_thorntail_init
 * EN v1.0 Address: 0x801D66E0
 * EN v1.0 Size: 564b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void sh_thorntail_init(SHthorntailObject *obj,SHthorntailConfig *config)
{
  SHthorntailRuntime *runtime;
  uint randomTime;
  int moveScratch;
  undefined4 local_28[2];
  undefined4 local_20;
  uint uStack_1c;

  runtime = obj->runtime;
  local_28[0] = lbl_803E5410;
  *(short *)obj = (short)((int)config->initialFacingByte << 8);
  switch (config->controlMode) {
  case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
    runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    randomTime = randomGetRange(1000,2000);
    runtime->idleTimer = (f32)(s32)randomTime;
    break;
  case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
    runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
    runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
    break;
  case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
    runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    randomTime = randomGetRange(1000,2000);
    runtime->idleTimer = (f32)(s32)randomTime;
    break;
  case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
    runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
    randomTime = randomGetRange(1000,2000);
    runtime->idleTimer = (f32)(s32)randomTime;
    break;
  }
  *(float *)((int)obj + 8) = *(float *)(*(int *)((int)obj + 0x50) + 4) *
      ((float)config->initScale / lbl_803E545C);
  Obj_GetActiveModel((int)obj);
  fn_8002CEC0((double)*(float *)((int)obj + 8));
  moveScratch = (int)runtime->moveScratch;
  (*(code *)(*lbl_803DCAA8 + 4))(moveScratch,3,0xa3,0);
  (*(code *)(*lbl_803DCAA8 + 0xc))(moveScratch,4,lbl_80326EF8,lbl_80326F28,local_28);
  (*(code *)(*lbl_803DCAA8 + 0x20))((int)obj,moveScratch);
  *(code **)((int)obj + 0xbc) = (code *)SHthorntail_updateLevelControlState;
  fn_80114F64((int)obj,(int)runtime,0xffffdc72,0x2aaa,3);
  fn_8011507C((int)runtime,400,0x78);
  ObjGroup_AddObject((int)obj,0x4d);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: SHthorntail_updateDustEffects
 * EN v1.0 Address: 0x801D6914
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateDustEffects(SHthorntailObject *obj)
{
  SHthorntailRuntime *runtime;
  undefined4 playerObj;
  char burstCount;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;

  playerObj = Obj_GetPlayerObject();
  runtime = obj->runtime;
  local_2c = lbl_803E5460;
  local_28 = lbl_803E5464;
  local_24 = lbl_803E5460;
  local_34 = 0xc0e;
  local_36 = 1;
  if ((runtime->dustEffectFlags & 4) != 0) {
    if (runtime->dustEffectTimer < lbl_803E5468) {
      if ((f32)(s32)randomGetRange(0,0x1e0) <
          runtime->dustEffectTimer * lbl_803E546C) {
        (*(code *)(*pDll_expgfx + 8))(playerObj,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    else if (runtime->dustEffectTimer < lbl_803E5470) {
      if ((f32)(s32)randomGetRange(0,0x1e0) <
          runtime->dustEffectTimer / lbl_803E5474) {
        (*(code *)(*pDll_expgfx + 8))(playerObj,0x7ca,&local_38,2,0xffffffff,0);
      }
      local_32 = 0x28;
      local_38 = 0;
      local_30 = lbl_803E5478 * ((runtime->dustEffectTimer - lbl_803E5468) / lbl_803E547C);
      (*(code *)(*pDll_expgfx + 8))(playerObj,0x7d2,&local_38,2,0xffffffff,0);
      runtime->dustEffectFlags = runtime->dustEffectFlags | 2;
    }
    else if (runtime->dustEffectTimer < lbl_803E5480) {
      if ((f32)(s32)randomGetRange(0,0x1e0) <
          runtime->dustEffectTimer * lbl_803E546C) {
        (*(code *)(*pDll_expgfx + 8))(playerObj,0x7ca,&local_38,2,0xffffffff,0);
      }
      if ((runtime->dustEffectFlags & 2) != 0) {
        runtime->dustEffectFlags = runtime->dustEffectFlags & 0xfd;
        local_32 = 0x46;
        local_30 = lbl_803E5484;
        for (burstCount = 0xf; burstCount != 0; burstCount = burstCount + -1) {
          (*(code *)(*pDll_expgfx + 8))(playerObj,0x7d2,&local_38,2,0xffffffff,0);
        }
      }
    }
    else {
      if (runtime->dustEffectTimer < lbl_803E5488) {
      }
      else {
        runtime->dustEffectTimer = lbl_803E5460;
        runtime->dustEffectFlags = runtime->dustEffectFlags & 0xfb;
      }
    }
    runtime->dustEffectTimer = runtime->dustEffectTimer + timeDelta;
  }
}
#pragma peephole reset
#pragma scheduling reset
