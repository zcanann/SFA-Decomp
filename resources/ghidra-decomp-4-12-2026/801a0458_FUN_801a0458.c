// Function: FUN_801a0458
// Entry: 801a0458
// Size: 536 bytes

void FUN_801a0458(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  int iVar5;
  int *piVar6;
  uint uStack_38;
  uint uStack_34;
  int local_30;
  int local_2c;
  uint auStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  if ((piVar6 != (int *)0x0) && (uVar1 = FUN_80020078(0x50), uVar1 == 0)) {
    iVar2 = FUN_800375e4(param_1,&uStack_34,auStack_28,&uStack_38);
    if (iVar2 != 0) {
      *piVar6 = 0;
    }
    if (*piVar6 == 0) {
      iVar2 = FUN_8002e1f4(&local_2c,&local_30);
      for (; local_2c < local_30; local_2c = local_2c + 1) {
        iVar5 = *(int *)(iVar2 + local_2c * 4);
        if (*(short *)(iVar5 + 0x44) == 0x3d) {
          *piVar6 = iVar5;
          local_2c = local_30;
        }
      }
    }
    FUN_80037afc(param_1);
    uVar1 = FUN_80020078(0x4d);
    *(char *)((int)piVar6 + 0x73) = (char)uVar1;
    if (*(char *)((int)piVar6 + 0x73) == '\0') {
      uVar3 = FUN_8002bac4();
      FUN_8003aebc(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
      uVar1 = FUN_80022264(0,0x1e);
      if (uVar1 == 0) {
        FUN_80039368(param_1,(undefined *)(piVar6 + 0xd),0x297);
      }
      iVar2 = FUN_8003811c(param_1);
      if (iVar2 == 0) {
        FUN_80039030(param_1,(char *)(piVar6 + 0xd));
        uStack_1c = (uint)DAT_803dc070;
        local_20 = 0x43300000;
        FUN_8002fb40((double)FLOAT_803e4f24,
                     (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4f28));
      }
      else {
        FUN_8003aebc(param_1,uVar3,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
        puVar4 = (undefined2 *)FUN_800396d0(param_1,1);
        *puVar4 = 0xf556;
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      if (*(short *)(param_1 + 0xb4) == -1) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  return;
}

