// Function: FUN_8019fedc
// Entry: 8019fedc
// Size: 536 bytes

void FUN_8019fedc(int param_1)

{
  int iVar1;
  undefined uVar4;
  undefined4 uVar2;
  undefined2 *puVar3;
  int iVar5;
  int *piVar6;
  undefined auStack56 [4];
  undefined auStack52 [4];
  int local_30;
  int local_2c;
  undefined auStack40 [8];
  undefined4 local_20;
  uint uStack28;
  
  piVar6 = *(int **)(param_1 + 0xb8);
  if ((piVar6 != (int *)0x0) && (iVar1 = FUN_8001ffb4(0x50), iVar1 == 0)) {
    iVar1 = FUN_800374ec(param_1,auStack52,auStack40,auStack56);
    if (iVar1 != 0) {
      *piVar6 = 0;
    }
    if (*piVar6 == 0) {
      iVar1 = FUN_8002e0fc(&local_2c,&local_30);
      for (; local_2c < local_30; local_2c = local_2c + 1) {
        iVar5 = *(int *)(iVar1 + local_2c * 4);
        if (*(short *)(iVar5 + 0x44) == 0x3d) {
          *piVar6 = iVar5;
          local_2c = local_30;
        }
      }
    }
    FUN_80037a04(param_1);
    uVar4 = FUN_8001ffb4(0x4d);
    *(undefined *)((int)piVar6 + 0x73) = uVar4;
    if (*(char *)((int)piVar6 + 0x73) == '\0') {
      uVar2 = FUN_8002b9ec();
      FUN_8003adc4(param_1,uVar2,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
      iVar1 = FUN_800221a0(0,0x1e);
      if (iVar1 == 0) {
        FUN_80039270(param_1,piVar6 + 0xd,0x297);
      }
      iVar1 = FUN_80038024(param_1);
      if (iVar1 == 0) {
        FUN_80038f38(param_1,piVar6 + 0xd);
        uStack28 = (uint)DAT_803db410;
        local_20 = 0x43300000;
        FUN_8002fa48((double)FLOAT_803e428c,
                     (double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4290),
                     param_1,0);
      }
      else {
        FUN_8003adc4(param_1,uVar2,*(int *)(param_1 + 0xb8) + 4,0x41,0,3);
        puVar3 = (undefined2 *)FUN_800395d8(param_1,1);
        *puVar3 = 0xf556;
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      if (*(short *)(param_1 + 0xb4) == -1) {
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      }
    }
  }
  return;
}

