// Function: FUN_801e6b10
// Entry: 801e6b10
// Size: 504 bytes

undefined4 FUN_801e6b10(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  uVar1 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar4 + 0x9d6) = 0xff;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e59e4;
  if (*(short *)(param_1 + 0xa0) != 0) {
    FUN_80030334((double)FLOAT_803e59dc,param_1,0,0);
  }
  FUN_80035f20(param_1);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  iVar2 = FUN_8001ffb4(0x617);
  if (iVar2 == 0) {
    local_28[0] = 1;
    uVar1 = *(undefined4 *)(iVar4 + 0x9b0);
    iVar4 = FUN_800138c4(uVar1);
    if (iVar4 == 0) {
      FUN_80013958(uVar1,local_28);
    }
    uVar1 = 7;
  }
  else {
    FUN_801e7c4c(param_1,uVar1,0);
    uStack28 = (uint)*(ushort *)(iVar4 + 0x9ca);
    local_20 = 0x43300000;
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e59e8 *
                                          (float)((double)CONCAT44(0x43300000,uStack28) -
                                                 DOUBLE_803e59f8)) / FLOAT_803e59ec));
    *(float *)(param_1 + 0x10) =
         (float)((double)*(float *)(iVar4 + 0x9b8) * dVar5 + (double)*(float *)(iVar4 + 0x9bc));
    uVar3 = (uint)*(ushort *)(iVar4 + 0x9ca) + (uint)DAT_803db410 * 0x100;
    if (0xffff < uVar3) {
      uStack28 = FUN_800221a0(0xf,0x23);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar4 + 0x9b8) =
           FLOAT_803e59f0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5a00);
    }
    *(short *)(iVar4 + 0x9ca) = (short)uVar3;
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      iVar4 = FUN_8029689c(uVar1);
      if (iVar4 < 1) {
        uVar1 = FUN_800221a0(0,2);
        (**(code **)(*DAT_803dca54 + 0x48))(uVar1,param_1,0xffffffff);
        FUN_80014b3c(0,0x100);
      }
      else {
        FUN_800200e8(0x61d,1);
        FUN_80014b3c(0,0x100);
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}

