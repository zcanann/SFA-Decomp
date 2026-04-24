// Function: FUN_8020a3dc
// Entry: 8020a3dc
// Size: 524 bytes

void FUN_8020a3dc(int param_1,int param_2)

{
  int iVar1;
  short sVar3;
  int iVar2;
  short *psVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined auStack56 [6];
  undefined2 local_32;
  float local_30;
  undefined auStack44 [12];
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  psVar4 = (short *)FUN_800395d8(param_1,0xe);
  if (psVar4 != (short *)0x0) {
    iVar1 = (int)-*psVar4;
    iVar5 = (uint)DAT_803db410 * 0x100;
    iVar6 = (uint)DAT_803db410 * -0x100;
    if ((iVar6 <= iVar1) && (iVar6 = iVar1, iVar5 < iVar1)) {
      iVar6 = iVar5;
    }
    *psVar4 = *psVar4 + (short)iVar6;
    FUN_80247754(param_2 + 0x1c,param_1 + 0xc,auStack44);
    local_30 = FLOAT_803e651c;
    iVar6 = FUN_80080150(param_2 + 0x18);
    if (((iVar6 != 0) && (iVar6 = FUN_800395d8(param_1,0xf), iVar6 != 0)) &&
       (iVar1 = FUN_800395d8(param_1,0x10), iVar1 != 0)) {
      uStack28 = (int)DAT_803dc19a ^ 0x80000000;
      local_20 = 0x43300000;
      iVar5 = (int)(*(float *)(param_2 + 0x18) *
                   (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6528));
      local_18 = (longlong)iVar5;
      sVar3 = (short)iVar5 - *(short *)(iVar6 + 2);
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      iVar7 = (int)sVar3;
      iVar5 = -(int)DAT_803dc198 * (uint)DAT_803db410;
      if ((iVar5 <= iVar7) &&
         (iVar2 = (int)DAT_803dc198 * (uint)DAT_803db410, iVar5 = iVar7, iVar2 < iVar7)) {
        iVar5 = iVar2;
      }
      *(short *)(iVar6 + 2) = *(short *)(iVar6 + 2) + (short)iVar5;
      *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) - (short)iVar5;
      iVar6 = FUN_800801a8(param_2 + 0x18);
      if (iVar6 != 0) {
        FUN_8008016c(param_2 + 0x18);
      }
      if (FLOAT_803e6520 < *(float *)(param_2 + 0x18)) {
        local_32 = 45000;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ad,auStack56,1,0xffffffff,0);
      }
    }
  }
  return;
}

