// Function: FUN_8020aa14
// Entry: 8020aa14
// Size: 524 bytes

void FUN_8020aa14(int param_1,int param_2)

{
  int iVar1;
  short sVar3;
  int iVar2;
  short *psVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined auStack_38 [6];
  undefined2 local_32;
  float local_30;
  float afStack_2c [3];
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar4 = (short *)FUN_800396d0(param_1,0xe);
  if (psVar4 != (short *)0x0) {
    iVar1 = (int)-*psVar4;
    iVar6 = (uint)DAT_803dc070 * 0x100;
    iVar7 = (uint)DAT_803dc070 * -0x100;
    if ((iVar7 <= iVar1) && (iVar7 = iVar1, iVar6 < iVar1)) {
      iVar7 = iVar6;
    }
    *psVar4 = *psVar4 + (short)iVar7;
    FUN_80247eb8((float *)(param_2 + 0x1c),(float *)(param_1 + 0xc),afStack_2c);
    local_30 = FLOAT_803e71b4;
    uVar5 = FUN_800803dc((float *)(param_2 + 0x18));
    if (((uVar5 != 0) && (iVar7 = FUN_800396d0(param_1,0xf), iVar7 != 0)) &&
       (iVar1 = FUN_800396d0(param_1,0x10), iVar1 != 0)) {
      uStack_1c = (int)DAT_803dce02 ^ 0x80000000;
      local_20 = 0x43300000;
      iVar6 = (int)(*(float *)(param_2 + 0x18) *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e71c0));
      local_18 = (longlong)iVar6;
      sVar3 = (short)iVar6 - *(short *)(iVar7 + 2);
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      iVar8 = (int)sVar3;
      iVar6 = -(int)DAT_803dce00 * (uint)DAT_803dc070;
      if ((iVar6 <= iVar8) &&
         (iVar2 = (int)DAT_803dce00 * (uint)DAT_803dc070, iVar6 = iVar8, iVar2 < iVar8)) {
        iVar6 = iVar2;
      }
      *(short *)(iVar7 + 2) = *(short *)(iVar7 + 2) + (short)iVar6;
      *(short *)(iVar1 + 2) = *(short *)(iVar1 + 2) - (short)iVar6;
      iVar7 = FUN_80080434((float *)(param_2 + 0x18));
      if (iVar7 != 0) {
        FUN_800803f8((undefined4 *)(param_2 + 0x18));
      }
      if (FLOAT_803e71b8 < *(float *)(param_2 + 0x18)) {
        local_32 = 45000;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ad,auStack_38,1,0xffffffff,0);
      }
    }
  }
  return;
}

