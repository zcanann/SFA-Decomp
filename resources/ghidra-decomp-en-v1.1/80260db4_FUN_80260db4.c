// Function: FUN_80260db4
// Entry: 80260db4
// Size: 280 bytes

undefined4 FUN_80260db4(int param_1,uint param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  short *psVar3;
  ushort uVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  ushort unaff_r31;
  
  iVar2 = param_1 * 0x110;
  if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
    uVar1 = 0xfffffffd;
  }
  else {
    psVar3 = *(short **)(&DAT_803afec8 + iVar2);
    if ((ushort)psVar3[3] < param_2) {
      uVar1 = 0xfffffff7;
    }
    else {
      psVar3[3] = psVar3[3] - (short)param_2;
      uVar4 = psVar3[4];
      uVar7 = 0;
      uVar6 = 0xffff;
      while (param_2 != 0) {
        uVar7 = uVar7 + 1;
        if ((int)(*(ushort *)(&DAT_803afe50 + iVar2) - 5) < (int)(uVar7 & 0xffff)) {
          return 0xfffffffa;
        }
        uVar4 = uVar4 + 1;
        if ((uVar4 < 5) || ((uint)*(ushort *)(&DAT_803afe50 + iVar2) <= (uint)uVar4)) {
          uVar4 = 5;
        }
        if (psVar3[uVar4] == 0) {
          uVar5 = uVar4;
          if (uVar6 != 0xffff) {
            psVar3[unaff_r31] = uVar4;
            uVar5 = uVar6;
          }
          psVar3[uVar4] = -1;
          param_2 = param_2 - 1;
          unaff_r31 = uVar4;
          uVar6 = uVar5;
        }
      }
      psVar3[4] = uVar4;
      *(ushort *)(&DAT_803afefe + iVar2) = uVar6;
      uVar1 = FUN_80260f68(param_1,psVar3,param_3);
    }
  }
  return uVar1;
}

