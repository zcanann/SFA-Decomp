// Function: FUN_80245634
// Entry: 80245634
// Size: 280 bytes

uint FUN_80245634(byte *param_1,int param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint local_14 [2];
  
  iVar4 = FUN_80254c34(0,1,-0x7fdbaa2c);
  if (iVar4 == 0) {
    uVar5 = 0;
  }
  else {
    iVar4 = FUN_80254534(0,1,3);
    if (iVar4 == 0) {
      FUN_80254d28(0);
      uVar5 = 0;
    }
    else {
      local_14[0] = param_2 * 0x40 + 0x100U | 0xa0000000;
      uVar6 = FUN_802539e0(0,(byte *)local_14,4,1,0);
      uVar5 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253dc8(0);
      uVar1 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253c3c(0,param_1,param_3,1);
      uVar2 = countLeadingZeros(uVar6);
      uVar6 = FUN_80254660(0);
      uVar3 = countLeadingZeros(uVar6);
      FUN_80254d28(0);
      uVar5 = countLeadingZeros((uVar5 | uVar1 | uVar2 | uVar3) >> 5);
      uVar5 = uVar5 >> 5;
    }
  }
  return uVar5;
}

