// Function: FUN_8024574c
// Entry: 8024574c
// Size: 308 bytes

void FUN_8024574c(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  byte local_10 [8];
  
  uVar7 = 0;
  DAT_803ae084 = 0;
  DAT_803ae088 = 0;
  FUN_802420b0(0x803ae040,0x40);
  iVar5 = FUN_80254c34(0,1,0);
  if (iVar5 != 0) {
    iVar5 = FUN_80254534(0,1,3);
    if (iVar5 == 0) {
      FUN_80254d28(0);
    }
    else {
      local_10[0] = 0x20;
      local_10[1] = 0;
      local_10[2] = 1;
      local_10[3] = 0;
      uVar6 = FUN_802539e0(0,local_10,4,1,0);
      uVar7 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253dc8(0);
      uVar1 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253cdc(0,0x803ae040,0x40,0,0);
      uVar2 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253dc8(0);
      uVar3 = countLeadingZeros(uVar6);
      uVar6 = FUN_80254660(0);
      uVar4 = countLeadingZeros(uVar6);
      FUN_80254d28(0);
      uVar7 = countLeadingZeros((uVar7 | uVar1 | uVar2 | uVar3 | uVar4) >> 5);
      uVar7 = uVar7 >> 5;
    }
  }
  DAT_803ae08c = uVar7;
  DAT_803ae080 = 0x40;
  return;
}

