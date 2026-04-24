// Function: FUN_802455a0
// Entry: 802455a0
// Size: 292 bytes

uint FUN_802455a0(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  int local_14 [2];
  
  FUN_802419b8();
  iVar5 = FUN_802544d0(0,1,0);
  if (iVar5 == 0) {
    uVar6 = 0;
  }
  else {
    iVar5 = FUN_80253dd0(0,1,3);
    if (iVar5 == 0) {
      FUN_802545c4(0);
      uVar6 = 0;
    }
    else {
      local_14[0] = param_3 << 6;
      uVar7 = FUN_8025327c(0,local_14,4,1,0);
      uVar6 = countLeadingZeros(uVar7);
      uVar7 = FUN_80253664(0);
      uVar1 = countLeadingZeros(uVar7);
      uVar7 = FUN_80253578(0,param_1,param_2,0,0);
      uVar2 = countLeadingZeros(uVar7);
      uVar7 = FUN_80253664(0);
      uVar3 = countLeadingZeros(uVar7);
      uVar7 = FUN_80253efc(0);
      uVar4 = countLeadingZeros(uVar7);
      FUN_802545c4(0);
      uVar6 = countLeadingZeros((uVar6 | uVar1 | uVar2 | uVar3 | uVar4) >> 5);
      uVar6 = uVar6 >> 5;
    }
  }
  return uVar6;
}

