// Function: FUN_80245054
// Entry: 80245054
// Size: 308 bytes

void FUN_80245054(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 local_10 [2];
  
  uVar7 = 0;
  DAT_803ad424 = 0;
  DAT_803ad428 = 0;
  FUN_802419b8(&DAT_803ad3e0,0x40);
  iVar5 = FUN_802544d0(0,1,0);
  if (iVar5 != 0) {
    iVar5 = FUN_80253dd0(0,1,3);
    if (iVar5 == 0) {
      FUN_802545c4(0);
    }
    else {
      local_10[0] = 0x20000100;
      uVar6 = FUN_8025327c(0,local_10,4,1,0);
      uVar7 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253664(0);
      uVar1 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253578(0,&DAT_803ad3e0,0x40,0,0);
      uVar2 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253664(0);
      uVar3 = countLeadingZeros(uVar6);
      uVar6 = FUN_80253efc(0);
      uVar4 = countLeadingZeros(uVar6);
      FUN_802545c4(0);
      uVar7 = countLeadingZeros((uVar7 | uVar1 | uVar2 | uVar3 | uVar4) >> 5);
      uVar7 = uVar7 >> 5;
    }
  }
  DAT_803ad420 = 0x40;
  DAT_803ad42c = uVar7;
  return;
}

