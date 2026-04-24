// Function: FUN_8028b70c
// Entry: 8028b70c
// Size: 496 bytes

int FUN_8028b70c(void)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  byte local_28 [4];
  undefined auStack36 [16];
  
  puVar2 = DAT_803d83b4;
  uVar1 = DAT_803d83ac & 0xff;
  if ((((uVar1 == 0xd1) || (uVar1 == 0xd0)) || (uVar1 == 0xd2)) ||
     ((uVar1 == 0xd3 || (uVar1 == 0xd4)))) {
    if (uVar1 == 0xd2) {
      iVar4 = FUN_8028a8e4(DAT_803d83b0,(uint)DAT_803d83b4 & 0xff,DAT_803d83b8,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d83ac = (uint)local_28[0];
    }
    else if (uVar1 == 0xd3) {
      iVar4 = FUN_8028a7c4(DAT_803d83b0,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d83ac = (uint)local_28[0];
    }
    else if (uVar1 == 0xd4) {
      iVar4 = FUN_8028a658(DAT_803d83b0,DAT_803d83b4,DAT_803d83b8 & 0xff,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d83ac = (uint)local_28[0];
    }
    else {
      uVar3 = countLeadingZeros(0xd1 - uVar1);
      iVar4 = FUN_8028ac30(DAT_803d83b0 & 0xff,DAT_803d83b8,DAT_803d83b4,local_28,1,uVar3 >> 5);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d83ac = (uint)local_28[0];
      if (uVar1 == 0xd1) {
        FUN_8028afe4(DAT_803d83b8,*puVar2);
      }
    }
    DAT_803d8420 = DAT_803d8420 + 4;
  }
  else {
    FUN_80286978(auStack36,4);
    FUN_80286990(auStack36);
    iVar4 = 0;
  }
  return iVar4;
}

