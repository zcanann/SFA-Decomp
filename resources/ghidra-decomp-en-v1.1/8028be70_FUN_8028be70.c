// Function: FUN_8028be70
// Entry: 8028be70
// Size: 496 bytes

int FUN_8028be70(void)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  byte local_28 [4];
  undefined auStack_24 [16];
  
  puVar2 = DAT_803d9014;
  uVar1 = DAT_803d900c & 0xff;
  if ((((uVar1 == 0xd1) || (uVar1 == 0xd0)) || (uVar1 == 0xd2)) ||
     ((uVar1 == 0xd3 || (uVar1 == 0xd4)))) {
    if (uVar1 == 0xd2) {
      iVar4 = FUN_8028b048(DAT_803d9010,(char)DAT_803d9014,DAT_803d9018,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d900c = (uint)local_28[0];
    }
    else if (uVar1 == 0xd3) {
      iVar4 = FUN_8028af28(DAT_803d9010,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d900c = (uint)local_28[0];
    }
    else if (uVar1 == 0xd4) {
      iVar4 = FUN_8028adbc(DAT_803d9010,DAT_803d9014,(char)DAT_803d9018,local_28);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d900c = (uint)local_28[0];
    }
    else {
      uVar3 = countLeadingZeros(0xd1 - uVar1);
      iVar4 = FUN_8028b394((uint)DAT_803d9010 & 0xff,(int)DAT_803d9018,DAT_803d9014,(char *)local_28
                           ,1,uVar3 >> 5);
      if ((local_28[0] == 0) && (iVar4 != 0)) {
        local_28[0] = 1;
      }
      DAT_803d900c = (uint)local_28[0];
      if (uVar1 == 0xd1) {
        FUN_8028b748((uint)DAT_803d9018,*puVar2);
      }
    }
    DAT_803d9080 = DAT_803d9080 + 4;
  }
  else {
    FUN_802870dc(auStack_24,4);
    FUN_802870f4((int)auStack_24);
    iVar4 = 0;
  }
  return iVar4;
}

