// Function: FUN_8028c494
// Entry: 8028c494
// Size: 192 bytes

void FUN_8028c494(void)

{
  uint uVar1;
  undefined uVar2;
  int local_18;
  int local_14;
  undefined auStack_10 [16];
  
  if (DAT_803d8ff8 == 0) {
    uVar1 = DAT_803d92f8 & 0xffff;
    if ((uVar1 == 0xd00) || ((uVar1 < 0xd00 && (uVar1 == 0x700)))) {
      local_18 = 4;
      FUN_8028ce58((int)&local_14,DAT_803d9080,&local_18,0,1);
      if (local_14 == 0xfe00000) {
        uVar2 = 5;
      }
      else {
        uVar2 = 3;
      }
    }
    else {
      uVar2 = 4;
    }
    FUN_802870dc(auStack_10,uVar2);
    FUN_802870f4((int)auStack_10);
  }
  else {
    DAT_803d8ff8 = 0;
  }
  return;
}

