// Function: FUN_801185cc
// Entry: 801185cc
// Size: 328 bytes

undefined4 FUN_801185cc(void)

{
  uint uVar1;
  ushort uVar3;
  int iVar2;
  undefined8 uVar4;
  
  if ((DAT_803a6a5e & 2) == 0) {
    if ((DAT_803a6a5e & 4) == 0) {
      uVar1 = (uint)(FLOAT_803e29d0 * DAT_803a6a0c);
      iVar2 = FUN_8024e064();
      if (iVar2 == 1) {
        uVar4 = FUN_80286990((int)((ulonglong)DAT_803a6a84 * (ulonglong)uVar1 >> 0x20) +
                             DAT_803a6a80 * uVar1 + DAT_803a6a84 * ((int)uVar1 >> 0x1f),
                             DAT_803a6a84 * uVar1,0,5000);
        DAT_803a6a8c = (int)uVar4;
      }
      else {
        uVar4 = FUN_80286990((int)((ulonglong)DAT_803a6a84 * (ulonglong)uVar1 >> 0x20) +
                             DAT_803a6a80 * uVar1 + DAT_803a6a84 * ((int)uVar1 >> 0x1f),
                             DAT_803a6a84 * uVar1,0,0x176a);
        DAT_803a6a8c = (int)uVar4;
      }
      if (DAT_803a6a88 != DAT_803a6a8c) {
        DAT_803a6a88 = DAT_803a6a8c;
        return 1;
      }
    }
    else {
      uVar3 = FUN_8024df24();
      if (uVar3 == 1) {
        return 1;
      }
    }
  }
  else {
    uVar3 = FUN_8024df24();
    if (uVar3 == 0) {
      return 1;
    }
  }
  return 0;
}

