// Function: FUN_80118018
// Entry: 80118018
// Size: 372 bytes

void FUN_80118018(void)

{
  undefined4 uVar1;
  int iVar2;
  
  if (DAT_803dd66c == 0) {
    DAT_803dd678 = DAT_803dd678 ^ 1;
    FUN_8024f6fc(&DAT_803a57c0 + DAT_803dd678 * 0x280,0x280);
    uVar1 = FUN_80243790();
    FUN_80117c74(&DAT_803a57c0 + DAT_803dd678 * 0x280,0,0xa0);
    FUN_802419e8(&DAT_803a57c0 + DAT_803dd678 * 0x280,0x280);
    FUN_802437a4(uVar1);
  }
  else {
    if (DAT_803dd66c == 1) {
      if (DAT_803dd674 != 0) {
        DAT_803dd670 = DAT_803dd674;
      }
      (*DAT_803dd668)();
      iVar2 = FUN_8024f7b4();
      DAT_803dd674 = iVar2 + -0x80000000;
    }
    else {
      (*DAT_803dd668)();
      iVar2 = FUN_8024f7b4();
      DAT_803dd670 = iVar2 + -0x80000000;
    }
    DAT_803dd678 = DAT_803dd678 ^ 1;
    FUN_8024f6fc(&DAT_803a57c0 + DAT_803dd678 * 0x280,0x280);
    uVar1 = FUN_80243790();
    if (DAT_803dd670 != 0) {
      FUN_802419b8(DAT_803dd670,0x280);
    }
    FUN_80117c74(&DAT_803a57c0 + DAT_803dd678 * 0x280,DAT_803dd670,0xa0);
    FUN_802419e8(&DAT_803a57c0 + DAT_803dd678 * 0x280,0x280);
    FUN_802437a4(uVar1);
  }
  return;
}

