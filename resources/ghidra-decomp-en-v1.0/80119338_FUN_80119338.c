// Function: FUN_80119338
// Entry: 80119338
// Size: 288 bytes

undefined4 FUN_80119338(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_800033a8(&DAT_803a5d60,0,0x1a8);
  FUN_80244000(&DAT_803a5ccc,&DAT_803a5cc0,3);
  iVar1 = FUN_8026b974();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = FUN_8024377c();
    DAT_803dd678 = 0;
    DAT_803dd674 = 0;
    DAT_803dd670 = 0;
    DAT_803dd66c = param_1;
    DAT_803dd668 = FUN_8024f6b8(FUN_80118018);
    if ((DAT_803dd668 == 0) && (DAT_803dd66c != 0)) {
      FUN_8024f6b8(0);
      FUN_802437a4(uVar2);
      uVar2 = 0;
    }
    else {
      FUN_802437a4(uVar2);
      if (DAT_803dd66c == 0) {
        FUN_800033a8(&DAT_803a57c0,0,0x500);
        FUN_802419e8(&DAT_803a57c0,0x500);
        FUN_8024f6fc(&DAT_803a57c0 + DAT_803dd678 * 0x280,0x280);
        FUN_8024f784();
      }
      DAT_803dd660 = 1;
      uVar2 = 1;
    }
  }
  return uVar2;
}

