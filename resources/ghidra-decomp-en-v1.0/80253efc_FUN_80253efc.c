// Function: FUN_80253efc
// Entry: 80253efc
// Size: 272 bytes

undefined4 FUN_80253efc(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = param_1 * 0x40;
  uVar1 = FUN_8024377c();
  if ((*(uint *)(&DAT_803ae40c + iVar2) & 4) == 0) {
    FUN_802437a4(uVar1);
    uVar1 = 0;
  }
  else {
    *(uint *)(&DAT_803ae40c + iVar2) = *(uint *)(&DAT_803ae40c + iVar2) & 0xfffffffb;
    uVar3 = (&DAT_cc006800)[param_1 * 5];
    (&DAT_cc006800)[param_1 * 5] = uVar3 & 0x405;
    if ((*(uint *)(&DAT_803ae40c + iVar2) & 8) != 0) {
      if (param_1 == 1) {
        FUN_80243bcc(0x20000);
      }
      else if ((param_1 < 1) && (-1 < param_1)) {
        FUN_80243bcc(0x100000);
      }
    }
    FUN_802437a4(uVar1);
    if ((param_1 == 2) || ((uVar3 & 0x80) == 0)) {
      uVar1 = 1;
    }
    else {
      iVar2 = FUN_80253960(param_1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        uVar1 = 1;
      }
    }
  }
  return uVar1;
}

