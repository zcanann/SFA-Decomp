// Function: FUN_80254660
// Entry: 80254660
// Size: 272 bytes

undefined4 FUN_80254660(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = param_1 * 0x40;
  FUN_80243e74();
  if ((*(uint *)(&DAT_803af06c + iVar2) & 4) == 0) {
    FUN_80243e9c();
    uVar1 = 0;
  }
  else {
    *(uint *)(&DAT_803af06c + iVar2) = *(uint *)(&DAT_803af06c + iVar2) & 0xfffffffb;
    uVar3 = (&DAT_cc006800)[param_1 * 5];
    (&DAT_cc006800)[param_1 * 5] = uVar3 & 0x405;
    if ((*(uint *)(&DAT_803af06c + iVar2) & 8) != 0) {
      if (param_1 == 1) {
        FUN_802442c4(0x20000);
      }
      else if ((param_1 < 1) && (-1 < param_1)) {
        FUN_802442c4(0x100000);
      }
    }
    FUN_80243e9c();
    if ((param_1 == 2) || ((uVar3 & 0x80) == 0)) {
      uVar1 = 1;
    }
    else {
      iVar2 = FUN_802540c4(param_1);
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

