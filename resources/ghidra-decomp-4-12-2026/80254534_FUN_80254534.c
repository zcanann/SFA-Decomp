// Function: FUN_80254534
// Entry: 80254534
// Size: 300 bytes

undefined4 FUN_80254534(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = param_1 * 0x40;
  FUN_80243e74();
  if (((*(uint *)(&DAT_803af06c + iVar1) & 4) == 0) &&
     ((param_1 == 2 ||
      ((((param_2 != 0 || ((*(uint *)(&DAT_803af06c + iVar1) & 8) != 0)) ||
        (iVar2 = FUN_802540c4(param_1), iVar2 != 0)) &&
       (((*(uint *)(&DAT_803af06c + iVar1) & 0x10) != 0 &&
        (*(int *)(&DAT_803af078 + iVar1) == param_2)))))))) {
    *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) | 4;
    (&DAT_cc006800)[param_1 * 5] =
         (&DAT_cc006800)[param_1 * 5] & 0x405 | (1 << param_2) << 7 | param_3 << 4;
    if ((*(uint *)(&DAT_803af06c + iVar1) & 8) != 0) {
      if (param_1 == 1) {
        FUN_8024423c(0x20000);
      }
      else if ((param_1 < 1) && (-1 < param_1)) {
        FUN_8024423c(0x100000);
      }
    }
    FUN_80243e9c();
    uVar3 = 1;
  }
  else {
    FUN_80243e9c();
    uVar3 = 0;
  }
  return uVar3;
}

