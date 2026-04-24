// Function: FUN_80253dd0
// Entry: 80253dd0
// Size: 300 bytes

undefined4 FUN_80253dd0(int param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = param_1 * 0x40;
  uVar2 = FUN_8024377c();
  if (((*(uint *)(&DAT_803ae40c + iVar1) & 4) == 0) &&
     ((param_1 == 2 ||
      ((((param_2 != 0 || ((*(uint *)(&DAT_803ae40c + iVar1) & 8) != 0)) ||
        (iVar3 = FUN_80253960(param_1), iVar3 != 0)) &&
       (((*(uint *)(&DAT_803ae40c + iVar1) & 0x10) != 0 &&
        (*(int *)(&DAT_803ae418 + iVar1) == param_2)))))))) {
    *(uint *)(&DAT_803ae40c + iVar1) = *(uint *)(&DAT_803ae40c + iVar1) | 4;
    (&DAT_cc006800)[param_1 * 5] =
         (&DAT_cc006800)[param_1 * 5] & 0x405 | (1 << param_2) << 7 | param_3 << 4;
    if ((*(uint *)(&DAT_803ae40c + iVar1) & 8) != 0) {
      if (param_1 == 1) {
        FUN_80243b44(0x20000);
      }
      else if ((param_1 < 1) && (-1 < param_1)) {
        FUN_80243b44(0x100000);
      }
    }
    FUN_802437a4(uVar2);
    uVar2 = 1;
  }
  else {
    FUN_802437a4(uVar2);
    uVar2 = 0;
  }
  return uVar2;
}

