// Function: FUN_80252f90
// Entry: 80252f90
// Size: 196 bytes

int FUN_80252f90(int param_1,undefined4 *param_2)

{
  uint uVar1;
  int iVar2;
  
  FUN_80243e74();
  uVar1 = FUN_80252ca8(param_1);
  if ((uVar1 & 0x20) != 0) {
    *(undefined4 *)(&DAT_803af020 + param_1 * 8) = *(undefined4 *)(&DAT_cc006404 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803af024 + param_1 * 8) = *(undefined4 *)(&DAT_cc006408 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803af010 + param_1 * 4) = 1;
  }
  iVar2 = *(int *)(&DAT_803af010 + param_1 * 4);
  *(undefined4 *)(&DAT_803af010 + param_1 * 4) = 0;
  if (iVar2 != 0) {
    *param_2 = *(undefined4 *)(&DAT_803af020 + param_1 * 8);
    param_2[1] = *(undefined4 *)(&DAT_803af024 + param_1 * 8);
  }
  FUN_80243e9c();
  return iVar2;
}

