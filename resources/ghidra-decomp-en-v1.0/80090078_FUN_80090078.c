// Function: FUN_80090078
// Entry: 80090078
// Size: 504 bytes

void FUN_80090078(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_800e84f8();
  if (((-1 < param_1) && (param_1 < 3)) && (iVar2 = FUN_800e87c4(), iVar2 == 0)) {
    *(undefined2 *)(iVar1 + param_1 * 2 + 0xe) = 0xffff;
    *(undefined *)(iVar1 + param_1 + 0x41) = 0xff;
  }
  iVar1 = 0;
  if (((((((DAT_8039a828 == 0) || (param_1 != *(int *)(DAT_8039a828 + 0x13f0))) &&
         ((iVar1 = 1, DAT_8039a82c == 0 || (param_1 != *(int *)(DAT_8039a82c + 0x13f0))))) &&
        ((iVar1 = 2, DAT_8039a830 == 0 || (param_1 != *(int *)(DAT_8039a830 + 0x13f0))))) &&
       ((iVar1 = 3, DAT_8039a834 == 0 || (param_1 != *(int *)(DAT_8039a834 + 0x13f0))))) &&
      ((((iVar1 = 4, DAT_8039a838 == 0 || (param_1 != *(int *)(DAT_8039a838 + 0x13f0))) &&
        ((iVar1 = 5, DAT_8039a83c == 0 || (param_1 != *(int *)(DAT_8039a83c + 0x13f0))))) &&
       ((iVar1 = 6, DAT_8039a840 == 0 || (param_1 != *(int *)(DAT_8039a840 + 0x13f0))))))) &&
     ((iVar1 = 7, DAT_8039a844 == 0 || (param_1 != *(int *)(DAT_8039a844 + 0x13f0))))) {
    iVar1 = 8;
  }
  iVar2 = (&DAT_8039a828)[iVar1];
  if ((iVar2 != 0) && (iVar1 != 8)) {
    if (param_1 == *(int *)(iVar2 + 0x13f0)) {
      if (*(int *)(iVar2 + 4) != 0) {
        FUN_80023800();
        *(undefined4 *)((&DAT_8039a828)[iVar1] + 4) = 0;
      }
      if ((&DAT_8039a828)[iVar1] != 0) {
        FUN_80023800();
        (&DAT_8039a828)[iVar1] = 0;
      }
    }
    else {
      FUN_801378a8(s_____Error_non_existant_cloud_id___8030f5f0,param_1);
    }
  }
  return;
}

