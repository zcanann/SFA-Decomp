// Function: FUN_80092e64
// Entry: 80092e64
// Size: 504 bytes

void FUN_80092e64(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 0) {
    if (param_1 == -1) {
      iVar2 = 0;
      do {
        FUN_80090078(iVar2);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 8);
    }
    else {
      FUN_80090078();
    }
  }
  else {
    iVar2 = 0;
    if (((((((DAT_8039a828 == 0) || (param_1 != *(int *)(DAT_8039a828 + 0x13f0))) &&
           ((iVar2 = 1, DAT_8039a82c == 0 || (param_1 != *(int *)(DAT_8039a82c + 0x13f0))))) &&
          ((iVar2 = 2, DAT_8039a830 == 0 || (param_1 != *(int *)(DAT_8039a830 + 0x13f0))))) &&
         ((iVar2 = 3, DAT_8039a834 == 0 || (param_1 != *(int *)(DAT_8039a834 + 0x13f0))))) &&
        ((((iVar2 = 4, DAT_8039a838 == 0 || (param_1 != *(int *)(DAT_8039a838 + 0x13f0))) &&
          ((iVar2 = 5, DAT_8039a83c == 0 || (param_1 != *(int *)(DAT_8039a83c + 0x13f0))))) &&
         ((iVar2 = 6, DAT_8039a840 == 0 || (param_1 != *(int *)(DAT_8039a840 + 0x13f0))))))) &&
       ((iVar2 = 7, DAT_8039a844 == 0 || (param_1 != *(int *)(DAT_8039a844 + 0x13f0))))) {
      iVar2 = 8;
    }
    iVar1 = (&DAT_8039a828)[iVar2];
    if ((iVar1 != 0) && (iVar2 != 8)) {
      if (param_1 == *(int *)(iVar1 + 0x13f0)) {
        *(undefined4 *)(iVar1 + 0x13f8) = 1;
        *(float *)((&DAT_8039a828)[iVar2] + 0x1430) =
             -((float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803df1a8) /
              (float)((double)CONCAT44(0x43300000,
                                       *(uint *)((&DAT_8039a828)[iVar2] + 0x13fc) ^ 0x80000000) -
                     DOUBLE_803df1a8));
      }
      else {
        FUN_801378a8(s_____Error_non_existant_cloud_id___8030f730,param_1);
      }
    }
  }
  return;
}

