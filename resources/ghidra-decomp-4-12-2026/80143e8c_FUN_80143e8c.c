// Function: FUN_80143e8c
// Entry: 80143e8c
// Size: 116 bytes

undefined4 FUN_80143e8c(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = FUN_80144994(param_1,param_2);
  if (((iVar1 == 0) && ((param_2[0x15] & 0x8000000U) != 0)) &&
     (param_2[8] == (int)*(short *)(param_1 + 0xa0))) {
    *(undefined *)((int)param_2 + 10) = 0;
  }
  return 1;
}

