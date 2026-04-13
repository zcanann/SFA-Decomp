// Function: FUN_801e383c
// Entry: 801e383c
// Size: 112 bytes

void FUN_801e383c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,3);
  FUN_80037a5c(param_1,10);
  *(undefined *)(iVar1 + 4) = 4;
  *(float *)(iVar1 + 0xc) = *(float *)(iVar1 + 0xc) + FLOAT_803e64c8;
  *(float *)(iVar1 + 8) = *(float *)(iVar1 + 8) + FLOAT_803e64d0;
  return;
}

