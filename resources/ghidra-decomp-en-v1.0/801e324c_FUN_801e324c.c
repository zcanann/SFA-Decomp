// Function: FUN_801e324c
// Entry: 801e324c
// Size: 112 bytes

void FUN_801e324c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80037200(param_1,3);
  FUN_80037964(param_1,10);
  *(undefined *)(iVar1 + 4) = 4;
  *(float *)(iVar1 + 0xc) = *(float *)(iVar1 + 0xc) + FLOAT_803e5830;
  *(float *)(iVar1 + 8) = *(float *)(iVar1 + 8) + FLOAT_803e5838;
  return;
}

