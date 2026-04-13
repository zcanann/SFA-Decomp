// Function: FUN_801ce004
// Entry: 801ce004
// Size: 136 bytes

void FUN_801ce004(int param_1)

{
  int iVar1;
  float local_18;
  undefined4 local_14;
  float local_10 [2];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b9ec(param_1);
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_80038524(param_1,0,local_10,&local_14,&local_18,0);
    *(float *)(*(int *)(iVar1 + 8) + 0xc) = local_10[0];
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0x10) = local_14;
    *(float *)(*(int *)(iVar1 + 8) + 0x14) = local_18;
  }
  return;
}

