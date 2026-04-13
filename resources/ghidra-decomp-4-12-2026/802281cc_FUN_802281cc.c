// Function: FUN_802281cc
// Entry: 802281cc
// Size: 140 bytes

void FUN_802281cc(int param_1,int param_2)

{
  int iVar1;
  
  *(float *)(param_1 + 0x10) = FLOAT_803e7a94 + *(float *)(param_2 + 0xc);
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  *(undefined2 *)(*(int *)(param_1 + 0xb8) + 8) = *(undefined2 *)(param_2 + 0x1a);
  iVar1 = FUN_8002b660(param_1);
  FUN_800285f0(iVar1,FUN_80028590);
  *(undefined *)(param_1 + 0x36) = 0;
  return;
}

