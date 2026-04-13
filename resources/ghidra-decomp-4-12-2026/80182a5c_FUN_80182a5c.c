// Function: FUN_80182a5c
// Entry: 80182a5c
// Size: 144 bytes

void FUN_80182a5c(int param_1)

{
  ushort *puVar1;
  int iVar2;
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  puVar1 = (ushort *)FUN_8002bac4();
  *(undefined *)(iVar2 + 6) = 0;
  *(undefined *)(iVar2 + 5) = 0;
  *(undefined *)(iVar2 + 9) = 1;
  *(float *)(param_1 + 0x28) = FLOAT_803e45f0;
  *(float *)(param_1 + 0x2c) = FLOAT_803e460c;
  local_1c = FLOAT_803e45d0;
  local_18 = FLOAT_803e45d0;
  local_14 = FLOAT_803e45d0;
  local_20 = FLOAT_803e45e8;
  local_28[2] = 0;
  local_28[1] = 0;
  local_28[0] = *puVar1;
  FUN_80021b8c(local_28,(float *)(param_1 + 0x24));
  return;
}

