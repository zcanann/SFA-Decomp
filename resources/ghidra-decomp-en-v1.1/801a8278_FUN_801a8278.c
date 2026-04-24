// Function: FUN_801a8278
// Entry: 801a8278
// Size: 176 bytes

void FUN_801a8278(int param_1)

{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  puVar1 = (ushort *)FUN_8002bac4();
  local_1c = FLOAT_803e51ec;
  iVar2 = *(int *)(puVar1 + 0x5c);
  *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
  *(float *)(param_1 + 0x28) = FLOAT_803e5208 * *(float *)(iVar2 + 0x298) + FLOAT_803e5204;
  *(float *)(param_1 + 0x2c) = FLOAT_803e5210 * *(float *)(iVar2 + 0x298) + FLOAT_803e520c;
  local_18 = local_1c;
  local_14 = local_1c;
  local_20 = FLOAT_803e5214;
  local_28[2] = 0;
  local_28[1] = 0;
  local_28[0] = *puVar1;
  FUN_80021b8c(local_28,(float *)(param_1 + 0x24));
  *(ushort *)(iVar3 + 0x24) = *(ushort *)(iVar3 + 0x24) | 0x40;
  return;
}

