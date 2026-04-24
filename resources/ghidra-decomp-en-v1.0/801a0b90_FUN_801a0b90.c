// Function: FUN_801a0b90
// Entry: 801a0b90
// Size: 76 bytes

void FUN_801a0b90(int param_1)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e42c0;
  iVar2 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar2 + 0x24) = FLOAT_803e42c0;
  *(float *)(iVar2 + 0x20) = fVar1;
  *(float *)(iVar2 + 0x28) = fVar1;
  *(byte *)(iVar2 + 0x49) = *(byte *)(iVar2 + 0x49) | 1;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  *(float *)(iVar2 + 0x38) = fVar1;
  *(byte *)(iVar2 + 0x4a) = *(byte *)(iVar2 + 0x4a) & 0xdf;
  return;
}

