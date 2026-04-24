// Function: FUN_80138ef8
// Entry: 80138ef8
// Size: 28 bytes

void FUN_80138ef8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) | 0x80000000;
  *(float *)(iVar1 + 0x808) = FLOAT_803e2408;
  return;
}

