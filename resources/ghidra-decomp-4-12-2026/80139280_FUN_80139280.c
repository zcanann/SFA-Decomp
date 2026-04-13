// Function: FUN_80139280
// Entry: 80139280
// Size: 28 bytes

void FUN_80139280(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) | 0x80000000;
  *(float *)(iVar1 + 0x808) = FLOAT_803e3098;
  return;
}

