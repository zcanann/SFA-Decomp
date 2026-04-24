// Function: FUN_8020bac4
// Entry: 8020bac4
// Size: 88 bytes

void FUN_8020bac4(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x709) {
    FUN_80221978((double)FLOAT_803e6588,param_1,iVar1 + 0x14,3,iVar1 + 100);
  }
  if (*(int *)(iVar1 + 100) != 0) {
    FUN_8001f384();
  }
  return;
}

