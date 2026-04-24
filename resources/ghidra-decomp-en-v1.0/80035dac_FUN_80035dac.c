// Function: FUN_80035dac
// Entry: 80035dac
// Size: 28 bytes

void FUN_80035dac(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  *(undefined *)(iVar1 + 0x6e) = 0;
  *(undefined *)(iVar1 + 0x6f) = 0;
  *(undefined4 *)(iVar1 + 0x48) = 0;
  *(undefined4 *)(iVar1 + 0x4c) = 0;
  return;
}

