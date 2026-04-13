// Function: FUN_8020c13c
// Entry: 8020c13c
// Size: 88 bytes

void FUN_8020c13c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x709) {
    FUN_80221fc8(param_1,iVar1 + 0x14,3,(uint *)(iVar1 + 100));
  }
  if (*(uint *)(iVar1 + 100) != 0) {
    FUN_8001f448(*(uint *)(iVar1 + 100));
  }
  return;
}

